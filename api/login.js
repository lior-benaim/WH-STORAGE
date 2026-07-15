const crypto = require("crypto");

function sign(value, secret) {
  const h = crypto.createHmac("sha256", secret).update(value).digest("hex");
  return `${value}.${h}`;
}

// ── הגנה מפני ניסיונות כניסה חוזרים ──────────────────────────────────────────
const DB_URL = "https://wh-storage-default-rtdb.europe-west1.firebasedatabase.app";
const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 24 * 60 * 60 * 1000; // 24 שעות

function safeIpKey(ip) {
  return String(ip || "unknown").replace(/[.#$/\[\]:]/g, "-");
}
function safePhoneKey(phone) {
  return String(phone || "").replace(/\D/g, "");
}
function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return fwd.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

// מחזיר { ok, data } — ok=false גם על שגיאת רשת וגם על תשובה לא תקינה (למשל
// "אין הרשאה"), כדי שלעולם לא נבלבל "אין נתונים" עם "לא הצלחנו לבדוק".
async function fbGet(path) {
  try {
    const r = await fetch(`${DB_URL}/${path}.json`);
    if (!r.ok) return { ok: false, data: null };
    const data = await r.json();
    return { ok: true, data };
  } catch {
    return { ok: false, data: null };
  }
}
async function fbPut(path, value) {
  try {
    const r = await fetch(`${DB_URL}/${path}.json`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(value),
    });
    return r.ok;
  } catch {
    return false;
  }
}
async function fbDelete(path) {
  try {
    const r = await fetch(`${DB_URL}/${path}.json`, { method: "DELETE" });
    return r.ok;
  } catch {
    return false;
  }
}

module.exports = (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", async () => {
    let username, password, phone;
    try {
      const parsed = JSON.parse(body || "{}");
      username = (parsed.username || "").trim();
      password = parsed.password || "";
      phone = (parsed.phone || "").trim();
    } catch {
      res.status(400).json({ error: "Bad request" });
      return;
    }

    const validUser = process.env.WH_USERNAME;
    const validPass = process.env.WH_PASSWORD;
    const secret = process.env.WH_SESSION_SECRET || "fallback-secret-change-me";

    if (!validUser || !validPass) {
      res.status(500).json({ error: "Server not configured" });
      return;
    }

    const ip = getClientIp(req);
    const ipKey = safeIpKey(ip);
    const now = Date.now();

    // בדיקת נעילה קיימת (אם אי אפשר לבדוק בגלל תקלת חיבור — לא חוסמים בגללה,
    // זו רק בדיקת נוחות, לא הבדיקה הביטחונית הקריטית)
    const attemptsCheck = await fbGet(`loginAttempts/${ipKey}`);
    const record = attemptsCheck.ok ? attemptsCheck.data : null;
    if (record && record.lockedUntil && record.lockedUntil > now) {
      const hoursLeft = Math.ceil((record.lockedUntil - now) / (60 * 60 * 1000));
      res.status(429).json({ error: `יותר מדי ניסיונות כניסה כושלים. המערכת נעולה לעוד כ-${hoursLeft} שעות.` });
      return;
    }

    async function registerFailure(msg) {
      const prevCount = record && !(record.lockedUntil && record.lockedUntil <= now) ? (record.count || 0) : 0;
      const newCount = prevCount + 1;
      const newRecord = { count: newCount, lastAttempt: now };
      if (newCount >= MAX_ATTEMPTS) {
        newRecord.lockedUntil = now + LOCKOUT_MS;
        await fbPut(`loginAttempts/${ipKey}`, newRecord);
        res.status(429).json({ error: "יותר מדי ניסיונות כושלים. המערכת ננעלה ל-24 שעות." });
      } else {
        await fbPut(`loginAttempts/${ipKey}`, newRecord);
        res.status(401).json({ error: `${msg} נותרו ${MAX_ATTEMPTS - newCount} ניסיונות לפני נעילה.` });
      }
    }

    if (!(username === validUser && password === validPass)) {
      await registerFailure("שם משתמש או סיסמה שגויים.");
      return;
    }

    if (!phone) {
      await registerFailure("חובה להזין מספר טלפון.");
      return;
    }

    const phoneKey = safePhoneKey(phone);
    if (!phoneKey) {
      await registerFailure("מספר טלפון לא תקין.");
      return;
    }

    // ── בדיקת מספר טלפון מול רשימת המשתמשים המאושרים ────────────────────────
    const userCheck = await fbGet(`allowedUsers/${phoneKey}`);
    if (!userCheck.ok) {
      // לא הצלחנו בכלל לבדוק (למשל: חוקי ה-Firebase עדיין לא כוללים גישה
      // לנתיב הזה) — נכשלים בבטחה, בלי לתת גישה ובלי לספור ניסיון כושל,
      // כדי שלא תיווצר נעילה שגויה בזמן שמסדרים את ההגדרות.
      res.status(500).json({
        error: "שגיאת חיבור למסד הנתונים בבדיקת הטלפון — ודאי שחוקי ה-Firebase כוללים את allowedUsers, ונסי שוב.",
      });
      return;
    }

    let userRecord = userCheck.data;

    if (!userRecord) {
      // אתחול חד-פעמי: אם עדיין אין אף משתמש מאושר ברשימה, הכניסה הראשונה
      // שמצליחה עם שם המשתמש/סיסמה הנכונים הופכת אוטומטית למנהלת הראשית.
      const allCheck = await fbGet(`allowedUsers`);
      if (!allCheck.ok) {
        res.status(500).json({
          error: "שגיאת חיבור למסד הנתונים — ודאי שחוקי ה-Firebase כוללים את allowedUsers, ונסי שוב.",
        });
        return;
      }
      const totalUsers = allCheck.data ? Object.keys(allCheck.data).length : 0;
      if (totalUsers === 0) {
        const bootstrapRecord = { name: "מנהל.ת ראשי.ת", phone, active: true, isAdmin: true, addedAt: now };
        const wrote = await fbPut(`allowedUsers/${phoneKey}`, bootstrapRecord);
        if (!wrote) {
          res.status(500).json({ error: "לא הצלחנו ליצור את חשבון המנהל הראשוני — נסי שוב בעוד רגע." });
          return;
        }
        userRecord = bootstrapRecord;
      }
    }

    if (!userRecord || userRecord.active === false) {
      await registerFailure("מספר טלפון לא מאושר למערכת — פני למנהל.ת.");
      return;
    }

    // ── הצלחה ──────────────────────────────────────────────────────────────
    await fbDelete(`loginAttempts/${ipKey}`);
    const sessionPayload = JSON.stringify({
      u: username,
      phone,
      name: userRecord.name || "",
      isAdmin: !!userRecord.isAdmin,
      t: now,
    });
    const token = sign(sessionPayload, secret);
    const cookie = [
      `wh_session=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      `Max-Age=${60 * 60 * 24 * 14}`,
    ].join("; ");
    res.setHeader("Set-Cookie", cookie);
    res.status(200).json({ ok: true });
  });
};
