const crypto = require("crypto");

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

module.exports = (req, res) => {
  const secret = process.env.WH_SESSION_SECRET || "fallback-secret-change-me";
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.wh_session;

  if (!token) {
    res.status(401).json({ ok: false });
    return;
  }

  const lastDot = token.lastIndexOf(".");
  const value = token.slice(0, lastDot);
  const sig = token.slice(lastDot + 1);
  const expected = crypto.createHmac("sha256", secret).update(value).digest("hex");

  if (sig !== expected) {
    res.status(401).json({ ok: false });
    return;
  }

  let payload = {};
  try {
    payload = JSON.parse(value);
  } catch {
    // תואם לאחור לפורמט הישן (לפני שהוספנו טלפון/שם) — עדיין תקין, רק בלי פרטים נוספים
  }

  res.status(200).json({
    ok: true,
    name: payload.name || "",
    phone: payload.phone || "",
    isAdmin: !!payload.isAdmin,
  });
};
