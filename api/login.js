const crypto = require("crypto");

function sign(value, secret) {
  const h = crypto.createHmac("sha256", secret).update(value).digest("hex");
  return `${value}.${h}`;
}

module.exports = (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    let username, password;
    try {
      const parsed = JSON.parse(body || "{}");
      username = (parsed.username || "").trim();
      password = parsed.password || "";
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

    if (username === validUser && password === validPass) {
      const sessionValue = `${username}:${Date.now()}`;
      const token = sign(sessionValue, secret);
      const cookie = [
        `wh_session=${encodeURIComponent(token)}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        `Max-Age=${60 * 60 * 24 * 14}`, // 14 days
      ].join("; ");
      res.setHeader("Set-Cookie", cookie);
      res.status(200).json({ ok: true });
    } else {
      res.status(401).json({ error: "שם משתמש או סיסמה שגויים" });
    }
  });
};
