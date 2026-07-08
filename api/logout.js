module.exports = (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "wh_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
  );
  res.writeHead(302, { Location: "/login.html" });
  res.end();
};
