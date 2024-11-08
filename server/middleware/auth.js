const jwt = require("jsonwebtoken");

const authenticate = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }
    req.user = user;
    console.log("USER AUTH: ", user);
    next();
  });
};

module.exports = authenticate;
