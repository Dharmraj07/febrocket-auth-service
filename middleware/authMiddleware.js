const jwt = require("jsonwebtoken");
const config = require("../config");
const { AppError } = require("../controllers/authController");

const getTokenFromRequest = (req) => {
  if (req.cookies?.[config.COOKIE_NAMES.ACCESS]) {
    return req.cookies[config.COOKIE_NAMES.ACCESS];
  }

  const authorization = req.headers.authorization;
  if (!authorization) return null;

  if (authorization.startsWith("Bearer ")) {
    return authorization.slice("Bearer ".length);
  }

  return authorization;
};

const requireAuth = (options = {}) => (req, _res, next) => {
  const token = getTokenFromRequest(req);

  if (!token) {
    return next(new AppError("Unauthorized access. Please log in.", 401));
  }

  try {
    req.user = jwt.verify(token, config.jwtAccessSecret);
  } catch (_error) {
    return next(new AppError("Unauthorized access. Invalid token.", 401));
  }

  if (options.adminOnly && req.user.role !== config.ROLES.ADMIN) {
    return next(new AppError("Access denied. Admin privileges required.", 403));
  }

  return next();
};

module.exports = requireAuth;