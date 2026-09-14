const rateLimit = require("express-rate-limit");
const config = require("../config");

const commonOptions = {
  windowMs: config.rateLimitWindowMs,
  standardHeaders: "draft-7",
  legacyHeaders: false,
};

const authLimiter = rateLimit({
  ...commonOptions,
  limit: config.rateLimitMax,
  message: {
    success: false,
    message: "Too many authentication requests. Please try again later.",
  },
});

const passwordLimiter = rateLimit({
  ...commonOptions,
  limit: config.passwordRateLimitMax,
  message: {
    success: false,
    message: "Too many password requests. Please try again later.",
  },
});

module.exports = { authLimiter, passwordLimiter };
