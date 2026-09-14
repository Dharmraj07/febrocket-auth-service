// ============================================================
// IMPORTS
// ============================================================
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const createError = require("http-errors");
const jwt = require("jsonwebtoken");
const config = require("../config");
const { COOKIE_NAMES } = config;


// ============================================================
// ERROR
// ============================================================
function AppError(message, statusCode = 500, errors) {
  return createError(statusCode, message, { errors });
}


// ============================================================
// GENERIC HELPERS
// ============================================================

/** Makes email comparison consistent (trim spaces, lowercase). */
const normalizeEmail = (email) => String(email).trim().toLowerCase();

/** Picks only safe, public fields from a user document. */
const publicUser = (user) => ({
  id: user._id,
  email: user.email,
  role: user.role,
  userName: user.userName,
  isVerified: user.isVerified,
});


// ============================================================
// PASSWORD HELPERS
// ============================================================

/** Hash a plain password using bcrypt (12 salt rounds). */
const hashPassword = async (password) => bcrypt.hash(password, 12);

/** Compare a plain password against a bcrypt hash. */
const comparePassword = (password, hash) => bcrypt.compare(password, hash);

/** Hash a token using SHA-256 (store hash, never raw token). */
const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");


// ============================================================
// JWT HELPERS
// ============================================================

/** Generate a short-lived ACCESS token. */
const accessToken = (user) =>
  jwt.sign(
    {
      id: user._id,
      role: user.role,
      email: user.email,
      userName: user.userName,
    },
    config.jwtAccessSecret,
    { expiresIn: config.jwtAccessExpiry }
  );

/** Generate a long-lived REFRESH token with a unique jti. */
const refreshToken = (user) =>
  jwt.sign(
    {
      id: user._id,
      role: user.role,
      email: user.email,
      userName: user.userName,
      jti: crypto.randomUUID(),
      type: "refresh",
    },
    config.jwtRefreshSecret,
    { expiresIn: config.jwtRefreshExpiry }
  );

/** Build a session record to store inside the user document. */
const sessionRecord = (token, req) => {
  const payload = jwt.decode(token);
  return {
    jti: payload.jti,
    tokenHash: hashToken(token),
    revokedAt: null,
    replacedByJti: null,
    expiresAt: new Date(Date.now() + config.refreshSessionTtlMs),
    createdAt: new Date(),
    userAgent: req.headers?.["user-agent"] || "",
    ipAddress: req.ip || req.headers?.["x-forwarded-for"] || "",
  };
};


// ============================================================
// COOKIE HELPERS
// ============================================================

const cookieBase = () => ({
  httpOnly: true,
  sameSite: config.cookieSameSite,
  secure: config.cookieSecure,
  path: "/",
});

/** Set access + refresh cookies on the response. */
const setCookies = (res, access, refresh) => {
  const base = cookieBase();
  res.cookie(COOKIE_NAMES.ACCESS, access, {
    ...base,
    maxAge: config.accessCookieMaxAge,
  });
  res.cookie(COOKIE_NAMES.REFRESH, refresh, {
    ...base,
    maxAge: config.refreshCookieMaxAge,
  });
};

/** Clear both auth cookies (used on logout). */
const clearCookies = (res) => {
  const base = cookieBase();
  res.clearCookie(COOKIE_NAMES.ACCESS, base);
  res.clearCookie(COOKIE_NAMES.REFRESH, base);
};


// ============================================================
// OTP HELPERS
// ============================================================

/** Generate a 6-digit OTP with an expiry. */
const generateOtp = () => ({
  value: crypto.randomInt(100000, 999999).toString(),
  expiresAt: new Date(Date.now() + config.otpTtlMs),
});

/** Hash OTP, save to user, return raw value (to email). */
const saveOtp = async (user) => {
  const otp = generateOtp();
  user.otp = await hashPassword(otp.value);
  user.otpExpires = otp.expiresAt;
  await user.save();
  return otp.value;
};

/** Verify an OTP. */
const verifyOtp = async (user, otp) => {
  if (!user || !user.otp) return false;
  if (user.otpExpires <= new Date()) return false;
  return bcrypt.compare(otp, user.otp);
};


// ============================================================
// EXPORTS
// ============================================================
module.exports = {
  AppError,
  normalizeEmail,
  publicUser,
  hashPassword,
  comparePassword,
  hashToken,
  accessToken,
  refreshToken,
  sessionRecord,
  setCookies,
  clearCookies,
  generateOtp,
  saveOtp,
  verifyOtp,
};