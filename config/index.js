require("dotenv").config();

const jwtSecret = process.env.JWT_SECRET_KEY || 'your_name';

const ROLES = Object.freeze({
  USER: 'user',
  ADMIN: 'admin',
  BUSINESS: 'business',
});

const PROVIDERS = Object.freeze({
  GOOGLE: 'google',
  FACEBOOK: 'facebook',
});

const COOKIE_NAMES = Object.freeze({
  ACCESS: 'access_token',
  REFRESH: 'refresh_token',
});

module.exports = {
  port: Number(process.env.PORT || 8080),
  mongoUri: process.env.MONGO_URI || null,
  jwtSecret,
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || jwtSecret,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || jwtSecret,
  jwtExpiry: process.env.JWT_EXPIRY || '18h',
  jwtAccessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
  jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '90d',
  emailUser: process.env.EMAIL_USER || null,
  emailPass: process.env.EMAIL_PASS || null,
  nodeEnv: process.env.NODE_ENV || 'development',
  cookieSameSite: process.env.COOKIE_SAMESITE || 'lax',
  cookieSecure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  corsOrigin: process.env.CORS_ORIGIN || process.env.FRONTEND_URL || 'http://localhost:3000',
  googleClientId: process.env.GOOGLE_CLIENT_ID || null,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || null,
  googleCallbackUrl: process.env.GOOGLE_CALLBACK_URL || `http://localhost:${process.env.PORT || 3001}/api/auth/google/callback`,
  facebookAppId: process.env.FACEBOOK_APP_ID || null,
  facebookAppSecret: process.env.FACEBOOK_APP_SECRET || null,
  facebookGraphApiVersion: process.env.FACEBOOK_GRAPH_API_VERSION || 'v23.0',
  facebookCallbackUrl: process.env.FACEBOOK_CALLBACK_URL || `http://localhost:${process.env.PORT || 3001}/api/auth/facebook/callback`,
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  oauthSuccessRedirect: process.env.OAUTH_SUCCESS_REDIRECT || process.env.FRONTEND_URL || 'http://localhost:3000',
  oauthFailureRedirect: process.env.OAUTH_FAILURE_REDIRECT || process.env.FRONTEND_URL || 'http://localhost:3000',
  accessCookieMaxAge: Number(process.env.ACCESS_COOKIE_MAX_AGE || 15 * 60 * 1000),
  refreshCookieMaxAge: Number(process.env.REFRESH_COOKIE_MAX_AGE || 90 * 24 * 60 * 60 * 1000),
  refreshSessionTtlMs: Number(process.env.REFRESH_SESSION_TTL_MS || 90 * 24 * 60 * 60 * 1000),
  otpTtlMs: Number(process.env.OTP_TTL_MS || 10 * 60 * 1000),
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 100),
  passwordRateLimitMax: Number(process.env.PASSWORD_RATE_LIMIT_MAX || 10),
  mailFrom: process.env.MAIL_FROM || process.env.EMAIL_USER || null,
  resendApiKey: process.env.RESEND_API_KEY || null,
  ROLES,
  PROVIDERS,
  COOKIE_NAMES,
};
