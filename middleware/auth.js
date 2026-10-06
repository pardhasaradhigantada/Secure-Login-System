const rateLimit = require('express-rate-limit');

/**
 * Middleware to protect routes that require an authenticated user.
 * Blocks unauthenticated access and either responds with JSON or redirects.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }

  // If this is an API call, return JSON 401 Unauthorized
  if (req.originalUrl.startsWith('/api/') || req.xhr || (req.headers.accept && req.headers.accept.includes('application/json'))) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please log in to access this resource.'
    });
  }

  // Otherwise, redirect to login page
  return res.redirect('/login.html');
}

/**
 * Middleware to redirect authenticated users away from login/register pages.
 */
function redirectIfAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  return next();
}

/**
 * Rate Limiter for Login Endpoint:
 * Limits each IP to 5 requests per 15-minute window to defend against brute-force attacks.
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  standardHeaders: true, // Return standard RateLimit headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      error: 'Too many login attempts from this IP. Please try again after 15 minutes for security.'
    });
  }
});

/**
 * Rate Limiter for Registration Endpoint:
 * Limits each IP to 10 registrations per 1 hour to prevent automated account spam.
 */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({
      success: false,
      error: 'Account creation rate limit reached. Please try again later.'
    });
  }
});

module.exports = {
  requireAuth,
  redirectIfAuth,
  loginLimiter,
  registerLimiter
};
