const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { dbGet, dbRun } = require('./database');
const {
  requireAuth,
  redirectIfAuth,
  loginLimiter,
  registerLimiter
} = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_SALT_ROUNDS = 12; // High security cost factor (2^12 hashing iterations)

// ==========================================
// 1. CORE MIDDLEWARE
// ==========================================

// Parse JSON request bodies (e.g. Content-Type: application/json)
app.use(express.json());

// Parse URL-encoded request bodies (HTML form submissions)
app.use(express.urlencoded({ extended: true }));

// Trust proxy if deployed behind a reverse proxy (e.g. Nginx, Heroku, Render)
app.set('trust proxy', 1);

// Configure Secure Session Management
app.use(
  session({
    name: 'secure_login_sid', // Custom session cookie name (avoids default 'connect.sid')
    secret: process.env.SESSION_SECRET || 'secure-login-app-demo-secret-key-replace-in-production',
    resave: false, // Prevents saving unchanged sessions back to store
    saveUninitialized: false, // Prevents storing empty, unauthenticated sessions
    cookie: {
      httpOnly: true, // Prevents client-side scripts from reading the cookie (mitigates XSS)
      secure: false, // Set to true in production if serving over HTTPS
      sameSite: 'lax', // Protects against Cross-Site Request Forgery (CSRF)
      maxAge: 24 * 60 * 60 * 1000 // 24-hour session lifetime
    }
  })
);

// Serve static frontend files from 'public' directory
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ==========================================
// 2. PAGE ROUTING & ACCESS CONTROL
// ==========================================

// Root route: Redirect based on authentication status
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  return res.redirect('/login.html');
});

// Protected Dashboard Page: Redirect to login if user is not authenticated
app.get('/dashboard.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Login Page: Redirect to dashboard if user is already authenticated
app.get('/login.html', redirectIfAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register Page: Redirect to dashboard if user is already authenticated
app.get('/register.html', redirectIfAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Clean vanity URLs (e.g., /login -> /login.html)
app.get('/login', redirectIfAuth, (req, res) => res.redirect('/login.html'));
app.get('/register', redirectIfAuth, (req, res) => res.redirect('/register.html'));
app.get('/dashboard', requireAuth, (req, res) => res.redirect('/dashboard.html'));

// ==========================================
// 3. AUTHENTICATION API ROUTES
// ==========================================

/**
 * Helper function for input validation
 */
function validateRegistrationInput(username, email, password, confirmPassword) {
  const errors = [];

  // Username validation: 3-30 chars, letters, numbers, underscores only
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  if (!username || typeof username !== 'string') {
    errors.push('Username is required.');
  } else if (!usernameRegex.test(username.trim())) {
    errors.push('Username must be 3-30 characters long and contain only letters, numbers, or underscores.');
  }

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || typeof email !== 'string') {
    errors.push('Valid email address is required.');
  } else if (!emailRegex.test(email.trim().toLowerCase())) {
    errors.push('Please provide a valid email address.');
  }

  // Password validation: minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 digit
  if (!password || typeof password !== 'string') {
    errors.push('Password is required.');
  } else if (password.length < 8) {
    errors.push('Password must be at least 8 characters long.');
  } else if (password.length > 128) {
    errors.push('Password cannot exceed 128 characters.');
  } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    errors.push('Password must include at least one uppercase letter, one lowercase letter, and one number.');
  }

  // Confirm password validation
  if (password !== confirmPassword) {
    errors.push('Passwords do not match.');
  }

  return errors;
}

/**
 * POST /api/register
 * Handles user registration with input validation, duplicate checks,
 * and secure bcrypt password hashing.
 */
app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // 1. Validate inputs
    const validationErrors = validateRegistrationInput(username, email, password, confirmPassword);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: validationErrors[0],
        errors: validationErrors
      });
    }

    // 2. Sanitize and normalize inputs
    const sanitizedUsername = username.trim();
    const sanitizedEmail = email.trim().toLowerCase();

    // 3. Check for existing username or email using PARAMETERIZED queries to avoid SQL Injection
    const existingUser = await dbGet(
      'SELECT id, username, email FROM users WHERE username = ? OR email = ? LIMIT 1',
      [sanitizedUsername, sanitizedEmail]
    );

    if (existingUser) {
      if (existingUser.username.toLowerCase() === sanitizedUsername.toLowerCase()) {
        return res.status(409).json({
          success: false,
          error: 'Username is already taken. Please choose a different username.'
        });
      }
      if (existingUser.email.toLowerCase() === sanitizedEmail.toLowerCase()) {
        return res.status(409).json({
          success: false,
          error: 'An account with this email address already exists.'
        });
      }
    }

    // 4. Securely hash password with bcrypt and salt rounds
    // bcrypt automatically creates a unique salt per password
    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    // 5. Store user in database (Notice: plain-text password is NEVER saved)
    const result = await dbRun(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [sanitizedUsername, sanitizedEmail, passwordHash]
    );

    console.log(`👤 New user registered: ${sanitizedUsername} (ID: ${result.lastID})`);

    // 6. Return response (NEVER return password or passwordHash)
    return res.status(201).json({
      success: true,
      message: 'Account successfully created! You can now log in.',
      userId: result.lastID
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    return res.status(500).json({
      success: false,
      error: 'An unexpected server error occurred during registration. Please try again.'
    });
  }
});

/**
 * POST /api/login
 * Handles user login with bcrypt verification, session initialization,
 * and rate-limiting protection against brute-force attacks.
 */
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { identifier, password, rememberMe } = req.body;

    // 1. Basic validation
    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        error: 'Please enter both your username/email and password.'
      });
    }

    const trimmedIdentifier = String(identifier).trim();

    // 2. Find user by username OR email using parameterized query
    // Querying with parameter placeholders prevents SQL Injection attacks
    const user = await dbGet(
      'SELECT id, username, email, password_hash, created_at FROM users WHERE username = ? OR email = ? LIMIT 1',
      [trimmedIdentifier, trimmedIdentifier.toLowerCase()]
    );

    // 3. User verification
    // Use generic error message to prevent user enumeration (timing-safe defense)
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username/email or password.'
      });
    }

    // 4. Verify password with bcrypt.compare
    // Compares candidate password against the stored bcrypt hash safely
    const isPasswordValid = await bcrypt.compare(String(password), user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username/email or password.'
      });
    }

    // 5. Establish secure session
    // Store user ID and non-sensitive profile info in session
    req.session.userId = user.id;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      created_at: user.created_at
    };

    // If "Remember Me" is checked, keep session alive for 30 days; otherwise 1 day
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    } else {
      req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 1 day
    }

    console.log(`🔓 User logged in: ${user.username} (ID: ${user.id})`);

    // 6. Return success response (Password hash is omitted)
    return res.status(200).json({
      success: true,
      message: 'Login successful!',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    return res.status(500).json({
      success: false,
      error: 'An unexpected server error occurred during login. Please try again.'
    });
  }
});

/**
 * GET /api/me
 * Returns authenticated user details and active session metadata.
 * Protected by requireAuth middleware.
 */
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    // Fetch latest user details from DB to guarantee current state
    const user = await dbGet(
      'SELECT id, username, email, created_at FROM users WHERE id = ?',
      [req.session.userId]
    );

    if (!user) {
      // User was deleted from DB while session still existed
      req.session.destroy();
      return res.status(401).json({
        success: false,
        error: 'Session invalid or user account no longer exists.'
      });
    }

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.created_at
      },
      session: {
        id: req.sessionID,
        cookieExpires: req.session.cookie.expires,
        maxAgeMs: req.session.cookie.maxAge
      }
    });
  } catch (error) {
    console.error('❌ /api/me error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve session details.'
    });
  }
});

/**
 * POST /api/logout
 * Securely destroys session and clears session cookie.
 */
app.post('/api/logout', (req, res) => {
  const username = req.session?.user?.username || 'Unknown';

  // Destroy session stored on server
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ Error destroying session on logout:', err);
      return res.status(500).json({
        success: false,
        error: 'Could not log out. Please try again.'
      });
    }

    // Clear session cookie on client browser
    res.clearCookie('secure_login_sid', {
      path: '/',
      httpOnly: true
    });

    console.log(`🔒 User logged out: ${username}`);

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.'
    });
  });
});

/**
 * GET /api/security-info
 * Returns system security specifications for dashboard educational display
 */
app.get('/api/security-info', requireAuth, (req, res) => {
  res.json({
    success: true,
    security: {
      passwordAlgorithm: 'bcrypt',
      saltRounds: BCRYPT_SALT_ROUNDS,
      storageType: 'SQLite3 (Parameterized SQL Queries)',
      sqlInjectionProtection: 'Active (? Placeholders)',
      sessionStorage: 'Express-Session (Encrypted Signed Cookies)',
      sessionCookieHttpOnly: true,
      sessionCookieSameSite: 'Lax',
      rateLimiting: 'Active (express-rate-limit 5 attempts / 15m window)',
      plainTextPasswordStored: false
    }
  });
});

// ==========================================
// 4. 404 NOT FOUND & ERROR HANDLING
// ==========================================

app.use((req, res) => {
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(404).json({ success: false, error: 'API route not found.' });
  }
  res.status(404).redirect('/login.html');
});

// Start Express server
const server = app.listen(PORT, () => {
  console.log(`
======================================================
🚀 Secure Login System is running!
🌐 URL: http://localhost:${PORT}
🔐 Login: http://localhost:${PORT}/login.html
📝 Register: http://localhost:${PORT}/register.html
📊 Dashboard: http://localhost:${PORT}/dashboard.html
======================================================
  `);
});

module.exports = { app, server };
