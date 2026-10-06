# 🛡️ Secure Login System

A clean, modern, lightweight, and secure authentication web application built using **Node.js**, **Express**, **SQLite**, **bcrypt**, and **express-session**, with a responsive vanilla **HTML/CSS/JavaScript** frontend.

Designed to demonstrate industry-standard authentication patterns, defense against common web vulnerabilities (SQL Injection, XSS, CSRF, Brute Force), and beginner-friendly code clarity.

---

## 🌟 Key Features

1. **User Registration**:
   - Username and email format validation and sanitization.
   - Real-time password strength meter (calculating length, uppercase, lowercase, and numbers).
   - Dynamic password checklist and match validation.
   - Secure password hashing using **bcrypt** (cost factor 12) before database insertion.
   - Never saves plain-text passwords.

2. **User Login**:
   - Supports sign-in using either **Username** or **Email**.
   - Timing-safe authentication flow and generic error messages (defending against user enumeration).
   - Password verification using `bcrypt.compare()`.
   - "Remember Me" toggle support for extended session expiration.
   - Built-in rate limiting with `express-rate-limit` to prevent brute-force credential stuffing.

3. **Authenticated Dashboard**:
   - Protected route guarded by Express session middleware (`requireAuth`).
   - Displays personalized user greeting, avatar, username, email, member since date, and user ID.
   - Displays real-time session status, expiration timestamps, and security safeguards.

4. **Secure Logout**:
   - Terminates server-side session via `req.session.destroy()`.
   - Clears the signed HTTP-Only session cookie (`res.clearCookie()`).
   - Seamlessly redirects to the login screen with a notification.

5. **Security Safeguards**:
   - **Parameterized SQL Queries**: All database queries use `?` placeholders to eliminate SQL Injection.
   - **Case-Insensitive Uniqueness**: SQLite `COLLATE NOCASE` prevents duplicate accounts with slight casing variations.
   - **HTTP-Only Cookies**: Session cookies cannot be read by JavaScript `document.cookie`, mitigating XSS session hijacking.
   - **SameSite Protection**: Set to `Lax` to protect against Cross-Site Request Forgery (CSRF).
   - **Rate Limiting**: Limits login attempts (5 requests per 15-minute window per IP) and registration attempts.
   - **No Secrets in Responses**: Passwords and password hashes are never returned in JSON payloads or rendered to HTML.

---

## 📁 Project Folder Structure

```text
Secure Login System/
├── data/
│   └── database.sqlite       # Auto-created SQLite database file
├── middleware/
│   └── auth.js               # Route protection & rate limiting middleware
├── public/
│   ├── css/
│   │   └── style.css         # Modern glassmorphism design system & animations
│   ├── js/
│   │   ├── dashboard.js      # Session checks, user profile loader, logout handler
│   │   ├── login.js          # Form handler, password toggle, login fetch logic
│   │   └── register.js       # Live password strength meter, client validation
│   ├── dashboard.html        # Authenticated user dashboard view
│   ├── index.html            # Landing page / automatic authentication router
│   ├── login.html            # Login page view
│   └── register.html         # Registration page view
├── database.js               # SQLite connection setup & promisified query helpers
├── package.json              # Project dependencies and scripts
├── server.js                 # Express application & authentication API endpoints
└── README.md                 # Complete documentation & conceptual guides
```

---

## 🚀 Getting Started

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed (v16.x or newer, recommended Node v18+ or v20+).

Check your installed versions:
```bash
node -v
npm -v
```

### Installation

1. Open your terminal or PowerShell in the project directory:
   ```bash
   cd "Secure Login System"
   ```

2. Install the lightweight dependencies:
   ```bash
   npm install
   ```

### Running the Application

- **Production / Standard Mode**:
  ```bash
  npm start
  ```

- **Development Mode (Auto-restart on file changes in Node 18+)**:
  ```bash
  npm run dev
  ```

Open your browser and navigate to:
```text
http://localhost:3000
```

---

## 🧠 Educational Guide: How It Works

Here is a beginner-friendly breakdown of the core security and backend mechanisms implemented in this project:

### 1. Database Queries & Preventing SQL Injection
**The Vulnerability**: Concatenating strings into SQL queries (e.g., `"SELECT * FROM users WHERE username = '" + input + "'"` ) lets attackers inject malicious SQL commands (like `' OR '1'='1`).

**The Solution**: We use **parameterized queries** in [database.js](file:///c:/Users/Pardhu/OneDrive/Desktop/Secure%20Login%20System/database.js):
```javascript
const user = await dbGet(
  'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?',
  [identifier, identifier.toLowerCase()]
);
```
The database engine treats the `?` parameters strictly as data values, never as executable SQL code.

---

### 2. Password Hashing with bcrypt
**The Vulnerability**: Storing plain-text passwords allows anyone with database read access to compromise all user accounts. Simple hashing algorithms like MD5 or SHA-256 are also unsafe because they are too fast and susceptible to rainbow table lookups.

**The Solution**: We use **bcrypt** with a cost factor (salt rounds = 12):
```javascript
const BCRYPT_SALT_ROUNDS = 12;
const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
```
- **Salt**: bcrypt generates a cryptographically random salt and combines it with the password so identical passwords have completely different hashes.
- **Adaptive Cost**: 12 rounds means $2^{12} = 4096$ hashing iterations. This makes brute-force attacks computationally impractical while taking only a split second for a legitimate login.

---

### 3. Login Verification Flow
When a user attempts to sign in:
1. We query SQLite for the record matching the username or email using a parameterized query.
2. If no record is found, we immediately return a **generic error message**: `"Invalid username/email or password."` This prevents attackers from guessing whether a specific email or username is registered.
3. If the record exists, we use `bcrypt.compare()`:
   ```javascript
   const isMatch = await bcrypt.compare(password, user.password_hash);
   ```
   `bcrypt.compare` extracts the salt from the stored hash, hashes the candidate password using that same salt and cost, and verifies if the resulting hash matches.

---

### 4. Session Management with `express-session`
HTTP is stateless. To remember that a user is logged in:
1. After successful login, Express creates a session on the server and assigns it a unique session ID:
   ```javascript
   req.session.userId = user.id;
   req.session.user = { id: user.id, username: user.username, email: user.email };
   ```
2. Express sends a cookie to the browser named `secure_login_sid` containing the signed session ID.
3. Cookie Security Settings:
   - `httpOnly: true`: Disallows client JavaScript (`document.cookie`) from accessing the session token, protecting against Cross-Site Scripting (XSS) token theft.
   - `sameSite: 'lax'`: Tells the browser not to send the cookie during third-party cross-site requests, mitigating Cross-Site Request Forgery (CSRF).
   - `maxAge`: Sets an expiration window (24 hours standard, 30 days if "Remember Me" is enabled).

---

### 5. Protecting Routes (Authentication Middleware)
To prevent unauthenticated users from accessing protected endpoints:
```javascript
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next(); // User is authenticated, proceed
  }
  // Not authenticated
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  return res.redirect('/login.html');
}
```
Any route with `requireAuth` immediately denies access if a valid session does not exist.

---

### 6. Secure Logout
To properly log out a user, both sides must be cleared:
```javascript
app.post('/api/logout', (req, res) => {
  // 1. Destroy server session
  req.session.destroy((err) => {
    // 2. Clear browser cookie
    res.clearCookie('secure_login_sid');
    return res.json({ message: 'Logged out successfully.' });
  });
});
```

---

### 7. Brute-Force Rate Limiting
To defend against automated dictionary and brute-force attacks, `express-rate-limit` enforces strict thresholds on the `/api/login` endpoint:
- Up to 5 login attempts allowed per IP address within a 15-minute window.
- Exceeding this limit returns HTTP `429 Too Many Requests` with a helpful cooldown notification.

---

## 🛠️ Testing the Application

1. **Test Registration**:
   - Visit `http://localhost:3000/register.html`.
   - Try registering with a weak password (notice the strength meter & requirement checkmarks).
   - Enter matching valid credentials (e.g. `alex_dev`, `alex@example.com`, `SecurePass123!`).
   - Confirm successful registration and automatic redirection.

2. **Test Login**:
   - Try logging in with the wrong password to observe the generic error alert.
   - Log in using either the username (`alex_dev`) or email (`alex@example.com`).

3. **Test Route Protection**:
   - Open a private/incognito window and navigate directly to `http://localhost:3000/dashboard.html`.
   - Notice that the server automatically redirects you to `/login.html`.

4. **Test Logout**:
   - In your authenticated tab, click the **Logout** button.
   - Observe session termination and safe redirection back to `/login.html`.
