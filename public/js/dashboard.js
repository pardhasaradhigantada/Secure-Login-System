/**
 * Dashboard Page Script
 * Verifies session authentication, populates user profile data,
 * loads security specifications, and manages secure session termination (logout).
 */

document.addEventListener('DOMContentLoaded', async () => {
  const userGreeting = document.getElementById('user-greeting');
  const userEmailSub = document.getElementById('user-email-sub');
  const userAvatar = document.getElementById('user-avatar');
  const valUsername = document.getElementById('val-username');
  const valEmail = document.getElementById('val-email');
  const valUserId = document.getElementById('val-user-id');
  const valCreatedAt = document.getElementById('val-created-at');
  const valSessionStatus = document.getElementById('val-session-status');
  const valCookieExpires = document.getElementById('val-cookie-expires');
  const logoutBtn = document.getElementById('logout-btn');

  // ==========================================
  // 1. Fetch Current User Profile & Session
  // ==========================================
  try {
    const response = await fetch('/api/me', {
      headers: {
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      // Not authenticated or session expired -> redirect to login page
      console.warn('Unauthorized access. Redirecting to login...');
      window.location.href = '/login.html?sessionExpired=true';
      return;
    }

    const data = await response.json();
    const user = data.user;
    const session = data.session;

    // Display user profile info
    if (userGreeting) userGreeting.textContent = user.username;
    if (userEmailSub) userEmailSub.textContent = user.email;
    if (userAvatar) userAvatar.textContent = user.username.charAt(0).toUpperCase();

    if (valUsername) valUsername.textContent = user.username;
    if (valEmail) valEmail.textContent = user.email;
    if (valUserId) valUserId.textContent = `#${user.id}`;

    if (valCreatedAt && user.createdAt) {
      const createdDate = new Date(user.createdAt);
      valCreatedAt.textContent = createdDate.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    }

    if (valSessionStatus) {
      valSessionStatus.innerHTML = `
        <span class="status-dot"></span>
        <span>Active (Authenticated)</span>
      `;
    }

    if (valCookieExpires && session.cookieExpires) {
      const expDate = new Date(session.cookieExpires);
      valCookieExpires.textContent = expDate.toLocaleString();
    } else if (valCookieExpires) {
      valCookieExpires.textContent = '24 Hours (Session Cookie)';
    }

  } catch (err) {
    console.error('Failed to load user profile:', err);
    window.location.href = '/login.html';
    return;
  }

  // ==========================================
  // 2. Fetch Security Architecture Specs
  // ==========================================
  try {
    const secResponse = await fetch('/api/security-info');
    if (secResponse.ok) {
      const secData = await secResponse.json();
      const sec = secData.security;
      
      const secHashEl = document.getElementById('sec-hash');
      const secDbEl = document.getElementById('sec-db');
      const secSessionEl = document.getElementById('sec-session');
      const secRateEl = document.getElementById('sec-rate');

      if (secHashEl) secHashEl.textContent = `${sec.passwordAlgorithm} (Cost Factor: ${sec.saltRounds} rounds)`;
      if (secDbEl) secDbEl.textContent = `${sec.storageType} - ${sec.sqlInjectionProtection}`;
      if (secSessionEl) secSessionEl.textContent = `Signed HTTP-Only, SameSite=${sec.sessionCookieSameSite}`;
      if (secRateEl) secRateEl.textContent = sec.rateLimiting;
    }
  } catch (err) {
    console.warn('Could not load security metadata:', err);
  }

  // ==========================================
  // 3. Handle Secure Logout
  // ==========================================
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      logoutBtn.disabled = true;
      logoutBtn.innerHTML = `
        <span class="spinner" style="display:inline-block; border-color: rgba(255,255,255,0.3); border-top-color: #ef4444;"></span>
        <span>Logging out...</span>
      `;

      try {
        const response = await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          }
        });

        if (response.ok) {
          // Destroyed session on backend, redirect to login page
          window.location.href = '/login.html?loggedOut=true';
        } else {
          alert('Could not complete logout. Redirecting to login.');
          window.location.href = '/login.html';
        }
      } catch (err) {
        console.error('Logout error:', err);
        window.location.href = '/login.html?loggedOut=true';
      }
    });
  }
});
