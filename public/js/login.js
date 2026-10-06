/**
 * Login Page Script
 * Handles credentials submission, rate limiting feedback,
 * show/hide password toggle, and redirect to dashboard.
 */

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const identifierInput = document.getElementById('identifier');
  const passwordInput = document.getElementById('password');
  const rememberMeInput = document.getElementById('rememberMe');
  const submitBtn = document.getElementById('submit-btn');
  const alertBox = document.getElementById('alert-box');
  const alertText = document.getElementById('alert-text');
  const togglePasswordBtn = document.getElementById('toggle-password');

  // ==========================================
  // 1. Check URL Parameters for Feedback
  // ==========================================
  const urlParams = new URLSearchParams(window.location.search);

  if (urlParams.get('registered') === 'true') {
    showAlert('Account created successfully! Please sign in.', 'success');
    const user = urlParams.get('user');
    if (user) {
      identifierInput.value = user;
      passwordInput.focus();
    }
  } else if (urlParams.get('loggedOut') === 'true') {
    showAlert('You have been securely logged out.', 'success');
  } else if (urlParams.get('sessionExpired') === 'true') {
    showAlert('Your session has expired. Please log in again.', 'warning');
  }

  // ==========================================
  // 2. Password Visibility Toggle
  // ==========================================
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      togglePasswordBtn.innerHTML = isPassword
        ? `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>`
        : `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
    });
  }

  // ==========================================
  // 3. Form Submission Handling
  // ==========================================
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const identifier = identifierInput.value.trim();
    const password = passwordInput.value;
    const rememberMe = rememberMeInput ? rememberMeInput.checked : false;

    if (!identifier || !password) {
      showAlert('Please enter both your username/email and password.', 'error');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          identifier,
          password,
          rememberMe
        })
      });

      const data = await response.json();

      if (!response.ok) {
        // Status 401 (Invalid credentials) or 429 (Rate limit reached)
        showAlert(data.error || 'Login failed. Please check your credentials.', 'error');
        setLoading(false);
        return;
      }

      // Login Successful!
      showAlert('Login successful! Redirecting to dashboard...', 'success');

      // Seamless redirect to dashboard
      setTimeout(() => {
        window.location.href = '/dashboard.html';
      }, 500);

    } catch (err) {
      console.error('Login request error:', err);
      showAlert('Unable to reach authentication server. Please check your connection.', 'error');
      setLoading(false);
    }
  });

  // Helper functions
  function showAlert(msg, type = 'error') {
    alertText.textContent = msg;
    alertBox.className = `alert-box alert-${type} visible`;
  }

  function hideAlert() {
    alertBox.className = 'alert-box';
    alertText.textContent = '';
  }

  function setLoading(isLoading) {
    if (isLoading) {
      submitBtn.classList.add('loading');
      submitBtn.disabled = true;
    } else {
      submitBtn.classList.remove('loading');
      submitBtn.disabled = false;
    }
  }
});
