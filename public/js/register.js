/**
 * Registration Page Script
 * Handles real-time input validation, password strength calculation,
 * show/hide password toggles, and async API registration submission.
 */

document.addEventListener('DOMContentLoaded', () => {
  const registerForm = document.getElementById('register-form');
  const usernameInput = document.getElementById('username');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const submitBtn = document.getElementById('submit-btn');
  const alertBox = document.getElementById('alert-box');
  const alertText = document.getElementById('alert-text');

  // Password Visibility Toggles
  const togglePasswordBtn = document.getElementById('toggle-password');
  const toggleConfirmPasswordBtn = document.getElementById('toggle-confirm-password');

  // Strength Meter Elements
  const meterFill = document.getElementById('meter-fill');
  const meterText = document.getElementById('meter-text');

  // Requirement Checklist Items
  const reqLength = document.getElementById('req-length');
  const reqUppercase = document.getElementById('req-uppercase');
  const reqLowercase = document.getElementById('req-lowercase');
  const reqNumber = document.getElementById('req-number');

  // ==========================================
  // 1. Password Visibility Toggle
  // ==========================================
  function setupPasswordToggle(btn, input) {
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      btn.innerHTML = isPassword
        ? `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>`
        : `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
    });
  }

  setupPasswordToggle(togglePasswordBtn, passwordInput);
  setupPasswordToggle(toggleConfirmPasswordBtn, confirmPasswordInput);

  // ==========================================
  // 2. Real-time Password Strength Meter
  // ==========================================
  passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    const hasLength = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasNum = /[0-9]/.test(val);

    // Update individual requirement tags
    updateReq(reqLength, hasLength);
    updateReq(reqUppercase, hasUpper);
    updateReq(reqLowercase, hasLower);
    updateReq(reqNumber, hasNum);

    // Calculate score (0 to 4)
    let score = 0;
    if (hasLength) score++;
    if (hasUpper) score++;
    if (hasLower) score++;
    if (hasNum) score++;

    // Update meter fill and label
    if (val.length === 0) {
      meterFill.style.width = '0%';
      meterFill.style.backgroundColor = 'transparent';
      meterText.textContent = 'None';
      meterText.style.color = 'var(--text-dim)';
    } else if (score <= 1) {
      meterFill.style.width = '25%';
      meterFill.style.backgroundColor = '#ef4444'; // Red
      meterText.textContent = 'Weak';
      meterText.style.color = '#ef4444';
    } else if (score === 2) {
      meterFill.style.width = '50%';
      meterFill.style.backgroundColor = '#f97316'; // Orange
      meterText.textContent = 'Fair';
      meterText.style.color = '#f97316';
    } else if (score === 3) {
      meterFill.style.width = '75%';
      meterFill.style.backgroundColor = '#eab308'; // Yellow
      meterText.textContent = 'Good';
      meterText.style.color = '#eab308';
    } else {
      meterFill.style.width = '100%';
      meterFill.style.backgroundColor = '#10b981'; // Green
      meterText.textContent = 'Strong';
      meterText.style.color = '#10b981';
    }

    // Check if confirm password matches while typing
    checkPasswordsMatch();
  });

  confirmPasswordInput.addEventListener('input', checkPasswordsMatch);

  function checkPasswordsMatch() {
    const pwd = passwordInput.value;
    const confirm = confirmPasswordInput.value;
    const errorMsg = document.getElementById('confirm-password-error');
    if (confirm && pwd !== confirm) {
      errorMsg.textContent = 'Passwords do not match.';
      errorMsg.classList.add('visible');
    } else {
      errorMsg.classList.remove('visible');
    }
  }

  function updateReq(el, isValid) {
    if (!el) return;
    if (isValid) {
      el.classList.add('valid');
    } else {
      el.classList.remove('valid');
    }
  }

  // ==========================================
  // 3. Form Submission via Fetch API
  // ==========================================
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // Quick client-side sanity checks
    if (!username || !email || !password || !confirmPassword) {
      showAlert('All fields are required.', 'error');
      return;
    }

    if (username.length < 3 || username.length > 30) {
      showAlert('Username must be between 3 and 30 characters.', 'error');
      return;
    }

    if (password.length < 8) {
      showAlert('Password must be at least 8 characters long.', 'error');
      return;
    }

    if (password !== confirmPassword) {
      showAlert('Passwords do not match. Please verify.', 'error');
      return;
    }

    // Put button in loading state
    setLoading(true);

    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          username,
          email,
          password,
          confirmPassword
        })
      });

      const data = await response.json();

      if (!response.ok) {
        // Handled server error (validation, duplicate username/email, or rate limit)
        showAlert(data.error || 'Registration failed. Please try again.', 'error');
        setLoading(false);
        return;
      }

      // Success!
      showAlert('Account created successfully! Redirecting to login...', 'success');
      registerForm.reset();

      // Smooth redirect after 1.2 seconds
      setTimeout(() => {
        window.location.href = `/login.html?registered=true&user=${encodeURIComponent(username)}`;
      }, 1200);

    } catch (err) {
      console.error('Fetch error:', err);
      showAlert('Network error or server unreachable. Please check your connection.', 'error');
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
