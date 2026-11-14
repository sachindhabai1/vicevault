// ==============================================================
// VICEVAULT // Secure Email OTP Authentication & Account Security
// ==============================================================
// Connects frontend to the Node.js + Express Backend with Firebase Admin SDK:
// 1. Email OTP on Signup:
//    - Crypto 6-digit OTP sent via Nodemailer Gmail SMTP
//    - 15-minute visible countdown timer
//    - Max 5 wrong attempts per OTP before invalidation
//    - Single-use: OTP deleted on verification
//    - Resend OTP with 60s cooldown and 5 emails/hour limit
//    - User marked emailVerified: true in Firebase Auth
//    - Direct signInWithCustomToken on successful OTP
// 2. Login Attempt Limiter (Max 5):
//    - Backend validates credentials via Firebase Auth REST API
//    - 5 failed attempts locks account for 15 minutes with live wait timer
//    - Unverified users blocked and redirected to OTP screen
// 3. Protected Dashboard Gate:
//    - Blocks checkout/orders/profile until email is verified

(function() {
  'use strict';

  // Base URL for Backend API
  // Automatically detects if running on port 5000 (Express) or port 3000 / external origin
  const API_BASE = (function() {
    if (window.__API_BASE__) return window.__API_BASE__;
    const loc = window.location || { hostname: 'localhost', port: '5001' };
    if (loc.hostname === 'localhost' || loc.hostname === '127.0.0.1') {
      return loc.port === '5001' ? '' : 'http://localhost:5001';
    }
    // For GitHub Pages or deployed domain, default to current origin or custom backend URL
    return window.__BACKEND_URL__ || 'http://localhost:5001';
  })();

  // State
  let activeVerificationEmail = '';
  let activeVerificationUid = '';
  let otpExpiryTime = 0;
  let otpCountdownInterval = null;
  let resendCooldownSeconds = 0;
  let resendCooldownInterval = null;
  let loginLockoutInterval = null;

  // Validation helpers
  function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email.trim());
  }

  function cleanIndianPhone(raw) {
    if (!raw) return '';
    const digits = String(raw).replace(/[^0-9]/g, '');
    if (digits.length === 10) return digits;
    if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
    if (digits.length > 10) return digits.slice(-10);
    return digits;
  }

  function isValidIndianPhone(raw) {
    const cleaned = cleanIndianPhone(raw);
    return /^[6-9]\d{9}$/.test(cleaned);
  }

  // ==========================================
  // INJECT LUXURY EMAIL OTP MODAL INTO DOM
  // ==========================================
  function ensureModals() {
    if (!document.getElementById('firebaseOtpModal')) {
      const otpModal = document.createElement('div');
      otpModal.id = 'firebaseOtpModal';
      otpModal.className = 'hidden fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/90 backdrop-blur-2xl transition-all duration-300';
      otpModal.innerHTML = `
        <div class="relative w-full max-w-md apple-glass-panel rounded-3xl p-6 sm:p-7 border border-[#F0D9B5]/40 shadow-2xl space-y-4 text-center bg-[#1A1A1F]/95">
          <button type="button" onclick="window.firebaseAuthService.closeOtpModal()" class="absolute top-4 right-4 w-7 h-7 rounded-full bg-white/[0.08] hover:bg-white/[0.2] text-[#86868b] hover:text-white flex items-center justify-center transition-colors">
            ✕
          </button>
          
          <div class="w-12 h-12 mx-auto rounded-2xl bg-[#F0D9B5]/15 border border-[#F0D9B5]/40 flex items-center justify-center text-[#F0D9B5]">
            <i data-lucide="mail-check" class="w-6 h-6"></i>
          </div>

          <div>
            <h3 class="text-lg font-bold text-white">Enter 6-Digit Email OTP</h3>
            <p class="text-xs text-[#86868b] mt-1">
              Humne <span id="fbOtpTargetEmail" class="text-[#F0D9B5] font-mono font-semibold">user@email.com</span> par official verification code bheja hai.
            </p>
          </div>

          <!-- Visible 15-Minute Expiry Countdown Badge -->
          <div class="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-between text-xs">
            <span class="text-amber-200/90 flex items-center gap-1.5 font-medium">
              <i data-lucide="clock" class="w-4 h-4 text-amber-400"></i>
              <span>OTP Validity (15 Mins):</span>
            </span>
            <span id="fbOtpCountdownTimer" class="font-mono font-extrabold text-amber-300 text-sm">15:00</span>
          </div>

          <div class="space-y-2">
            <input type="text" id="fbOtpInput" maxlength="6" pattern="[0-9]{6}" placeholder="------" 
                   class="w-full px-4 py-3.5 bg-black/80 border border-white/[0.15] rounded-xl text-white text-center font-mono tracking-[0.5em] text-xl font-bold focus:outline-none focus:border-[#F0D9B5]">
            <div id="fbOtpError" class="text-rose-400 text-xs hidden text-center font-medium p-2 bg-rose-950/30 rounded-lg border border-rose-800/30"></div>
          </div>

          <button type="button" id="btnFbVerifyOtp" onclick="window.firebaseAuthService.verifyEnteredOtp()" 
                  class="w-full py-3.5 rounded-full bg-gradient-to-r from-[#F0D9B5] to-[#D8BE96] hover:brightness-110 text-[#1A1A1F] font-extrabold text-xs shadow-lg shadow-[#F0D9B5]/20 transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-95">
            <span id="btnFbVerifyOtpText">Verify & Unlock Account</span>
          </button>

          <div class="p-2.5 rounded-xl bg-black/40 border border-white/[0.06] text-[11px] text-[#86868b] space-y-1 text-left">
            <p>🔒 <b>Security Rules:</b></p>
            <p>• Max <b>5 attempts</b> allowed. Uske baad OTP invalidate ho jayega.</p>
            <p>• OTP single-use hai aur verify hote hi delete ho jayega.</p>
          </div>

          <div class="flex items-center justify-between text-xs text-[#86868b] pt-1 border-t border-white/[0.06]">
            <span id="fbOtpResendStatus" class="text-[11px] font-mono text-[#86868b]">Resend available in: <b id="fbOtpResendSeconds">60s</b></span>
            <button type="button" id="btnFbResendOtp" onclick="window.firebaseAuthService.resendOtp()" disabled 
                    class="text-[#F0D9B5] hover:underline disabled:opacity-40 disabled:no-underline font-semibold cursor-pointer text-xs">
              Resend OTP
            </button>
          </div>
        </div>
      `;
      document.body.appendChild(otpModal);
    }

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }

  // ==========================================
  // COUNTDOWN TIMERS
  // ==========================================

  /**
   * 15-Minute Strict Expiry Countdown
   */
  function startOtpExpiryCountdown(expiresAt) {
    if (otpCountdownInterval) clearInterval(otpCountdownInterval);
    otpExpiryTime = expiresAt || (Date.now() + 15 * 60 * 1000);

    const timerEl = document.getElementById('fbOtpCountdownTimer');
    const errEl = document.getElementById('fbOtpError');
    const verifyBtn = document.getElementById('btnFbVerifyOtp');

    function tick() {
      const now = Date.now();
      const remainingMs = otpExpiryTime - now;

      if (remainingMs <= 0) {
        clearInterval(otpCountdownInterval);
        if (timerEl) {
          timerEl.textContent = 'EXPIRED';
          timerEl.className = 'font-mono font-bold text-rose-400 text-sm';
        }
        if (errEl) {
          errEl.textContent = '⏳ OTP expire ho chuka hai (15 minutes limit pass ho gayi). Kripya "Resend OTP" par click karein.';
          errEl.classList.remove('hidden');
        }
        if (verifyBtn) verifyBtn.disabled = true;
      } else {
        const mins = Math.floor(remainingMs / 60000);
        const secs = Math.floor((remainingMs % 60000) / 1000);
        const formatted = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
        if (timerEl) {
          timerEl.textContent = formatted;
          timerEl.className = mins < 2 ? 'font-mono font-bold text-rose-400 text-sm animate-pulse' : 'font-mono font-extrabold text-amber-300 text-sm';
        }
        if (verifyBtn) verifyBtn.disabled = false;
      }
    }

    tick();
    otpCountdownInterval = setInterval(tick, 1000);
  }

  /**
   * 60-Second Cooldown for Resend OTP Button
   */
  function startResendCooldown(seconds = 60) {
    if (resendCooldownInterval) clearInterval(resendCooldownInterval);
    resendCooldownSeconds = seconds;

    const resendBtn = document.getElementById('btnFbResendOtp');
    const resendStatus = document.getElementById('fbOtpResendStatus');
    const resendSecondsEl = document.getElementById('fbOtpResendSeconds');

    function tick() {
      if (resendCooldownSeconds > 0) {
        if (resendBtn) resendBtn.disabled = true;
        if (resendStatus) resendStatus.classList.remove('hidden');
        if (resendSecondsEl) resendSecondsEl.textContent = `${resendCooldownSeconds}s`;
        resendCooldownSeconds--;
      } else {
        clearInterval(resendCooldownInterval);
        if (resendBtn) resendBtn.disabled = false;
        if (resendStatus) resendStatus.classList.add('hidden');
      }
    }

    tick();
    resendCooldownInterval = setInterval(tick, 1000);
  }

  // ==========================================
  // SIGNUP FLOW (Talks to Node.js /api/auth/signup)
  // ==========================================
  async function handleSignUp({ name, email, phone, password }) {
    ensureModals();

    if (!name || name.trim().length < 2) {
      throw new Error('Kripya apna poora naam (Full Name) dalein.');
    }
    if (!isValidEmail(email)) {
      throw new Error('Kripya valid email address dalein (e.g. name@gmail.com).');
    }
    if (!password || password.length < 6) {
      throw new Error('Password kam se kam 6 characters ka hona chahiye.');
    }

    const normEmail = email.trim().toLowerCase();
    const cleanPhone = cleanIndianPhone(phone);

    try {
      const response = await fetch(`${API_BASE}/api/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          email: normEmail,
          password: password,
          phone: cleanPhone
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Signup fail ho gaya. Kripya dobara try karein.');
      }

      activeVerificationEmail = normEmail;
      activeVerificationUid = data.uid || '';

      // Open OTP Entry Modal
      openOtpModal(normEmail, data.expiresAt);
      startResendCooldown(60);

      if (typeof showToast === 'function') {
        showToast('✉️ 6-digit OTP aapki email par bhej diya gaya hai!');
      }

      return { success: true, pendingOtp: true };

    } catch (err) {
      console.error('Signup error:', err);
      throw err;
    }
  }

  // ==========================================
  // VERIFY ENTERED OTP (Talks to /api/auth/verify-otp)
  // ==========================================
  async function verifyEnteredOtp() {
    const input = document.getElementById('fbOtpInput');
    const errEl = document.getElementById('fbOtpError');
    const btn = document.getElementById('btnFbVerifyOtp');
    const btnText = document.getElementById('btnFbVerifyOtpText');

    if (!input) return;
    const otp = input.value.trim();

    if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
      if (errEl) {
        errEl.textContent = '❌ Kripya pura 6-digit number OTP dalein.';
        errEl.classList.remove('hidden');
      }
      input.focus();
      return;
    }

    if (!activeVerificationEmail) {
      if (errEl) {
        errEl.textContent = '❌ Email session expire ho gayi. Kripya pehle Sign Up ya Login karein.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    // Loading State
    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Verifying with Server...';
    if (errEl) errEl.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: activeVerificationEmail,
          otp: otp
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (errEl) {
          errEl.textContent = data.error || 'Galat OTP! Kripya dobara check karein.';
          errEl.classList.remove('hidden');
        }
        if (data.expired || data.maxAttemptsExceeded) {
          if (btn) btn.disabled = true;
        }
        return;
      }

      // --- OTP VERIFICATION SUCCESSFUL ---
      clearInterval(otpCountdownInterval);
      clearInterval(resendCooldownInterval);

      // Sign in to client Firebase SDK using returned Custom Token
      if (data.customToken && window.firebaseAuth) {
        try {
          await window.firebaseAuth.signInWithCustomToken(data.customToken);
          console.log('⚡ Firebase client authenticated via Custom Token!');
        } catch (tokenErr) {
          console.warn('Custom token sign-in notice:', tokenErr);
        }
      }

      // Sync local storage profile
      const userProfile = {
        id: data.uid || activeVerificationUid || 'USR-' + Math.floor(100000 + Math.random() * 900000),
        uid: data.uid || activeVerificationUid,
        email: activeVerificationEmail,
        name: activeVerificationEmail.split('@')[0],
        emailVerified: true,
        phoneVerified: true,
        joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
      };
      localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));

      closeOtpModal();

      if (typeof closeAuthModal === 'function') {
        closeAuthModal(true);
      }
      if (typeof updateNavUserProfile === 'function') {
        updateNavUserProfile(userProfile);
      }
      if (typeof showToast === 'function') {
        showToast('🎉 Email successfully verified! Account fully unlocked.');
      }

    } catch (err) {
      console.error('Verify OTP error:', err);
      if (errEl) {
        errEl.textContent = 'Server se connect nahi ho saka. Kripya internet ya server check karein.';
        errEl.classList.remove('hidden');
      }
    } finally {
      if (btn) btn.disabled = false;
      if (btnText) btnText.textContent = 'Verify & Unlock Account';
    }
  }

  // ==========================================
  // RESEND OTP (Talks to /api/auth/resend-otp)
  // ==========================================
  async function resendOtp() {
    if (!activeVerificationEmail) {
      if (typeof showToast === 'function') showToast('Kripya pehle email enter karein.');
      return;
    }

    const resendBtn = document.getElementById('btnFbResendOtp');
    if (resendBtn) resendBtn.disabled = true;

    try {
      const response = await fetch(`${API_BASE}/api/auth/resend-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: activeVerificationEmail })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (typeof showToast === 'function') showToast('⚠️ ' + (data.error || 'Resend fail ho gaya.'));
        if (data.cooldown && data.waitSeconds) {
          startResendCooldown(data.waitSeconds);
        }
        return;
      }

      startOtpExpiryCountdown(data.expiresAt);
      startResendCooldown(60);

      const errEl = document.getElementById('fbOtpError');
      if (errEl) errEl.classList.add('hidden');
      const input = document.getElementById('fbOtpInput');
      if (input) {
        input.value = '';
        input.focus();
      }

      if (typeof showToast === 'function') {
        showToast('✉️ Naya OTP bhej diya gaya hai (Valid for 15 mins).');
      }

    } catch (err) {
      console.error('Resend OTP error:', err);
      if (typeof showToast === 'function') showToast('Server error while resending OTP.');
    }
  }

  // ==========================================
  // LOGIN FLOW (Enforces Max 5 Failed Attempts & 15m Lock)
  // ==========================================
  async function handleLogin({ identifier, password }) {
    ensureModals();

    if (!identifier || !password) {
      throw new Error('Email aur password dono enter karein.');
    }

    const normEmail = identifier.trim().toLowerCase();

    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: normEmail,
        password: password
      })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      // 1. Account Locked due to 5 failed attempts
      if (data.locked) {
        startLoginLockoutTimer(data.remainingWaitSeconds || (15 * 60));
        throw new Error(data.error || 'Account temporarily locked due to 5 failed login attempts.');
      }

      // 2. Unverified User: Block login and redirect to OTP screen!
      if (data.unverified) {
        activeVerificationEmail = normEmail;
        activeVerificationUid = data.uid || '';
        if (typeof closeAuthModal === 'function') closeAuthModal(false);
        openOtpModal(normEmail, data.expiresAt);
        startResendCooldown(60);
        throw new Error('Aapka email verified nahi hai. Kripya email par aaya 6-digit OTP dalein.');
      }

      // 3. Failed attempt with remaining attempts
      throw new Error(data.error || 'Invalid email or password.');
    }

    // --- LOGIN SUCCESS ---
    // Clear any active lockout timers
    if (loginLockoutInterval) clearInterval(loginLockoutInterval);

    // Client sign-in with returned Custom Token
    if (data.customToken && window.firebaseAuth) {
      try {
        await window.firebaseAuth.signInWithCustomToken(data.customToken);
      } catch (tokenErr) {
        console.warn('Sign in with custom token warning:', tokenErr);
      }
    }

    // Save profile to localStorage
    const userProfile = {
      id: data.user.uid,
      uid: data.user.uid,
      name: data.user.name || normEmail.split('@')[0],
      email: data.user.email,
      emailVerified: true,
      phoneVerified: true,
      joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
    };
    localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));

    if (typeof closeAuthModal === 'function') closeAuthModal(true);
    if (typeof updateNavUserProfile === 'function') updateNavUserProfile(userProfile);
    if (typeof showToast === 'function') {
      showToast('👋 Welcome back, ' + userProfile.name + '!');
    }

    return { success: true, user: userProfile };
  }

  /**
   * Live Lockout Timer Display for Login Form
   */
  function startLoginLockoutTimer(totalSeconds) {
    if (loginLockoutInterval) clearInterval(loginLockoutInterval);
    let secondsLeft = totalSeconds;

    const loginErrorEl = document.getElementById('loginError');
    const loginBtn = document.getElementById('btnSubmitLogin');

    function tick() {
      if (secondsLeft > 0) {
        const mins = Math.floor(secondsLeft / 60);
        const secs = secondsLeft % 60;
        const msg = `🔒 Account locked due to 5 failed attempts. Please wait ${mins}m ${secs}s before trying again.`;
        if (loginErrorEl) {
          loginErrorEl.textContent = msg;
          loginErrorEl.classList.remove('hidden');
        }
        if (loginBtn) loginBtn.disabled = true;
        secondsLeft--;
      } else {
        clearInterval(loginLockoutInterval);
        if (loginErrorEl) loginErrorEl.classList.add('hidden');
        if (loginBtn) loginBtn.disabled = false;
      }
    }

    tick();
    loginLockoutInterval = setInterval(tick, 1000);
  }

  // ==========================================
  // SIGN OUT
  // ==========================================
  async function signOut() {
    if (window.firebaseAuth) {
      try {
        await window.firebaseAuth.signOut();
      } catch (e) {}
    }
    localStorage.removeItem('vicevault_current_user');
    if (typeof updateNavGuestProfile === 'function') updateNavGuestProfile();
    if (typeof showToast === 'function') showToast('Logged out successfully.');
    window.location.reload();
  }

  // ==========================================
  // MODAL CONTROLLERS
  // ==========================================
  function openOtpModal(email, expiresAt) {
    ensureModals();
    activeVerificationEmail = email;

    const modal = document.getElementById('firebaseOtpModal');
    const target = document.getElementById('fbOtpTargetEmail');
    const input = document.getElementById('fbOtpInput');
    const err = document.getElementById('fbOtpError');

    if (target) target.textContent = email;
    if (input) {
      input.value = '';
      setTimeout(() => input.focus(), 150);
    }
    if (err) err.classList.add('hidden');
    if (modal) modal.classList.remove('hidden');

    startOtpExpiryCountdown(expiresAt);
  }

  function closeOtpModal() {
    const modal = document.getElementById('firebaseOtpModal');
    if (modal) modal.classList.add('hidden');
    if (otpCountdownInterval) clearInterval(otpCountdownInterval);
  }

  // ==========================================
  // PROTECTED ACTION GATE
  // ==========================================
  function isUserFullyVerified(user) {
    if (!user) {
      try {
        const raw = localStorage.getItem('vicevault_current_user');
        if (!raw) return false;
        const parsed = JSON.parse(raw);
        return parsed && parsed.emailVerified === true;
      } catch (e) {
        return false;
      }
    }
    return Boolean(user.emailVerified);
  }

  function requireFullyVerifiedUser(onVerifiedCallback) {
    const localUserRaw = localStorage.getItem('vicevault_current_user');
    let localUser = null;
    try {
      localUser = localUserRaw ? JSON.parse(localUserRaw) : null;
    } catch (e) {}

    const auth = window.firebaseAuth;
    const curUser = auth ? auth.currentUser : null;

    if (!curUser && !localUser) {
      if (typeof showToast === 'function') {
        showToast('🔒 Protected action: Kripya pehle VIP login karein.');
      }
      if (typeof openAuthModal === 'function') openAuthModal('login');
      return false;
    }

    if (!isUserFullyVerified(curUser || localUser)) {
      if (typeof showToast === 'function') {
        showToast('⚠️ Email verification zaroori hai.');
      }
      const email = (curUser && curUser.email) || (localUser && localUser.email) || '';
      if (email) {
        openOtpModal(email);
      }
      return false;
    }

    if (typeof onVerifiedCallback === 'function') {
      onVerifiedCallback(curUser || localUser);
    }
    return true;
  }

  // Initialize modals on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ensureModals);
  } else {
    ensureModals();
  }

  // Export public service API
  window.firebaseAuthService = {
    handleSignUp,
    handleLogin,
    signOut,
    verifyEnteredOtp,
    resendOtp,
    openOtpModal,
    closeOtpModal,
    isUserFullyVerified,
    requireFullyVerifiedUser,
    cleanIndianPhone,
    isValidIndianPhone,
    isValidEmail
  };

})();
