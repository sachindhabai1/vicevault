// ==============================================================
// VICEVAULT // Secure Email OTP Authentication & 12-Hour Account Lockout
// ==============================================================
// Connects frontend to the Node.js + Express Backend with Firebase Admin SDK:
// 1. Dedicated 6-Digit Email OTP Slot:
//    - Seamlessly integrated inside Auth Modal and popup modal
//    - Auto-focus box 1, auto-advance, backspace navigation, paste full 6 digits
//    - Numbers only, auto-verifies when all 6 boxes are filled + Verify button
//    - Target email displayed
//    - Visible 15:00 strict countdown timer
//    - Resend OTP button with 60s cooldown timer
//    - Clear error messages with remaining attempts
// 2. 12-Hour Account Lockout on 5 Failed Attempts:
//    - 5 wrong attempts (OTP or Password) locks account for exactly 12 hours
//    - Live ticking countdown timer formatted with hours, minutes, and seconds (e.g. 11h 59m 45s)
//    - Automatically unlocks / updates after 12 hours
// 3. Protected Dashboard Gate:
//    - User is signed in ONLY after correct OTP is entered
//    - Backend returns custom token -> signInWithCustomToken

(function() {
  'use strict';

  // Base URL for Backend API
  const API_BASE = (function() {
    if (window.__API_BASE__) return window.__API_BASE__;
    if (window.__BACKEND_URL__) return window.__BACKEND_URL__;
    const loc = window.location || { hostname: 'localhost', port: '5001' };
    if (loc.hostname === 'localhost' || loc.hostname === '127.0.0.1') {
      if (loc.port === '5001') {
        return '';
      }
      return 'http://localhost:5001';
    }
    // Production / GitHub Pages fallback
    return 'http://localhost:5001';
  })();

  // State
  let activeVerificationEmail = '';
  let activeVerificationUid = '';
  let otpExpiryTime = 0;
  let otpCountdownInterval = null;
  let resendCooldownSeconds = 0;
  let resendCooldownInterval = null;
  let loginLockoutInterval = null;
  let otpLockoutInterval = null;

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

  /**
   * Format seconds into human readable duration: "11h 59m 45s" or "14m 20s"
   */
  function formatRemainingDuration(totalSecs) {
    const s = Math.max(0, Math.ceil(totalSecs));
    const hours = Math.floor(s / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    if (hours > 0) {
      return `${hours}h ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`;
    }
    return `${mins}m ${String(secs).padStart(2, '0')}s`;
  }

  // ==========================================
  // INJECT LUXURY 6-DIGIT EMAIL OTP MODAL INTO DOM
  // ==========================================
  function ensureModals() {
    if (!document.getElementById('firebaseOtpModal')) {
      const otpModal = document.createElement('div');
      otpModal.id = 'firebaseOtpModal';
      otpModal.className = 'hidden fixed inset-0 z-[9999] flex items-center justify-center p-3.5 sm:p-4 bg-black/90 backdrop-blur-2xl transition-all duration-300';
      otpModal.innerHTML = `
        <div class="relative w-full max-w-md apple-glass-panel rounded-3xl p-6 sm:p-7 border border-[#F0D9B5]/40 shadow-2xl space-y-4 text-center bg-[#1A1A1F]/95">
          <!-- Close Button -->
          <button type="button" onclick="window.firebaseAuthService.closeOtpModal()" class="absolute top-4 right-4 w-7 h-7 rounded-full bg-white/[0.08] hover:bg-white/[0.2] text-[#86868b] hover:text-white flex items-center justify-center transition-colors cursor-pointer" title="Close">
            ✕
          </button>
          
          <!-- Brand Badge -->
          <div class="w-12 h-12 mx-auto rounded-2xl bg-[#F0D9B5]/15 border border-[#F0D9B5]/40 flex items-center justify-center text-[#F0D9B5] shadow-lg shadow-[#F0D9B5]/20">
            <i data-lucide="mail-check" class="w-6 h-6"></i>
          </div>

          <div>
            <span class="text-[10px] uppercase font-bold tracking-widest text-[#F0D9B5] bg-[#F0D9B5]/10 px-3 py-0.5 rounded-full border border-[#F0D9B5]/30">Verification Required</span>
            <h3 class="text-lg font-bold text-white tracking-tight mt-1">Enter 6-Digit Email OTP</h3>
            <p class="text-xs text-[#86868b] mt-1">
              Humne aapki email par 6-digit verification code bheja hai:<br>
              <span id="fbOtpTargetEmail" class="text-[#F0D9B5] font-mono font-semibold text-xs sm:text-sm">user@email.com</span>
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

          <!-- SIX SEPARATE INPUT BOXES (ONE PER DIGIT) -->
          <div class="space-y-2.5">
            <div class="flex items-center justify-center gap-2 sm:gap-2.5 py-1" id="fbOtpBoxesContainer">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="0" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner" autocomplete="one-time-code">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="1" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="2" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="3" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="4" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner">
              <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" data-index="5" class="fb-otp-box w-11 h-13 sm:w-12 sm:h-14 text-center font-mono text-xl sm:text-2xl font-bold bg-black/80 border border-white/[0.15] rounded-xl text-white focus:outline-none focus:border-[#F0D9B5] focus:ring-1 focus:ring-[#F0D9B5] transition-all shadow-inner">
            </div>

            <!-- Clear Error Messages Container -->
            <div id="fbOtpError" class="text-rose-400 text-xs hidden text-center font-medium p-2.5 bg-rose-950/30 rounded-lg border border-rose-800/30 leading-relaxed"></div>
          </div>

          <!-- Verify Button -->
          <button type="button" id="btnFbVerifyOtp" onclick="window.firebaseAuthService.verifyEnteredOtp()" 
                  class="w-full py-3.5 rounded-full bg-gradient-to-r from-[#F0D9B5] to-[#D8BE96] hover:brightness-110 text-[#1A1A1F] font-extrabold text-xs shadow-lg shadow-[#F0D9B5]/20 transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-95">
            <span id="btnFbVerifyOtpText">Verify & Unlock Account</span>
          </button>

          <!-- Security Explanations -->
          <div class="p-2.5 rounded-xl bg-black/40 border border-white/[0.06] text-[11px] text-[#86868b] space-y-1 text-left">
            <p class="font-medium text-white/90">🔒 <b>Security Rules:</b></p>
            <p>• Max <b>5 attempts</b> allowed. 5 galat attempts ke baad account <b>12 ghante</b> ke liye lock ho jayega.</p>
            <p>• OTP single-use hai aur verify hone par turant delete ho jata hai.</p>
          </div>

          <!-- Resend with 60-Second Cooldown -->
          <div class="flex items-center justify-between text-xs text-[#86868b] pt-1 border-t border-white/[0.06]">
            <span id="fbOtpResendStatus" class="text-[11px] font-mono text-[#86868b]">Resend code in: <b id="fbOtpResendSeconds">60s</b></span>
            <button type="button" id="btnFbResendOtp" onclick="window.firebaseAuthService.resendOtp()" disabled 
                    class="text-[#F0D9B5] hover:underline disabled:opacity-40 disabled:no-underline font-semibold cursor-pointer text-xs">
              Resend OTP
            </button>
          </div>
        </div>
      `;
      document.body.appendChild(otpModal);
      setupOtpInputHandlers('fbOtpBoxesContainer', '.fb-otp-box');
    }

    // Also bind event listeners on inline auth modal boxes if present
    setupOtpInputHandlers('authModalOtpBoxesContainer', '.modal-otp-box');
    setupOtpInputHandlers('regInlineOtpBoxes', '.reg-inline-otp-box');

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }

  // ==========================================
  // 6-BOX INTERACTION LOGIC
  // ==========================================
  function setupOtpInputHandlers(containerId, boxSelector) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const boxes = container.querySelectorAll(boxSelector);

    boxes.forEach((box, idx) => {
      // Avoid duplicate event listener bindings
      if (box.dataset.bound === 'true') return;
      box.dataset.bound = 'true';

      // 1. Input event: accept numbers only, advance to next box, auto-verify if all 6 filled
      box.addEventListener('input', () => {
        const val = box.value;
        const clean = val.replace(/\D/g, ''); // Numbers only
        box.value = clean ? clean.slice(-1) : '';

        if (box.value && idx < boxes.length - 1) {
          boxes[idx + 1].focus();
          boxes[idx + 1].select();
        }

        // Auto-verify when all 6 digits are entered
        if (boxSelector === '.reg-inline-otp-box') {
          const inlineBoxes = document.querySelectorAll('#regInlineOtpBoxes .reg-inline-otp-box');
          let code = '';
          inlineBoxes.forEach(b => { code += (b.value || '').trim(); });
          if (code.length === 6) {
            verifyOtpFromRegisterForm();
          }
        } else {
          const fullCode = getEnteredOtp();
          if (fullCode.length === 6) {
            verifyEnteredOtp();
          }
        }
      });

      // 2. Keydown: Backspace moves back and clears previous box
      box.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace') {
          if (!box.value && idx > 0) {
            boxes[idx - 1].focus();
            boxes[idx - 1].value = '';
            e.preventDefault();
          }
        } else if (e.key === 'ArrowLeft' && idx > 0) {
          boxes[idx - 1].focus();
          boxes[idx - 1].select();
          e.preventDefault();
        } else if (e.key === 'ArrowRight' && idx < boxes.length - 1) {
          boxes[idx + 1].focus();
          boxes[idx + 1].select();
          e.preventDefault();
        }
      });

      // 3. Paste event: full 6-digit code pasting support
      box.addEventListener('paste', (e) => {
        e.preventDefault();
        const clipboard = (e.clipboardData || window.clipboardData).getData('text') || '';
        const digits = clipboard.replace(/\D/g, '').slice(0, 6);
        if (!digits) return;

        for (let i = 0; i < digits.length && i < boxes.length; i++) {
          boxes[i].value = digits[i];
        }

        const nextFocus = Math.min(digits.length, boxes.length - 1);
        boxes[nextFocus].focus();
        boxes[nextFocus].select();

        if (digits.length === 6) {
          if (boxSelector === '.reg-inline-otp-box') {
            verifyOtpFromRegisterForm();
          } else {
            verifyEnteredOtp();
          }
        }
      });

      // 4. Focus event: auto-select text
      box.addEventListener('focus', () => {
        box.select();
      });
    });
  }

  function getEnteredOtp() {
    // Check inline modal boxes first
    const modalBoxes = document.querySelectorAll('#authModalOtpBoxesContainer .modal-otp-box');
    let modalCode = '';
    modalBoxes.forEach(b => { modalCode += (b.value || '').trim(); });
    if (modalCode.length > 0) return modalCode;

    // Check popup modal boxes
    const popupBoxes = document.querySelectorAll('#fbOtpBoxesContainer .fb-otp-box');
    let popupCode = '';
    popupBoxes.forEach(b => { popupCode += (b.value || '').trim(); });
    return popupCode;
  }

  function clearOtpBoxes() {
    const allBoxes = document.querySelectorAll('.fb-otp-box, .modal-otp-box');
    allBoxes.forEach(b => { b.value = ''; });
    setTimeout(() => {
      const activeFirstBox = document.querySelector('#authModalOtpBoxesContainer .modal-otp-box') 
        || document.querySelector('#fbOtpBoxesContainer .fb-otp-box');
      if (activeFirstBox) {
        activeFirstBox.focus();
        activeFirstBox.select();
      }
    }, 150);
  }

  function clearInlineRegOtpBoxes() {
    const boxes = document.querySelectorAll('#regInlineOtpBoxes .reg-inline-otp-box');
    boxes.forEach(b => { b.value = ''; });
    setTimeout(() => {
      const first = document.querySelector('#regInlineOtpBoxes .reg-inline-otp-box[data-inline-index="0"]');
      if (first) {
        first.focus();
        first.select();
      }
    }, 120);
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

    const timerEls = [
      document.getElementById('fbOtpCountdownTimer'),
      document.getElementById('authModalCountdownTimer'),
      document.getElementById('regInlineCountdownTimer')
    ].filter(Boolean);

    const errEls = [
      document.getElementById('fbOtpError'),
      document.getElementById('authModalOtpError'),
      document.getElementById('regInlineOtpError')
    ].filter(Boolean);

    const verifyBtns = [
      document.getElementById('btnFbVerifyOtp'),
      document.getElementById('btnAuthModalVerifyOtp'),
      document.getElementById('btnVerifyRegInlineOtp')
    ].filter(Boolean);

    function tick() {
      const now = Date.now();
      const remainingMs = otpExpiryTime - now;

      if (remainingMs <= 0) {
        clearInterval(otpCountdownInterval);
        timerEls.forEach(el => {
          el.textContent = 'EXPIRED';
          el.className = 'font-mono font-bold text-rose-400 text-sm';
        });
        errEls.forEach(el => {
          el.textContent = '⏳ OTP expire ho chuka hai (15 minutes limit pass ho gayi). Kripya "Resend OTP" par tap karein.';
          el.classList.remove('hidden');
        });
        verifyBtns.forEach(b => { b.disabled = true; });
      } else {
        const mins = Math.floor(remainingMs / 60000);
        const secs = Math.floor((remainingMs % 60000) / 1000);
        const formatted = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
        timerEls.forEach(el => {
          el.textContent = formatted;
          el.className = mins < 2 ? 'font-mono font-bold text-rose-400 text-sm animate-pulse' : 'font-mono font-extrabold text-amber-300 text-sm';
        });
        verifyBtns.forEach(b => { b.disabled = false; });
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

    const resendBtns = [
      document.getElementById('btnFbResendOtp'),
      document.getElementById('btnAuthModalResendOtp'),
      document.getElementById('btnResendRegInlineOtp')
    ].filter(Boolean);

    const statusEls = [
      document.getElementById('fbOtpResendStatus'),
      document.getElementById('authModalOtpResendStatus'),
      document.getElementById('regInlineResendStatus')
    ].filter(Boolean);

    const secondsEls = [
      document.getElementById('fbOtpResendSeconds'),
      document.getElementById('authModalOtpResendSeconds'),
      document.getElementById('regInlineResendSeconds')
    ].filter(Boolean);

    function tick() {
      if (resendCooldownSeconds > 0) {
        resendBtns.forEach(b => { b.disabled = true; });
        statusEls.forEach(el => el.classList.remove('hidden'));
        secondsEls.forEach(el => { el.textContent = `${resendCooldownSeconds}s`; });
        resendCooldownSeconds--;
      } else {
        clearInterval(resendCooldownInterval);
        resendBtns.forEach(b => { b.disabled = false; });
        statusEls.forEach(el => el.classList.add('hidden'));
      }
    }

    tick();
    resendCooldownInterval = setInterval(tick, 1000);
  }

  /**
   * 12-Hour Account Lockout Countdown Timer
   */
  function start12HourLockoutTimer(totalSeconds) {
    if (otpLockoutInterval) clearInterval(otpLockoutInterval);
    if (loginLockoutInterval) clearInterval(loginLockoutInterval);

    let secondsLeft = Math.max(0, Math.ceil(totalSeconds));

    const errEls = [
      document.getElementById('fbOtpError'),
      document.getElementById('authModalOtpError'),
      document.getElementById('loginError'),
      document.getElementById('regInlineOtpError')
    ].filter(Boolean);

    const verifyBtns = [
      document.getElementById('btnFbVerifyOtp'),
      document.getElementById('btnAuthModalVerifyOtp'),
      document.getElementById('btnVerifyRegInlineOtp'),
      document.getElementById('btnSendRegOtp'),
      document.querySelector('#loginForm button[type="submit"]'),
      document.querySelector('#registerForm button[type="submit"]')
    ].filter(Boolean);

    const inlineBoxes = document.querySelectorAll('#regInlineOtpBoxes .reg-inline-otp-box');

    function tick() {
      if (secondsLeft > 0) {
        const timeDisplay = formatRemainingDuration(secondsLeft);
        const msg = `🔒 Aapka account 12 ghante ke liye lock hai (5 se zyada galat attempts). Kripya ${timeDisplay} baad try karein. (12 ghante baad update hoga)`;
        
        errEls.forEach(el => {
          el.textContent = msg;
          el.classList.remove('hidden');
        });
        verifyBtns.forEach(b => { b.disabled = true; });
        inlineBoxes.forEach(b => { b.disabled = true; });
        secondsLeft--;
      } else {
        clearInterval(otpLockoutInterval);
        clearInterval(loginLockoutInterval);
        errEls.forEach(el => el.classList.add('hidden'));
        verifyBtns.forEach(b => { b.disabled = false; });
        inlineBoxes.forEach(b => { b.disabled = false; });
      }
    }

    tick();
    otpLockoutInterval = setInterval(tick, 1000);
    loginLockoutInterval = otpLockoutInterval;
  }

  // ==========================================
  // INLINE REGISTER FORM OTP LOGIC
  // ==========================================
  async function sendOtpFromRegisterForm() {
    const emailInput = document.getElementById('regEmail');
    const sendBtn = document.getElementById('btnSendRegOtp');
    const sendBtnText = document.getElementById('btnSendRegOtpText');
    const inlineSection = document.getElementById('regInlineOtpSection');
    const targetEmailEl = document.getElementById('regInlineTargetEmail');
    const errEl = document.getElementById('regInlineOtpError');

    const email = emailInput ? emailInput.value.trim().toLowerCase() : '';
    if (!email || !isValidEmail(email)) {
      if (typeof showToast === 'function') {
        showToast('❌ Kripya pehle ek valid Email ID dalein (e.g. name@gmail.com).');
      }
      if (emailInput) emailInput.focus();
      return;
    }

    if (sendBtn) sendBtn.disabled = true;
    if (sendBtnText) sendBtnText.textContent = 'Sending...';
    if (errEl) errEl.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/auth/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (data.locked) {
          start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
        }
        if (typeof showToast === 'function') {
          showToast('⚠️ ' + (data.error || 'OTP send fail ho gaya.'));
        }
        if (errEl) {
          errEl.textContent = data.error || 'OTP send fail ho gaya.';
          errEl.classList.remove('hidden');
        }
        return;
      }

      activeVerificationEmail = email;
      window._activeRegisterEmail = email;

      // Expand inline OTP section
      if (inlineSection) {
        inlineSection.classList.remove('hidden');
      }
      if (targetEmailEl) {
        targetEmailEl.textContent = email;
      }

      // Start 15-min countdown & 60-sec cooldown
      startOtpExpiryCountdown(data.expiresAt);
      startResendCooldown(60);

      // Focus first inline box
      setTimeout(() => {
        const firstBox = document.querySelector('#regInlineOtpBoxes .reg-inline-otp-box[data-inline-index="0"]');
        if (firstBox) {
          firstBox.focus();
          firstBox.select();
        }
      }, 150);

      if (typeof showToast === 'function') {
        showToast('✉️ 6-digit OTP aapki email par bhej diya gaya hai!');
      }

    } catch (err) {
      console.error('sendOtpFromRegisterForm error:', err);
      if (typeof showToast === 'function') {
        showToast('Server connect nahi ho saka. Kripya check karein.');
      }
    } finally {
      if (sendBtn) sendBtn.disabled = false;
      if (sendBtnText) sendBtnText.textContent = 'Resend OTP';
      if (window.lucide && typeof window.lucide.createIcons === 'function') lucide.createIcons();
    }
  }

  async function verifyOtpFromRegisterForm() {
    const inlineSection = document.getElementById('regInlineOtpSection');
    const errEl = document.getElementById('regInlineOtpError');
    const verifyBtn = document.getElementById('btnVerifyRegInlineOtp');
    const verifyBtnText = document.getElementById('btnVerifyRegInlineOtpText');
    const emailInput = document.getElementById('regEmail');
    const emailStatusBadge = document.getElementById('regEmailStatusBadge');
    const helperText = document.getElementById('regEmailHelperText');
    const sendBtn = document.getElementById('btnSendRegOtp');

    const email = (emailInput ? emailInput.value.trim().toLowerCase() : '') || activeVerificationEmail;

    // Get 6 digits from inline boxes
    const boxes = document.querySelectorAll('#regInlineOtpBoxes .reg-inline-otp-box');
    let otp = '';
    boxes.forEach(b => { otp += (b.value || '').trim(); });

    if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
      if (errEl) {
        errEl.textContent = '❌ Kripya pura 6-digit OTP dalein.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (!email) {
      if (errEl) {
        errEl.textContent = '❌ Kripya pehle apni email ID enter karein.';
        errEl.classList.remove('hidden');
      }
      return;
    }

    if (verifyBtn) verifyBtn.disabled = true;
    if (verifyBtnText) verifyBtnText.textContent = 'Verifying...';
    if (errEl) errEl.classList.add('hidden');

    try {
      const response = await fetch(`${API_BASE}/api/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, otp: otp })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (data.locked) {
          start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
          clearInlineRegOtpBoxes();
          return;
        }

        if (errEl) {
          errEl.textContent = data.error || 'Galat OTP! Kripya dobara check karein.';
          errEl.classList.remove('hidden');
        }
        clearInlineRegOtpBoxes();
        return;
      }

      // --- INLINE OTP VERIFICATION SUCCESSFUL ---
      window._isRegisterEmailVerified = true;
      window._verifiedRegisterEmail = email;

      // Lock email input and show Verified badge
      if (emailInput) {
        emailInput.readOnly = true;
        emailInput.classList.add('border-emerald-500/50', 'text-emerald-300');
      }
      if (emailStatusBadge) {
        emailStatusBadge.classList.remove('hidden');
        emailStatusBadge.classList.add('inline-flex');
      }
      if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.innerHTML = `<span>✓ Done</span>`;
        sendBtn.className = 'absolute right-1.5 top-1.5 px-2.5 py-1.5 bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 text-[10px] font-bold rounded-lg flex items-center gap-1 cursor-default';
      }
      if (helperText) {
        helperText.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Email (${email}) verify ho gaya! Ab VIP Account create karein.</span>`;
      }

      // Collapse inline OTP section
      if (inlineSection) {
        inlineSection.innerHTML = `
          <div class="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-2">
            <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400"></i>
            <span>✓ Email Verified! Aapka OTP sahi hai. Ab VIP Account button dabayein.</span>
          </div>
        `;
      }

      if (typeof showToast === 'function') {
        showToast('🎉 Email successfully verify ho gaya!');
      }

      // If user had existing account and received custom token, log them in directly
      if (data.customToken && window.firebaseAuth) {
        try {
          await window.firebaseAuth.signInWithCustomToken(data.customToken);
          const userProfile = {
            id: data.uid || 'USR-' + Math.floor(100000 + Math.random() * 900000),
            uid: data.uid,
            email: email,
            name: email.split('@')[0],
            emailVerified: true,
            phoneVerified: true,
            joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
          };
          localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));
          if (typeof closeAuthModal === 'function') closeAuthModal(true);
          if (typeof updateNavUserProfile === 'function') updateNavUserProfile(userProfile);
          setTimeout(() => {
            if (typeof window.openUserAddressModal === 'function' && !userProfile.addressCompleted && !userProfile.address) {
              window.openUserAddressModal(userProfile);
            }
          }, 450);
        } catch (e) {
          console.warn('Sign in with custom token notice:', e);
        }
      } else {
        // Focus password input so user can effortlessly finish signup
        const passInput = document.getElementById('regPassword');
        if (passInput) passInput.focus();
      }

    } catch (err) {
      console.error('verifyOtpFromRegisterForm error:', err);
      if (errEl) {
        errEl.textContent = 'Server se connect nahi ho saka. Kripya check karein.';
        errEl.classList.remove('hidden');
      }
    } finally {
      if (verifyBtn) verifyBtn.disabled = false;
      if (verifyBtnText) verifyBtnText.textContent = 'Verify OTP & Unlock Email';
      if (window.lucide && typeof window.lucide.createIcons === 'function') lucide.createIcons();
    }
  }

  function resendOtpFromRegisterForm() {
    sendOtpFromRegisterForm();
  }

  // ==========================================
  // SIGNUP FLOW (Talks to Node.js /api/auth/signup)
  // ==========================================
  async function handleSignUp({ name, email, phone, password }) {
    ensureModals();

    if (!name || name.trim().length < 2) {
      throw new Error('Kripya apna pura naam (Full Name) dalein.');
    }
    if (!isValidEmail(email)) {
      throw new Error('Kripya ek valid email address enter karein (e.g. name@gmail.com).');
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
          phone: cleanPhone,
          whatsapp: cleanPhone, // Automatically same as mobile number
          mobileWhatsAppSame: true
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (data.locked) {
          start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
        }
        throw new Error(data.error || 'Signup fail ho gaya. Kripya dobara try karein.');
      }

      // If pre-verified, server returns customToken directly!
      if (data.verified && data.customToken) {
        if (window.firebaseAuth) {
          try {
            await window.firebaseAuth.signInWithCustomToken(data.customToken);
          } catch (tErr) {
            console.warn('Custom token error:', tErr);
          }
        }

        const userProfile = {
          id: data.uid || 'USR-' + Math.floor(100000 + Math.random() * 900000),
          uid: data.uid,
          email: normEmail,
          name: name.trim(),
          phone: cleanPhone ? `+91${cleanPhone}` : '',
          whatsapp: cleanPhone ? `+91${cleanPhone}` : '',
          mobileWhatsAppSame: true,
          emailVerified: true,
          phoneVerified: true,
          joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
        };
        localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));

        if (typeof closeAuthModal === 'function') closeAuthModal(true);
        if (typeof updateNavUserProfile === 'function') updateNavUserProfile(userProfile);
        if (typeof showToast === 'function') {
          showToast('🎉 Welcome to VICEVAULT! VIP Account create ho gaya.');
        }
        setTimeout(() => {
          if (typeof window.openUserAddressModal === 'function' && !userProfile.addressCompleted && !userProfile.address) {
            window.openUserAddressModal(userProfile);
          }
        }, 450);
        return { success: true, verified: true };
      }

      activeVerificationEmail = normEmail;
      activeVerificationUid = data.uid || '';

      // Open OTP Entry Slot
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
    const errEls = [
      document.getElementById('fbOtpError'),
      document.getElementById('authModalOtpError')
    ].filter(Boolean);

    const verifyBtns = [
      document.getElementById('btnFbVerifyOtp'),
      document.getElementById('btnAuthModalVerifyOtp')
    ].filter(Boolean);

    const btnTexts = [
      document.getElementById('btnFbVerifyOtpText'),
      document.getElementById('btnAuthModalVerifyOtpText')
    ].filter(Boolean);

    const otp = getEnteredOtp();

    if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
      errEls.forEach(el => {
        el.textContent = '❌ Kripya pura 6-digit number OTP dalein.';
        el.classList.remove('hidden');
      });
      return;
    }

    if (!activeVerificationEmail) {
      errEls.forEach(el => {
        el.textContent = '❌ Session expire ho gayi. Kripya pehle Sign Up ya Login karein.';
        el.classList.remove('hidden');
      });
      return;
    }

    // Loading State
    verifyBtns.forEach(b => { b.disabled = true; });
    btnTexts.forEach(t => { t.textContent = 'Verifying with Server...'; });
    errEls.forEach(el => el.classList.add('hidden'));

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
        // 1. Account Locked for 12 Hours!
        if (data.locked) {
          start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
          clearOtpBoxes();
          return;
        }

        errEls.forEach(el => {
          el.textContent = data.error || 'Galat OTP! Kripya dobara check karein.';
          el.classList.remove('hidden');
        });

        if (data.expired || data.maxAttemptsExceeded) {
          verifyBtns.forEach(b => { b.disabled = true; });
        }
        clearOtpBoxes();
        return;
      }

      // --- OTP VERIFICATION SUCCESSFUL ---
      clearInterval(otpCountdownInterval);
      clearInterval(resendCooldownInterval);
      if (otpLockoutInterval) clearInterval(otpLockoutInterval);

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
      const rawStored = localStorage.getItem('vicevault_current_user');
      let existingProfile = {};
      try { existingProfile = rawStored ? JSON.parse(rawStored) : {}; } catch (e) {}

      const userProfile = {
        id: data.uid || activeVerificationUid || existingProfile.id || 'USR-' + Math.floor(100000 + Math.random() * 900000),
        uid: data.uid || activeVerificationUid || existingProfile.uid,
        email: activeVerificationEmail,
        name: existingProfile.name || activeVerificationEmail.split('@')[0],
        phone: existingProfile.phone || '',
        whatsapp: existingProfile.whatsapp || existingProfile.phone || '',
        mobileWhatsAppSame: true,
        emailVerified: true,
        phoneVerified: true,
        joinedDate: existingProfile.joinedDate || new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
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
        showToast('🎉 Email verify ho gaya! Account fully unlocked.');
      }
      setTimeout(() => {
        if (typeof window.openUserAddressModal === 'function' && !userProfile.addressCompleted && !userProfile.address) {
          window.openUserAddressModal(userProfile);
        }
      }, 450);

    } catch (err) {
      console.error('Verify OTP error:', err);
      errEls.forEach(el => {
        el.textContent = 'Server se connect nahi ho saka. Kripya connection check karein.';
        el.classList.remove('hidden');
      });
    } finally {
      verifyBtns.forEach(b => { b.disabled = false; });
      btnTexts.forEach(t => { t.textContent = 'Verify & Unlock Account'; });
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

    const resendBtns = [
      document.getElementById('btnFbResendOtp'),
      document.getElementById('btnAuthModalResendOtp')
    ].filter(Boolean);

    resendBtns.forEach(b => { b.disabled = true; });

    try {
      const response = await fetch(`${API_BASE}/api/auth/resend-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: activeVerificationEmail })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        if (data.locked) {
          start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
          return;
        }

        if (typeof showToast === 'function') showToast('⚠️ ' + (data.error || 'Resend fail ho gaya.'));
        if (data.cooldown && data.waitSeconds) {
          startResendCooldown(data.waitSeconds);
        }
        return;
      }

      startOtpExpiryCountdown(data.expiresAt);
      startResendCooldown(60);

      const errEls = [
        document.getElementById('fbOtpError'),
        document.getElementById('authModalOtpError')
      ].filter(Boolean);
      errEls.forEach(el => el.classList.add('hidden'));
      clearOtpBoxes();

      if (typeof showToast === 'function') {
        showToast('✉️ Naya 6-digit OTP bhej diya gaya hai (Valid for 15 mins).');
      }

    } catch (err) {
      console.error('Resend OTP error:', err);
      if (typeof showToast === 'function') showToast('Server error while resending OTP.');
    }
  }

  // ==========================================
  // LOGIN FLOW (Enforces 12-Hour Lockout on 5 Failures)
  // ==========================================
  async function handleLogin({ identifier, password }) {
    ensureModals();

    if (!identifier || !password) {
      throw new Error('Email aur password dono zaroori hain.');
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
      // 1. Account Locked for 12 Hours!
      if (data.locked) {
        start12HourLockoutTimer(data.remainingWaitSeconds || (12 * 3600));
        throw new Error(data.error || 'Aapki login limit poori ho gayi hai. Account 12 ghante ke liye lock hai.');
      }

      // 2. Unverified User: Block login and redirect to OTP slot!
      if (data.unverified) {
        activeVerificationEmail = normEmail;
        activeVerificationUid = data.uid || '';
        openOtpModal(normEmail, data.expiresAt);
        startResendCooldown(60);
        throw new Error('Aapka email verify nahi hai. Email par bheja gaya 6-digit OTP dalein.');
      }

      throw new Error(data.error || 'Galat email ya password.');
    }

    // --- REQUIRE OTP ON EVERY LOGIN (If enabled by admin) ---
    if (data.requiresOtp) {
      activeVerificationEmail = normEmail;
      activeVerificationUid = data.uid || '';
      openOtpModal(normEmail, data.expiresAt);
      startResendCooldown(60);
      return { success: true, pendingOtp: true };
    }

    // --- LOGIN SUCCESS ---
    if (loginLockoutInterval) clearInterval(loginLockoutInterval);
    if (otpLockoutInterval) clearInterval(otpLockoutInterval);

    if (data.customToken && window.firebaseAuth) {
      try {
        await window.firebaseAuth.signInWithCustomToken(data.customToken);
      } catch (tokenErr) {
        console.warn('Sign in with custom token warning:', tokenErr);
      }
    }

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
  // MODAL CONTROLLERS & OTP SLOT ACTIVATION
  // ==========================================
  function openOtpModal(email, expiresAt) {
    ensureModals();
    activeVerificationEmail = email;

    // Check if inline auth modal exists on the page
    const authModal = document.getElementById('authModal');
    const authOtpSection = document.getElementById('authOtpSection');

    if (authModal && authOtpSection) {
      // Open and switch auth modal directly to OTP slot
      if (typeof openAuthModal === 'function') {
        openAuthModal('otp');
      } else if (typeof switchAuthMode === 'function') {
        authModal.classList.remove('hidden', 'opacity-0', 'pointer-events-none', 'invisible');
        switchAuthMode('otp');
      }

      const targetEl = document.getElementById('authModalTargetEmail');
      if (targetEl) targetEl.textContent = email;
      const errEl = document.getElementById('authModalOtpError');
      if (errEl) errEl.classList.add('hidden');
    } else {
      // Fallback to popup modal
      const modal = document.getElementById('firebaseOtpModal');
      const target = document.getElementById('fbOtpTargetEmail');
      const err = document.getElementById('fbOtpError');

      if (target) target.textContent = email;
      if (err) err.classList.add('hidden');
      if (modal) modal.classList.remove('hidden');
    }

    clearOtpBoxes();
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
        showToast('🔒 Protected action: Kripya pehle sign in ya account banayein.');
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

  // Global window helpers for inline register form
  window.sendOtpFromRegisterForm = sendOtpFromRegisterForm;
  window.verifyOtpFromRegisterForm = verifyOtpFromRegisterForm;
  window.resendOtpFromRegisterForm = resendOtpFromRegisterForm;
  window.__AUTH_API_BASE__ = API_BASE;

  // Export public service API
  window.firebaseAuthService = {
    apiBase: API_BASE,
    handleSignUp,
    handleLogin,
    signOut,
    verifyEnteredOtp,
    resendOtp,
    sendOtpFromRegisterForm,
    verifyOtpFromRegisterForm,
    resendOtpFromRegisterForm,
    openOtpModal,
    closeOtpModal,
    isUserFullyVerified,
    requireFullyVerifiedUser,
    cleanIndianPhone,
    isValidIndianPhone,
    isValidEmail,
    setupOtpInputHandlers
  };

})();
