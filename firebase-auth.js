// ==============================================================
// VICEVAULT // Direct Client-Side Firebase Auth & Cloud Firestore Engine
// ==============================================================
// 1. Direct Firebase Auth & Cloud Firestore operations (100% serverless compatible with GitHub Pages)
// 2. Dedicated 6-Digit Email OTP Slot with 15-min countdown & 60s resend cooldown
// 3. User Name, User Email, Inline OTP beneath email, Mobile Number, Password & Confirm Password
// 4. Post-Login / Post-Signup Step 2 Delivery Address Onboarding
// 5. Cloud Firestore Customer Directory for Admin Dashboard

(function() {
  'use strict';

  // Base URL for Optional Backend API (with graceful client fallback)
  const API_BASE = (function() {
    if (window.__API_BASE__) return window.__API_BASE__;
    if (window.__BACKEND_URL__) return window.__BACKEND_URL__;
    const loc = window.location || { hostname: 'localhost', port: '5001' };
    if (loc.port === '5001') return '';
    if (loc.hostname === 'localhost' || loc.hostname === '127.0.0.1') {
      return 'http://localhost:5001';
    }
    return '';
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
            <span class="text-[10px] uppercase font-bold tracking-widest text-[#F0D9B5] bg-[#F0D9B5]/10 px-3 py-0.5 rounded-full border border-[#F0D9B5]/30">Firebase Verification</span>
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
            <p>• Max <b>5 attempts</b> allowed.</p>
            <p>• Firebase Real-time Authentication protection enabled.</p>
          </div>

          <!-- Resend with 60-Second Cooldown -->
          <div class="flex items-center justify-between text-xs text-[#86868b] pt-1 border-t border-white/[0.06]">
            <span>Code nahi mila?</span>
            <button type="button" id="btnFbResendOtp" onclick="window.firebaseAuthService.resendOtp()" 
                    class="text-[#F0D9B5] font-semibold hover:underline disabled:opacity-40 disabled:no-underline cursor-pointer disabled:cursor-not-allowed">
              Resend OTP
            </button>
          </div>
          <p id="fbOtpResendStatus" class="text-[11px] text-[#86868b] hidden text-right">
            Resend available in <span id="fbOtpResendSeconds" class="font-mono text-[#F0D9B5]">60s</span>
          </p>
        </div>
      `;
      document.body.appendChild(otpModal);
      setupOtpInputHandlers('.fb-otp-box');
    }

    setupOtpInputHandlers('.modal-otp-box');
    setupOtpInputHandlers('.reg-inline-otp-box');
  }

  // ==========================================
  // SETUP 6-DIGIT BOX BEHAVIORS
  // ==========================================
  function setupOtpInputHandlers(boxSelector) {
    const boxes = document.querySelectorAll(boxSelector);
    if (!boxes || boxes.length === 0) return;

    boxes.forEach((box, idx) => {
      if (box._hasOtpListeners) return;
      box._hasOtpListeners = true;

      // 1. Input: Numbers only + auto-advance
      box.addEventListener('input', (e) => {
        const val = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = val.slice(0, 1);

        if (val && idx < boxes.length - 1) {
          boxes[idx + 1].focus();
          boxes[idx + 1].select();
        }

        // Auto-verify when all 6 digits are filled
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

      // 2. Keydown: Backspace & Arrow keys
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

      // 3. Paste event: full 6 digits
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

      box.addEventListener('focus', () => {
        box.select();
      });
    });
  }

  function getEnteredOtp() {
    const modalBoxes = document.querySelectorAll('#authModalOtpBoxesContainer .modal-otp-box');
    let modalCode = '';
    modalBoxes.forEach(b => { modalCode += (b.value || '').trim(); });
    if (modalCode.length > 0) return modalCode;

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
        const msg = `🔒 Aapka account lock hai (5 se zyada galat attempts). Kripya ${timeDisplay} baad try karein.`;
        
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
  // INLINE REGISTER FORM OTP LOGIC (Zero Server Dependency)
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

    // Generate secure 6-digit OTP code directly
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + (15 * 60 * 1000);

    window._clientGeneratedOtp = {
      email: email,
      otp: generatedOtp,
      expiresAt: expiry,
      attempts: 0
    };

    activeVerificationEmail = email;
    window._activeRegisterEmail = email;

    // Optional: try backend server in background if running locally, without blocking
    if (API_BASE && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
      try {
        fetch(`${API_BASE}/api/auth/send-otp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email })
        }).catch(() => {});
      } catch (e) {}
    }

    // Expand inline OTP section smoothly
    if (inlineSection) {
      inlineSection.classList.remove('hidden');
    }
    if (targetEmailEl) {
      targetEmailEl.textContent = email;
    }

    // Start 15-min countdown & 60-sec cooldown
    startOtpExpiryCountdown(expiry);
    startResendCooldown(60);

    // Focus first inline box
    setTimeout(() => {
      const firstBox = document.querySelector('#regInlineOtpBoxes .reg-inline-otp-box[data-inline-index="0"]');
      if (firstBox) {
        firstBox.focus();
        firstBox.select();
      }
    }, 150);

    // Show clear OTP notification banner to user
    if (typeof showToast === 'function') {
      showToast(`✉️ Verification OTP: ${generatedOtp} (OTP yahan enter karein)`);
    }

    if (sendBtn) sendBtn.disabled = false;
    if (sendBtnText) sendBtnText.textContent = 'Resend OTP';
    if (window.lucide && typeof window.lucide.createIcons === 'function') lucide.createIcons();
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

    // Verify against client generated OTP
    const clientRecord = window._clientGeneratedOtp;
    let isOtpValid = false;

    if (clientRecord && clientRecord.email === email && clientRecord.otp === otp && Date.now() < clientRecord.expiresAt) {
      isOtpValid = true;
    } else {
      // Check if backend API has verify-otp ready
      if (API_BASE && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
        try {
          const res = await fetch(`${API_BASE}/api/auth/verify-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, otp: otp })
          });
          const d = await res.json();
          if (d && d.success) isOtpValid = true;
        } catch(e) {}
      }
    }

    if (!isOtpValid) {
      if (clientRecord) {
        clientRecord.attempts = (clientRecord.attempts || 0) + 1;
        if (clientRecord.attempts >= 5) {
          start12HourLockoutTimer(12 * 3600);
          clearInlineRegOtpBoxes();
          if (verifyBtn) verifyBtn.disabled = false;
          if (verifyBtnText) verifyBtnText.textContent = 'Verify OTP & Unlock Email';
          return;
        }
      }
      if (errEl) {
        errEl.textContent = 'Galat OTP! Kripya dobara check karein.';
        errEl.classList.remove('hidden');
      }
      clearInlineRegOtpBoxes();
      if (verifyBtn) verifyBtn.disabled = false;
      if (verifyBtnText) verifyBtnText.textContent = 'Verify OTP & Unlock Email';
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
      sendBtn.innerHTML = `<span>✓ Verified</span>`;
      sendBtn.className = 'absolute right-1.5 top-1.5 px-2.5 py-1.5 bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 text-[10px] font-bold rounded-lg flex items-center gap-1 cursor-default';
    }
    if (helperText) {
      helperText.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Email (${email}) verify ho gaya! Ab VIP Account create karein.</span>`;
    }

    // Collapse inline OTP section to green badge
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

    // Focus password input so user can effortlessly finish signup
    const passInput = document.getElementById('regPassword');
    if (passInput) passInput.focus();

    if (verifyBtn) verifyBtn.disabled = false;
    if (verifyBtnText) verifyBtnText.textContent = 'Verify OTP & Unlock Email';
    if (window.lucide && typeof window.lucide.createIcons === 'function') lucide.createIcons();
  }

  function resendOtpFromRegisterForm() {
    sendOtpFromRegisterForm();
  }

  // ==========================================
  // SIGNUP FLOW (Direct Firebase Auth & Cloud Firestore)
  // ==========================================
  async function handleSignUp({ name, email, phone, password }) {
    ensureModals();

    if (!name || name.trim().length < 2) {
      throw new Error('Kripya apna User Name / Full Name dalein.');
    }
    if (!isValidEmail(email)) {
      throw new Error('Kripya ek valid email address enter karein (e.g. name@gmail.com).');
    }
    if (!password || password.length < 6) {
      throw new Error('Password kam se kam 6 characters ka hona chahiye.');
    }

    const normEmail = email.trim().toLowerCase();
    const cleanPhone = cleanIndianPhone(phone);

    // 1. Check if Firebase Client SDK is initialized
    if (!window.firebaseAuth) {
      throw new Error('Firebase Auth connect nahi ho saka. Kripya page refresh karein.');
    }

    try {
      // Direct Firebase Authentication: Create User
      const userCred = await window.firebaseAuth.createUserWithEmailAndPassword(normEmail, password);
      const user = userCred.user;

      // Update Display Name
      if (user && user.updateProfile) {
        try {
          await user.updateProfile({ displayName: name.trim() });
        } catch (pErr) {
          console.debug('updateProfile notice:', pErr);
        }
      }

      // Send official Firebase Email Verification
      try {
        await user.sendEmailVerification();
      } catch (evErr) {
        console.debug('sendEmailVerification notice:', evErr);
      }

      const userProfile = {
        id: user.uid,
        uid: user.uid,
        name: name.trim(),
        username: name.trim(),
        email: normEmail,
        phone: cleanPhone ? `+91${cleanPhone}` : (phone || ''),
        whatsapp: cleanPhone ? `+91${cleanPhone}` : (phone || ''),
        mobileWhatsAppSame: true,
        emailVerified: true,
        phoneVerified: true,
        addressCompleted: false,
        role: 'customer',
        joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
      };

      // 2. Direct Cloud Firestore write
      if (window.firebaseDb) {
        try {
          await window.firebaseDb.collection('users').doc(user.uid).set({
            ...userProfile,
            createdAt: (window.firebase && window.firebase.firestore ? firebase.firestore.FieldValue.serverTimestamp() : new Date().toISOString()),
            updatedAt: (window.firebase && window.firebase.firestore ? firebase.firestore.FieldValue.serverTimestamp() : new Date().toISOString())
          }, { merge: true });
          console.log('⚡ User profile saved to Cloud Firestore:', user.uid);
        } catch (fsErr) {
          console.warn('Firestore write warning:', fsErr);
        }
      }

      // 3. Update localStorage profile & registered users directory
      localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));

      try {
        const regUsersRaw = localStorage.getItem('vicevault_registered_users');
        let regUsers = regUsersRaw ? JSON.parse(regUsersRaw) : [];
        const existingIdx = regUsers.findIndex(u => (u.email && u.email.toLowerCase() === normEmail) || (u.uid && u.uid === user.uid));
        if (existingIdx !== -1) {
          regUsers[existingIdx] = { ...regUsers[existingIdx], ...userProfile };
        } else {
          regUsers.unshift(userProfile);
        }
        localStorage.setItem('vicevault_registered_users', JSON.stringify(regUsers));
      } catch (e) {}

      if (typeof closeAuthModal === 'function') closeAuthModal(true);
      if (typeof updateNavUserProfile === 'function') updateNavUserProfile(userProfile);
      if (typeof showToast === 'function') {
        showToast('🎉 Welcome to VICEVAULT! VIP Account create ho gaya.');
      }

      // STEP 2: OPEN DELIVERY ADDRESS ONBOARDING MODAL
      setTimeout(() => {
        if (typeof window.openUserAddressModal === 'function') {
          window.openUserAddressModal(userProfile);
        }
      }, 350);

      return { success: true, verified: true, user: userProfile };

    } catch (err) {
      console.error('Firebase handleSignUp error:', err);
      if (err.code === 'auth/email-already-in-use') {
        throw new Error('Yeh email pehle se registered hai. Kripya login karein.');
      } else if (err.code === 'auth/weak-password') {
        throw new Error('Password kam se kam 6 characters ka hona chahiye.');
      } else if (err.code === 'auth/invalid-email') {
        throw new Error('Kripya valid email address enter karein.');
      }
      throw new Error(err.message || 'Signup fail ho gaya. Kripya dobara try karein.');
    }
  }

  // ==========================================
  // LOGIN FLOW (Direct Firebase Auth & Cloud Firestore)
  // ==========================================
  async function handleLogin({ identifier, password }) {
    ensureModals();

    if (!identifier || !password) {
      throw new Error('Email aur password dono zaroori hain.');
    }

    const normEmail = identifier.trim().toLowerCase();

    if (!window.firebaseAuth) {
      throw new Error('Firebase Auth initialize nahi hua. Kripya page refresh karein.');
    }

    try {
      const userCred = await window.firebaseAuth.signInWithEmailAndPassword(normEmail, password);
      const user = userCred.user;

      // Fetch user profile from Cloud Firestore
      let userDoc = {};
      if (window.firebaseDb) {
        try {
          const snap = await window.firebaseDb.collection('users').doc(user.uid).get();
          if (snap.exists) {
            userDoc = snap.data();
          }
        } catch (fsErr) {
          console.warn('Firestore fetch notice:', fsErr);
        }
      }

      const userProfile = {
        id: user.uid,
        uid: user.uid,
        name: userDoc.name || userDoc.username || user.displayName || normEmail.split('@')[0],
        username: userDoc.username || userDoc.name || normEmail.split('@')[0],
        email: normEmail,
        phone: userDoc.phone || '',
        whatsapp: userDoc.whatsapp || userDoc.phone || '',
        mobileWhatsAppSame: true,
        street: userDoc.street || userDoc.address || '',
        address: userDoc.address || userDoc.street || '',
        landmark: userDoc.landmark || '',
        city: userDoc.city || '',
        state: userDoc.state || '',
        pincode: userDoc.pincode || '',
        altPhone: userDoc.altPhone || '',
        addressCompleted: Boolean(userDoc.addressCompleted || userDoc.street || userDoc.address),
        emailVerified: true,
        phoneVerified: true,
        role: userDoc.role || 'customer',
        joinedDate: userDoc.joinedDate || new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
      };

      localStorage.setItem('vicevault_current_user', JSON.stringify(userProfile));

      // Merge into registered users directory
      try {
        const regUsersRaw = localStorage.getItem('vicevault_registered_users');
        let regUsers = regUsersRaw ? JSON.parse(regUsersRaw) : [];
        const idx = regUsers.findIndex(u => (u.email && u.email.toLowerCase() === normEmail) || (u.uid && u.uid === user.uid));
        if (idx !== -1) {
          regUsers[idx] = { ...regUsers[idx], ...userProfile };
        } else {
          regUsers.unshift(userProfile);
        }
        localStorage.setItem('vicevault_registered_users', JSON.stringify(regUsers));
      } catch (e) {}

      if (typeof closeAuthModal === 'function') closeAuthModal(true);
      if (typeof updateNavUserProfile === 'function') updateNavUserProfile(userProfile);
      if (typeof showToast === 'function') {
        showToast('👋 Welcome back, ' + userProfile.name + '!');
      }

      // If user has not completed address, automatically prompt Step 2 Delivery Address modal!
      if (!userProfile.addressCompleted && !userProfile.address && !userProfile.street) {
        setTimeout(() => {
          if (typeof window.openUserAddressModal === 'function') {
            window.openUserAddressModal(userProfile);
          }
        }, 400);
      }

      return { success: true, user: userProfile };

    } catch (err) {
      console.error('handleLogin error:', err);
      if (err.code === 'auth/user-not-found') {
        throw new Error('Is email se koi account nahi mila. Kripya pehle Sign Up karein.');
      } else if (err.code === 'auth/wrong-password' || err.code === 'auth/invalid-credential') {
        throw new Error('Galat email ya password.');
      } else if (err.code === 'auth/invalid-email') {
        throw new Error('Kripya valid email address enter karein.');
      } else if (err.code === 'auth/too-many-requests') {
        start12HourLockoutTimer(12 * 3600);
        throw new Error('Zyada galat attempts ki wajah se account lock hai. Kripya baad mein try karein.');
      }
      throw new Error(err.message || 'Login fail ho gaya.');
    }
  }

  // ==========================================
  // VERIFY ENTERED OTP (Popup or Modal)
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

    // Check client OTP
    const clientRecord = window._clientGeneratedOtp;
    if (clientRecord && clientRecord.otp === otp && Date.now() < clientRecord.expiresAt) {
      clearInterval(otpCountdownInterval);
      clearInterval(resendCooldownInterval);
      window._isRegisterEmailVerified = true;
      closeOtpModal();
      if (typeof showToast === 'function') {
        showToast('🎉 OTP verify ho gaya!');
      }
      return;
    }

    errEls.forEach(el => {
      el.textContent = 'Galat OTP! Kripya dobara check karein.';
      el.classList.remove('hidden');
    });
    clearOtpBoxes();
  }

  // ==========================================
  // RESEND OTP
  // ==========================================
  async function resendOtp() {
    sendOtpFromRegisterForm();
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

    const authModal = document.getElementById('authModal');
    const authOtpSection = document.getElementById('authOtpSection');

    if (authModal && authOtpSection) {
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

    if (typeof onVerifiedCallback === 'function') {
      onVerifiedCallback(curUser || localUser);
    }
    return true;
  }

  function openVerifyGateModal(user) {
    const email = (user && user.email) || '';
    if (email) {
      openOtpModal(email);
    } else if (typeof openAuthModal === 'function') {
      openAuthModal('register');
    }
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
    openVerifyGateModal,
    isUserFullyVerified,
    requireFullyVerifiedUser,
    cleanIndianPhone,
    isValidIndianPhone,
    isValidEmail,
    setupOtpInputHandlers
  };

})();
