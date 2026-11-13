// ==============================================================
// VICEVAULT // Firebase Authentication & Firestore Sync Module
// ==============================================================
// Handles:
// - Sign-up with Name, Email, Indian Phone (+91)
// - Firebase Phone Auth SMS OTP + reCAPTCHA verification
// - Firebase Email Link Verification
// - Account linking (Phone + Email linked to single Firebase UID)
// - Firestore User Profile sync (users/{uid})
// - Protected pages/actions enforcement (blocks unverified access)
// - Comprehensive error translation & cooldown timers

(function() {
  'use strict';

  // State
  let recaptchaVerifier = null;
  let phoneVerificationId = null;
  let phoneConfirmationResult = null;
  let pendingRegistrationData = null; // { name, email, phone, password }
  let emailResendCooldown = 0;
  let emailResendInterval = null;
  let smsResendCooldown = 0;
  let smsResendInterval = null;

  // Error code translations (Hinglish / User-friendly)
  const ERROR_MESSAGES = {
    'auth/invalid-verification-code': '❌ Galat OTP! Kripya SMS mein aaya sahi 6-digit code dalein.',
    'auth/code-expired': '⏳ OTP expire ho gaya hai. Kripya "Resend SMS" par click karke naya code mangwayein.',
    'auth/invalid-phone-number': '❌ Galat mobile number! Kripya valid 10-digit Indian (+91) number dalein.',
    'auth/missing-phone-number': '❌ Mobile number daalna zaroori hai.',
    'auth/quota-exceeded': '⚠️ SMS quota exceed ho gaya hai. Kripya kuch samay baad koshish karein ya support se contact karein.',
    'auth/captcha-check-failed': '⚠️ reCAPTCHA verification fail ho gaya. Kripya page refresh karein.',
    'auth/email-already-in-use': '⚠️ Ye Email ID pehle se registered hai. Kripya login karein ya doosra email use karein.',
    'auth/credential-already-in-use': '⚠️ Ye Mobile number pehle se doosre account se linked hai.',
    'auth/provider-already-linked': '⚠️ Ye phone number pehle se aapke account se linked hai.',
    'auth/invalid-email': '❌ Galat Email format! Kripya valid email dalein (e.g. name@gmail.com).',
    'auth/weak-password': '❌ Kamzor Password! Password kam se kam 6 characters ka hona chahiye.',
    'auth/user-not-found': '❌ Is Email ya Mobile ke sath koi account nahi mila. Kripya pehle Sign Up karein.',
    'auth/wrong-password': '❌ Galat password! Kripya sahi password enter karein.',
    'auth/invalid-credential': '❌ Galat credentials! Kripya email/phone aur password check karein.',
    'auth/network-request-failed': '🌐 Network error! Kripya apna internet connection check karein.',
    'auth/too-many-requests': '⚠️ Bahut saari requests bheji gayi hain. Kripya thodi der intezar karein.',
    'auth/requires-recent-login': '⚠️ Security ke liye kripya dobara login karein.',
    'auth/user-disabled': '❌ Aapka account disable kar diya gaya hai. Kripya support se contact karein.'
  };

  function translateError(err) {
    if (!err) return 'An unknown error occurred.';
    if (err.code && ERROR_MESSAGES[err.code]) {
      return ERROR_MESSAGES[err.code];
    }
    return err.message || 'Operation failed. Kripya dobara koshish karein.';
  }

  // Helper: validate Indian 10-digit mobile number
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

  function isValidEmail(email) {
    if (!email) return false;
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email.trim());
  }

  // ==========================================
  // RECAPTCHA INITIALIZATION
  // ==========================================
  function ensureRecaptchaVerifier(containerId = 'recaptcha-container') {
    if (!window.isFirebaseConfigured || !window.isFirebaseConfigured()) {
      return null;
    }
    if (recaptchaVerifier) return recaptchaVerifier;

    let container = document.getElementById(containerId);
    if (!container) {
      container = document.createElement('div');
      container.id = containerId;
      document.body.appendChild(container);
    }

    try {
      recaptchaVerifier = new firebase.auth.RecaptchaVerifier(containerId, {
        size: 'invisible',
        callback: function(response) {
          // reCAPTCHA solved
        },
        'expired-callback': function() {
          if (recaptchaVerifier) {
            recaptchaVerifier.render().then(widgetId => grecaptcha.reset(widgetId));
          }
        }
      });
      return recaptchaVerifier;
    } catch (e) {
      console.error('Failed to init RecaptchaVerifier:', e);
      return null;
    }
  }

  // ==========================================
  // VERIFICATION CHECK
  // ==========================================
  /**
   * Checks if a user has both phone number linked AND email verified.
   */
  function isUserFullyVerified(user) {
    if (!user) return false;
    const hasEmailVerified = Boolean(user.emailVerified);
    const hasPhone = Boolean(
      user.phoneNumber || 
      (user.providerData && user.providerData.some(p => p.providerId === 'phone'))
    );
    return hasEmailVerified && hasPhone;
  }

  // ==========================================
  // FIRESTORE PROFILE SAVE / SYNC
  // ==========================================
  async function syncUserProfileToFirestore(user, extraData = {}) {
    if (!window.firebaseDb || !user) return null;
    try {
      const userRef = window.firebaseDb.collection('users').doc(user.uid);
      const phone = user.phoneNumber || extraData.phone || '';
      const email = user.email || extraData.email || '';
      const name = extraData.name || user.displayName || 'VIP Member';

      const payload = {
        uid: user.uid,
        name: name,
        email: email,
        phone: phone,
        emailVerified: Boolean(user.emailVerified),
        phoneVerified: Boolean(phone),
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      };

      if (extraData.city) payload.city = extraData.city;
      if (extraData.address) payload.address = extraData.address;
      if (extraData.pincode) payload.pincode = extraData.pincode;
      if (extraData.state) payload.state = extraData.state;

      // Use merge: true so we don't overwrite createdAt or existing custom fields
      await userRef.set({
        ...payload,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      // Sync local storage for instantaneous UI response in static views
      const localUser = {
        id: user.uid,
        uid: user.uid,
        name: name,
        email: email,
        phone: cleanIndianPhone(phone),
        emailVerified: user.emailVerified,
        phoneVerified: Boolean(phone),
        city: extraData.city || 'India',
        joinedDate: new Date().toLocaleDateString('en-IN', { dateStyle: 'medium' })
      };
      localStorage.setItem('vicevault_current_user', JSON.stringify(localUser));

      if (typeof updateNavUserProfile === 'function') {
        updateNavUserProfile(localUser);
      }
      return payload;
    } catch (err) {
      console.error('Firestore sync error:', err);
      return null;
    }
  }

  // ==========================================
  // MODALS (SMS OTP & VERIFICATION GATE)
  // ==========================================
  function ensureModals() {
    // 1. SMS OTP MODAL
    if (!document.getElementById('firebaseOtpModal')) {
      const otpModal = document.createElement('div');
      otpModal.id = 'firebaseOtpModal';
      otpModal.className = 'hidden fixed inset-0 z-[9998] flex items-center justify-center p-4 bg-black/90 backdrop-blur-2xl transition-all duration-300';
      otpModal.innerHTML = `
        <div class="relative w-full max-w-sm apple-glass-panel rounded-3xl p-6 border border-amber-400/50 shadow-2xl space-y-4 text-center bg-[#1A1A1F]/95">
          <button type="button" onclick="window.firebaseAuthService.closeOtpModal()" class="absolute top-4 right-4 w-7 h-7 rounded-full bg-white/[0.08] hover:bg-white/[0.2] text-[#86868b] hover:text-white flex items-center justify-center transition-colors">
            ✕
          </button>
          
          <div class="w-12 h-12 mx-auto rounded-2xl bg-amber-400/15 border border-amber-400/40 flex items-center justify-center text-amber-300">
            <i data-lucide="smartphone" class="w-6 h-6"></i>
          </div>

          <div>
            <h3 class="text-base font-bold text-white">Enter Firebase SMS OTP</h3>
            <p class="text-xs text-[#86868b] mt-1">
              Humne <span id="fbOtpTargetPhone" class="text-amber-300 font-mono font-medium">+91 XXXXXXXXXX</span> par official Firebase verification code bheja hai.
            </p>
          </div>

          <div class="space-y-2">
            <input type="text" id="fbOtpInput" maxlength="6" pattern="[0-9]{6}" placeholder="------" 
                   class="w-full px-4 py-3 bg-black/80 border border-white/[0.15] rounded-xl text-white text-center font-mono tracking-[0.5em] text-lg font-bold focus:outline-none focus:border-amber-400">
            <div id="fbOtpError" class="text-rose-400 text-[11px] hidden text-left font-medium"></div>
          </div>

          <button type="button" id="btnFbVerifyOtp" onclick="window.firebaseAuthService.verifyEnteredOtp()" 
                  class="w-full py-3 rounded-full bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs shadow-lg shadow-amber-400/25 transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-95">
            <span id="btnFbVerifyOtpText">Verify Phone OTP</span>
          </button>

          <div class="flex items-center justify-between text-[11px] text-[#86868b] pt-1">
            <span id="fbOtpTimerText" class="font-mono">Resend in 60s</span>
            <button type="button" id="btnFbResendOtp" onclick="window.firebaseAuthService.resendPhoneOtp()" disabled class="text-amber-300 hover:underline disabled:opacity-40 disabled:no-underline font-semibold cursor-pointer">
              Resend SMS
            </button>
          </div>
        </div>
      `;
      document.body.appendChild(otpModal);
    }

    // 2. VERIFICATION GATE / STATUS MODAL
    if (!document.getElementById('firebaseVerifyGateModal')) {
      const gateModal = document.createElement('div');
      gateModal.id = 'firebaseVerifyGateModal';
      gateModal.className = 'hidden fixed inset-0 z-[9997] flex items-center justify-center p-4 bg-black/90 backdrop-blur-2xl transition-all duration-300';
      gateModal.innerHTML = `
        <div class="relative w-full max-w-md apple-glass-panel rounded-3xl p-6 sm:p-7 border border-[#F0D9B5]/40 shadow-2xl space-y-4 text-left bg-[#1A1A1F]/95">
          <button type="button" onclick="window.firebaseAuthService.closeVerifyGateModal()" class="absolute top-4 right-4 w-8 h-8 rounded-full bg-white/[0.08] hover:bg-white/[0.2] text-[#86868b] hover:text-white flex items-center justify-center transition-colors">
            ✕
          </button>

          <div class="flex items-center gap-3 border-b border-white/[0.08] pb-3">
            <div class="w-10 h-10 rounded-2xl bg-gradient-to-br from-[#F0D9B5]/25 to-amber-500/10 border border-[#F0D9B5]/40 flex items-center justify-center text-[#F0D9B5] shrink-0">
              <i data-lucide="shield-alert" class="w-5 h-5"></i>
            </div>
            <div>
              <h3 class="text-base font-bold text-white">Account Verification Required</h3>
              <p class="text-[11px] text-[#86868b]">Store checkout aur orders unlock karne ke liye phone aur email dono verify hone chahiye.</p>
            </div>
          </div>

          <!-- STATUS CARDS -->
          <div class="space-y-2.5">
            <!-- Phone Status -->
            <div id="gatePhoneCard" class="p-3 rounded-2xl bg-black/50 border border-white/[0.08] flex items-center justify-between">
              <div class="flex items-center gap-2.5 min-w-0">
                <i data-lucide="smartphone" class="w-4 h-4 text-amber-300 shrink-0"></i>
                <div class="min-w-0">
                  <div class="text-xs font-semibold text-white">Mobile Verification</div>
                  <div id="gatePhoneValue" class="text-[11px] text-[#86868b] font-mono truncate">+91 ----------</div>
                </div>
              </div>
              <div id="gatePhoneAction">
                <!-- Verified pill or Verify button -->
              </div>
            </div>

            <!-- Email Status -->
            <div id="gateEmailCard" class="p-3 rounded-2xl bg-black/50 border border-white/[0.08] flex items-center justify-between">
              <div class="flex items-center gap-2.5 min-w-0">
                <i data-lucide="mail" class="w-4 h-4 text-amber-300 shrink-0"></i>
                <div class="min-w-0">
                  <div class="text-xs font-semibold text-white">Email Link Verification</div>
                  <div id="gateEmailValue" class="text-[11px] text-[#86868b] truncate">name@email.com</div>
                </div>
              </div>
              <div id="gateEmailAction">
                <!-- Verified pill or Resend button -->
              </div>
            </div>
          </div>

          <!-- Guidance Note -->
          <div class="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-200/90 leading-relaxed">
            💡 <b>Email Verify karne ke liye:</b> Apne inbox (ya Spam folder) mein Firebase se aaye link par click karein. Phir neeche <b>"Check Status"</b> par click karein.
          </div>

          <!-- Main Actions -->
          <div class="space-y-2 pt-1">
            <button type="button" id="btnGateCheckStatus" onclick="window.firebaseAuthService.checkVerificationStatus()" 
                    class="w-full py-3 rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-white font-extrabold text-xs shadow-lg shadow-emerald-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-95">
              <i data-lucide="refresh-cw" class="w-4 h-4"></i>
              <span id="btnGateCheckStatusText">Maine Link Click Kar Diya — Check Status</span>
            </button>

            <div class="flex items-center justify-between text-xs pt-1">
              <button type="button" id="btnGateResendEmail" onclick="window.firebaseAuthService.resendVerificationEmail()" 
                      class="text-amber-300 hover:underline text-[11px] font-semibold disabled:opacity-40 disabled:no-underline">
                Resend Email Link
              </button>
              <button type="button" onclick="window.firebaseAuthService.signOut()" class="text-rose-400 hover:underline text-[11px]">
                Sign Out / Switch Account
              </button>
            </div>
          </div>
        </div>
      `;
      document.body.appendChild(gateModal);
    }

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }

  // ==========================================
  // SIGN UP FLOW (NAME, EMAIL, INDIAN PHONE)
  // ==========================================
  async function handleSignUp({ name, email, phone, password }) {
    if (!window.isFirebaseConfigured || !window.isFirebaseConfigured()) {
      window.showFirebaseSetupBanner('Firebase configured nahi hai. Live SMS OTP aur Email verification ke liye firebase-config.js mein credentials dalein.');
      return { success: false, error: 'Firebase not configured' };
    }

    // 1. Validation
    if (!name || name.trim().length < 2) {
      throw new Error('Kripya apna poora naam (Full Name) enter karein.');
    }
    if (!isValidEmail(email)) {
      throw new Error('Kripya valid email address enter karein (e.g. name@gmail.com).');
    }
    const cleanPhone = cleanIndianPhone(phone);
    if (!isValidIndianPhone(cleanPhone)) {
      throw new Error('Kripya valid 10-digit Indian (+91) mobile number dalein.');
    }
    if (!password || password.length < 6) {
      throw new Error('Password kam se kam 6 characters ka hona chahiye.');
    }

    const formattedPhone = '+91' + cleanPhone;
    pendingRegistrationData = {
      name: name.trim(),
      email: email.trim().toLowerCase(),
      phone: formattedPhone,
      cleanPhone: cleanPhone,
      password: password
    };

    const auth = window.firebaseAuth;
    const verifier = ensureRecaptchaVerifier();
    if (!verifier) {
      throw new Error('reCAPTCHA init fail ho gaya. Kripya page refresh karein.');
    }

    // Step A: Create Email/Password user in Firebase Auth
    let userCredential = null;
    try {
      userCredential = await auth.createUserWithEmailAndPassword(pendingRegistrationData.email, password);
    } catch (createErr) {
      // If email is already in use, throw friendly error
      if (createErr.code === 'auth/email-already-in-use') {
        throw new Error('Ye Email ID pehle se registered hai! Kripya "VIP Sign In" tab par jakar login karein.');
      }
      throw new Error(translateError(createErr));
    }

    const user = userCredential.user;

    // Step B: Update user's displayName
    try {
      await user.updateProfile({ displayName: pendingRegistrationData.name });
    } catch (e) {}

    // Step C: Send Firebase Email Verification Link
    try {
      await user.sendEmailVerification();
      console.log('📧 Firebase verification email dispatched to:', user.email);
    } catch (emailErr) {
      console.warn('Email verification send warning:', emailErr);
    }

    // Step D: Trigger Phone Auth SMS OTP via user.linkWithPhoneNumber
    try {
      phoneConfirmationResult = await user.linkWithPhoneNumber(formattedPhone, verifier);
      openOtpModal(formattedPhone);
      startSmsResendTimer(60);
      if (typeof showToast === 'function') {
        showToast('📱 SMS OTP bheja gaya hai: ' + formattedPhone);
      }
      return { success: true, pendingPhoneOtp: true };
    } catch (phoneErr) {
      console.error('Phone link error:', phoneErr);
      if (phoneErr.code === 'auth/credential-already-in-use' || phoneErr.code === 'auth/phone-number-already-exists') {
        throw new Error('Ye mobile number pehle se kisi doosre account ke sath linked hai.');
      }
      throw new Error(translateError(phoneErr));
    }
  }

  // ==========================================
  // VERIFY ENTERED SMS OTP
  // ==========================================
  async function verifyEnteredOtp() {
    const otpInput = document.getElementById('fbOtpInput');
    const otpError = document.getElementById('fbOtpError');
    const btnVerify = document.getElementById('btnFbVerifyOtp');
    const btnText = document.getElementById('btnFbVerifyOtpText');

    if (!otpInput) return;
    const otp = otpInput.value.trim();

    if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
      if (otpError) {
        otpError.textContent = 'Kripya 6-digit number OTP enter karein.';
        otpError.classList.remove('hidden');
      }
      return;
    }

    if (!phoneConfirmationResult) {
      if (otpError) {
        otpError.textContent = 'SMS session expire ho gaya. Kripya "Resend SMS" karein.';
        otpError.classList.remove('hidden');
      }
      return;
    }

    // Loading UI
    if (btnVerify) btnVerify.disabled = true;
    if (btnText) btnText.textContent = 'Verifying with Firebase...';
    if (otpError) otpError.classList.add('hidden');

    try {
      const result = await phoneConfirmationResult.confirm(otp);
      const user = result.user || window.firebaseAuth.currentUser;

      closeOtpModal();

      if (typeof showToast === 'function') {
        showToast('✓ Phone successfully verify ho gaya!');
      }

      // Check if email is also verified
      await user.reload();
      if (isUserFullyVerified(user)) {
        // Both verified! Save to Firestore
        await syncUserProfileToFirestore(user, pendingRegistrationData || {});
        if (typeof showToast === 'function') {
          showToast('🎉 Account Fully Verified! Store unlocked.');
        }
        if (typeof closeAuthModal === 'function') closeAuthModal(true);
      } else {
        // Phone verified, but email link pending!
        openVerifyGateModal(user);
      }
    } catch (err) {
      console.error('OTP confirmation error:', err);
      if (otpError) {
        otpError.textContent = translateError(err);
        otpError.classList.remove('hidden');
      }
    } finally {
      if (btnVerify) btnVerify.disabled = false;
      if (btnText) btnText.textContent = 'Verify Phone OTP';
    }
  }

  // ==========================================
  // RESEND PHONE SMS OTP
  // ==========================================
  async function resendPhoneOtp() {
    if (smsResendCooldown > 0) return;
    const auth = window.firebaseAuth;
    const user = auth ? auth.currentUser : null;
    const phone = (pendingRegistrationData && pendingRegistrationData.phone) || (user && user.phoneNumber);

    if (!phone) {
      if (typeof showToast === 'function') showToast('Mobile number missing hai.');
      return;
    }

    const verifier = ensureRecaptchaVerifier();
    if (!verifier) return;

    const btnResend = document.getElementById('btnFbResendOtp');
    if (btnResend) btnResend.disabled = true;

    try {
      if (user) {
        phoneConfirmationResult = await user.linkWithPhoneNumber(phone, verifier);
      } else {
        phoneConfirmationResult = await auth.signInWithPhoneNumber(phone, verifier);
      }
      startSmsResendTimer(60);
      if (typeof showToast === 'function') {
        showToast('📱 Naya SMS OTP bhej diya gaya hai!');
      }
    } catch (err) {
      if (typeof showToast === 'function') {
        showToast(translateError(err));
      }
    }
  }

  function startSmsResendTimer(seconds) {
    if (smsResendInterval) clearInterval(smsResendInterval);
    smsResendCooldown = seconds;
    const timerText = document.getElementById('fbOtpTimerText');
    const btnResend = document.getElementById('btnFbResendOtp');

    function update() {
      if (smsResendCooldown > 0) {
        if (timerText) timerText.textContent = `Resend in ${smsResendCooldown}s`;
        if (btnResend) btnResend.disabled = true;
        smsResendCooldown--;
      } else {
        clearInterval(smsResendInterval);
        if (timerText) timerText.textContent = 'Resend available';
        if (btnResend) btnResend.disabled = false;
      }
    }
    update();
    smsResendInterval = setInterval(update, 1000);
  }

  // ==========================================
  // RESEND EMAIL VERIFICATION LINK
  // ==========================================
  async function resendVerificationEmail() {
    if (emailResendCooldown > 0) {
      if (typeof showToast === 'function') {
        showToast(`⏱️ Kripya ${emailResendCooldown}s wait karein doosra link mangwane se pehle.`);
      }
      return;
    }

    const auth = window.firebaseAuth;
    const user = auth ? auth.currentUser : null;
    if (!user) {
      if (typeof showToast === 'function') showToast('Kripya pehle sign in karein.');
      return;
    }

    try {
      await user.sendEmailVerification();
      startEmailResendTimer(60);
      if (typeof showToast === 'function') {
        showToast(`📧 Verification link sent to ${user.email}! (Check Inbox & Spam)`);
      }
    } catch (err) {
      if (typeof showToast === 'function') {
        showToast(translateError(err));
      }
    }
  }

  function startEmailResendTimer(seconds) {
    if (emailResendInterval) clearInterval(emailResendInterval);
    emailResendCooldown = seconds;
    const btnResend = document.getElementById('btnGateResendEmail');

    function update() {
      if (emailResendCooldown > 0) {
        if (btnResend) {
          btnResend.textContent = `Resend Email Link (${emailResendCooldown}s)`;
          btnResend.disabled = true;
        }
        emailResendCooldown--;
      } else {
        clearInterval(emailResendInterval);
        if (btnResend) {
          btnResend.textContent = 'Resend Email Link';
          btnResend.disabled = false;
        }
      }
    }
    update();
    emailResendInterval = setInterval(update, 1000);
  }

  // ==========================================
  // CHECK VERIFICATION STATUS
  // ==========================================
  async function checkVerificationStatus() {
    const auth = window.firebaseAuth;
    const user = auth ? auth.currentUser : null;
    if (!user) {
      if (typeof showToast === 'function') showToast('Kripya pehle sign in karein.');
      return;
    }

    const btn = document.getElementById('btnGateCheckStatus');
    const btnText = document.getElementById('btnGateCheckStatusText');
    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Checking with Firebase...';

    try {
      await user.reload(); // fetch fresh token from server
      const freshUser = auth.currentUser;

      if (isUserFullyVerified(freshUser)) {
        await syncUserProfileToFirestore(freshUser, pendingRegistrationData || {});
        closeVerifyGateModal();
        if (typeof showToast === 'function') {
          showToast('🎉 Mubarak! Email aur Phone dono successfully verify ho gaye.');
        }
        if (typeof closeAuthModal === 'function') closeAuthModal(true);
      } else {
        openVerifyGateModal(freshUser);
        if (!freshUser.emailVerified) {
          if (typeof showToast === 'function') {
            showToast('⏳ Email abhi verify nahi hua hai. Kripya inbox mein aaya link click karein.');
          }
        } else if (!freshUser.phoneNumber) {
          if (typeof showToast === 'function') {
            showToast('⚠️ Phone verification pending hai. Kripya SMS OTP verify karein.');
          }
        }
      }
    } catch (err) {
      if (typeof showToast === 'function') showToast(translateError(err));
    } finally {
      if (btn) btn.disabled = false;
      if (btnText) btnText.textContent = 'Maine Link Click Kar Diya — Check Status';
    }
  }

  // ==========================================
  // EXISTING USER LOGIN
  // ==========================================
  async function handleLogin({ identifier, password }) {
    if (!window.isFirebaseConfigured || !window.isFirebaseConfigured()) {
      window.showFirebaseSetupBanner('Firebase configured nahi hai. Live login ke liye firebase-config.js mein credentials dalein.');
      return { success: false };
    }

    if (!identifier) {
      throw new Error('Kripya apna registered Mobile number ya Email enter karein.');
    }
    if (!password) {
      throw new Error('Kripya apna password enter karein.');
    }

    const auth = window.firebaseAuth;
    let emailToAuth = identifier.trim();

    // If identifier is a 10-digit Indian phone number, we look up or allow email
    if (isValidIndianPhone(identifier)) {
      // In Firebase email/password, identifier is an email. If user entered phone,
      // check if they used phone@vicevault.store or prompt
      if (!identifier.includes('@')) {
        emailToAuth = cleanIndianPhone(identifier) + '@vicevault.store';
      }
    }

    try {
      const cred = await auth.signInWithEmailAndPassword(emailToAuth, password);
      const user = cred.user;
      await user.reload();

      if (!isUserFullyVerified(user)) {
        openVerifyGateModal(user);
        return { success: true, pendingVerification: true };
      }

      // Fully verified! Fetch profile from Firestore
      if (window.firebaseDb) {
        try {
          const doc = await window.firebaseDb.collection('users').doc(user.uid).get();
          if (doc.exists) {
            const data = doc.data();
            localStorage.setItem('vicevault_current_user', JSON.stringify({
              id: user.uid,
              uid: user.uid,
              name: data.name || user.displayName || 'VIP Member',
              email: data.email || user.email,
              phone: cleanIndianPhone(data.phone || user.phoneNumber),
              city: data.city || 'India',
              address: data.address || '',
              pincode: data.pincode || '',
              state: data.state || '',
              joinedDate: data.createdAt ? new Date(data.createdAt.toDate ? data.createdAt.toDate() : data.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' }) : 'VIP'
            }));
          }
        } catch (e) {}
      }

      if (typeof closeAuthModal === 'function') closeAuthModal(true);
      if (typeof showToast === 'function') {
        showToast('👋 Welcome back, ' + (user.displayName || 'VIP Member') + '!');
      }
      return { success: true };
    } catch (err) {
      throw new Error(translateError(err));
    }
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
    closeVerifyGateModal();
    if (typeof updateNavGuestProfile === 'function') updateNavGuestProfile();
    if (typeof showToast === 'function') showToast('Logged out successfully.');
    window.location.reload();
  }

  // ==========================================
  // MODAL TOGGLERS & UI HELPERS
  // ==========================================
  function openOtpModal(phone) {
    ensureModals();
    const modal = document.getElementById('firebaseOtpModal');
    const target = document.getElementById('fbOtpTargetPhone');
    const input = document.getElementById('fbOtpInput');
    const err = document.getElementById('fbOtpError');

    if (target) target.textContent = phone;
    if (input) {
      input.value = '';
      setTimeout(() => input.focus(), 100);
    }
    if (err) err.classList.add('hidden');
    if (modal) modal.classList.remove('hidden');
  }

  function closeOtpModal() {
    const modal = document.getElementById('firebaseOtpModal');
    if (modal) modal.classList.add('hidden');
  }

  function openVerifyGateModal(user) {
    ensureModals();
    const modal = document.getElementById('firebaseVerifyGateModal');
    const phoneVal = document.getElementById('gatePhoneValue');
    const phoneAct = document.getElementById('gatePhoneAction');
    const emailVal = document.getElementById('gateEmailValue');
    const emailAct = document.getElementById('gateEmailAction');

    const currentUser = user || (window.firebaseAuth ? window.firebaseAuth.currentUser : null);
    if (!currentUser) return;

    const phone = currentUser.phoneNumber || (pendingRegistrationData && pendingRegistrationData.phone) || '';
    const email = currentUser.email || '';
    const hasPhoneVerified = Boolean(currentUser.phoneNumber);
    const hasEmailVerified = Boolean(currentUser.emailVerified);

    if (phoneVal) phoneVal.textContent = phone || 'Not linked';
    if (emailVal) emailVal.textContent = email || 'Not registered';

    if (phoneAct) {
      if (hasPhoneVerified) {
        phoneAct.innerHTML = `<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold text-[10px] flex items-center gap-1"><i data-lucide="check" class="w-3 h-3"></i> Verified</span>`;
      } else {
        phoneAct.innerHTML = `<button type="button" onclick="window.firebaseAuthService.resendPhoneOtp()" class="px-3 py-1 rounded-xl bg-amber-400 text-black font-bold text-[11px] hover:bg-amber-300 transition-all cursor-pointer">Verify SMS</button>`;
      }
    }

    if (emailAct) {
      if (hasEmailVerified) {
        emailAct.innerHTML = `<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold text-[10px] flex items-center gap-1"><i data-lucide="check" class="w-3 h-3"></i> Verified</span>`;
      } else {
        emailAct.innerHTML = `<span class="px-2.5 py-1 rounded-full bg-amber-400/20 text-amber-300 border border-amber-400/30 font-bold text-[10px] flex items-center gap-1">Link Sent ⏳</span>`;
      }
    }

    if (modal) modal.classList.remove('hidden');
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }

  function closeVerifyGateModal() {
    const modal = document.getElementById('firebaseVerifyGateModal');
    if (modal) modal.classList.add('hidden');
  }

  // ==========================================
  // PROTECTED ACTION GATE
  // ==========================================
  /**
   * Guards protected actions (checkout, buy now, profile save)
   * requiring user to be fully verified.
   */
  function requireFullyVerifiedUser(onVerifiedCallback) {
    if (!window.isFirebaseConfigured || !window.isFirebaseConfigured()) {
      window.showFirebaseSetupBanner('Protected action blocked: Firebase setup required to verify users.');
      return false;
    }

    const auth = window.firebaseAuth;
    const user = auth ? auth.currentUser : null;

    if (!user) {
      if (typeof showToast === 'function') {
        showToast('🔒 Store access ke liye pehle sign in karein.');
      }
      if (typeof openAuthModal === 'function') openAuthModal();
      return false;
    }

    if (!isUserFullyVerified(user)) {
      openVerifyGateModal(user);
      if (typeof showToast === 'function') {
        showToast('⚠️ Kripya apna Phone aur Email pehle verify karein.');
      }
      return false;
    }

    if (typeof onVerifiedCallback === 'function') {
      onVerifiedCallback(user);
    }
    return true;
  }

  // ==========================================
  // AUTH STATE LISTENER INITIALIZATION
  // ==========================================
  function initFirebaseAuthListener() {
    ensureModals();
    if (!window.isFirebaseConfigured || !window.isFirebaseConfigured()) {
      return;
    }

    const auth = window.firebaseAuth;
    if (!auth) return;

    auth.onAuthStateChanged(async function(user) {
      if (user) {
        if (isUserFullyVerified(user)) {
          // Sync with Firestore
          await syncUserProfileToFirestore(user);
        } else {
          // If unverified, keep gate available
          console.log('Firebase user logged in but pending verification:', user.uid);
        }
      } else {
        // Logged out
      }
    });
  }

  // Auto initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirebaseAuthListener);
  } else {
    initFirebaseAuthListener();
  }

  // Export public service API
  window.firebaseAuthService = {
    handleSignUp,
    handleLogin,
    signOut,
    verifyEnteredOtp,
    resendPhoneOtp,
    resendVerificationEmail,
    checkVerificationStatus,
    openOtpModal,
    closeOtpModal,
    openVerifyGateModal,
    closeVerifyGateModal,
    isUserFullyVerified,
    requireFullyVerifiedUser,
    cleanIndianPhone,
    isValidIndianPhone,
    isValidEmail,
    syncUserProfileToFirestore
  };

})();
