// ==============================================================
// VICEVAULT // Firebase Client Web App Configuration
// ==============================================================
// Replace these placeholder values with your real Firebase Project credentials.
// Get them from Firebase Console (https://console.firebase.google.com/) ->
// Project Settings -> General -> "Your apps" -> Web app (</>)
//
// NOTE: These are client-side public identifiers.
// NEVER place Firebase Admin SDK / Service Account private keys in frontend files.

const DEFAULT_FIREBASE_CONFIG = {
  apiKey: "YOUR_FIREBASE_API_KEY",
  authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT_ID.firebasestorage.app",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId: "YOUR_APP_ID"
};

// Allow environment variable injection if available on window.__ENV__
const activeFirebaseConfig = (window.__ENV__ && window.__ENV__.FIREBASE_CONFIG) 
  || window.__FIREBASE_CONFIG__ 
  || DEFAULT_FIREBASE_CONFIG;

/**
 * Checks whether Firebase credentials have been supplied by the developer
 * or if they are still placeholder strings.
 * @returns {boolean}
 */
function isFirebaseConfigured() {
  if (!activeFirebaseConfig) return false;
  const { apiKey, projectId, appId } = activeFirebaseConfig;
  if (!apiKey || apiKey === "YOUR_FIREBASE_API_KEY" || apiKey.includes("REPLACE")) return false;
  if (!projectId || projectId === "YOUR_PROJECT_ID") return false;
  if (!appId || appId === "YOUR_APP_ID") return false;
  return true;
}

let firebaseApp = null;
let firebaseAuth = null;
let firebaseDb = null;

if (typeof firebase !== 'undefined') {
  if (isFirebaseConfigured()) {
    try {
      if (!firebase.apps || firebase.apps.length === 0) {
        firebaseApp = firebase.initializeApp(activeFirebaseConfig);
      } else {
        firebaseApp = firebase.app();
      }
      firebaseAuth = firebase.auth();
      firebaseDb = firebase.firestore();
      console.log('⚡ Firebase initialized successfully for project:', activeFirebaseConfig.projectId);
    } catch (err) {
      console.error('Firebase initialization error:', err);
    }
  } else {
    console.warn(
      '⚠️ [VICEVAULT Firebase Notice] Firebase configuration has placeholder values.\n' +
      'Please update firebase-config.js with your real Firebase Web App credentials to enable live SMS OTP & Email Verification.'
    );
  }
} else {
  console.warn('⚠️ [VICEVAULT Firebase Notice] Firebase SDK script tags not loaded yet.');
}

// Global references for vanilla JS access
window.firebaseConfig = activeFirebaseConfig;
window.isFirebaseConfigured = isFirebaseConfigured;
window.firebaseApp = firebaseApp;
window.firebaseAuth = firebaseAuth;
window.firebaseDb = firebaseDb;

/**
 * Surface a luxury banner/modal informing the user/developer that
 * Firebase credentials must be set in firebase-config.js.
 */
function showFirebaseSetupBanner(customMsg) {
  const msg = customMsg || 'Firebase Authentication setup zaroori hai! Kripya "firebase-config.js" file mein apni Firebase Console credentials dalein taaki live SMS OTP aur Email verification shuru ho sake.';
  if (typeof showToast === 'function') {
    showToast('⚠️ ' + msg);
  } else {
    alert(msg);
  }

  // Open or ensure a setup modal if present
  let setupModal = document.getElementById('firebaseSetupModal');
  if (!setupModal) {
    setupModal = document.createElement('div');
    setupModal.id = 'firebaseSetupModal';
    setupModal.className = 'fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/85 backdrop-blur-md transition-all duration-300';
    setupModal.innerHTML = `
      <div class="relative w-full max-w-md apple-glass-panel rounded-3xl p-6 border border-amber-400/40 shadow-2xl text-left space-y-4 bg-[#1A1A1F]/95">
        <div class="flex items-center justify-between border-b border-white/[0.08] pb-3">
          <div class="flex items-center gap-2 text-amber-300 font-bold text-sm">
            <i data-lucide="alert-triangle" class="w-5 h-5"></i>
            <span>Firebase Configuration Required</span>
          </div>
          <button type="button" onclick="document.getElementById('firebaseSetupModal').remove()" class="text-[#86868b] hover:text-white p-1 rounded-lg">
            ✕
          </button>
        </div>
        <div class="space-y-2 text-xs text-[#c4c4c8] leading-relaxed">
          <p class="font-medium text-white">Firebase credentials missing hain:</p>
          <p>Real SMS OTP aur Firebase Email Verification chalane ke liye:</p>
          <ol class="list-decimal list-inside space-y-1 text-[11px] text-[#86868b] bg-black/40 p-3 rounded-xl border border-white/[0.06]">
            <li>Firebase Console (<span class="text-amber-300 font-mono">console.firebase.google.com</span>) kholein.</li>
            <li>Project Settings &gt; General &gt; "Your apps" &gt; Web App me jayein.</li>
            <li>Credentials copy karke <span class="text-[#F0D9B5] font-mono">firebase-config.js</span> mein dalein.</li>
            <li>Authentication &gt; Sign-in method me <b>Phone</b> aur <b>Email/Password</b> enable karein.</li>
          </ol>
          <p class="text-[10px] text-amber-400/90 font-mono">Live Firebase Authentication setup zaroori hai.</p>
        </div>
        <button type="button" onclick="document.getElementById('firebaseSetupModal').remove()" class="w-full py-2.5 rounded-xl bg-amber-400 hover:bg-amber-300 text-black font-bold text-xs transition-all shadow-md">
          Theek Hai, Samajh Gaya (Close)
        </button>
      </div>
    `;
    document.body.appendChild(setupModal);
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      lucide.createIcons();
    }
  }
}

window.showFirebaseSetupBanner = showFirebaseSetupBanner;
