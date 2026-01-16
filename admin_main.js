// main.js

// Helper: Format timestamp to readable string
export function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  // Format without seconds (e.g. "Dec 6, 2025, 10:33 AM")
  try {
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return d.toLocaleString();
  }
}

// Helper: Generate random password string
export function generateRandomString(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*=+?';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Helper: Modal open/close
export function openModal(modal) {
  if (modal) {
    modal.style.display = "flex";
    modal.setAttribute("aria-hidden", "false");
  }
}
export function closeModal(modal) {
  if (modal) {
    modal.style.display = "none";
    modal.setAttribute("aria-hidden", "true");
  }
}

// Helper: Row selection
export function enableRowSelection(tbody) {
  if (!tbody) return;
  tbody.addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr");
    if (!tr) return;
    const prev = tbody.querySelector("tr.selected");
    if (prev && prev !== tr) prev.classList.remove("selected");
    tr.classList.toggle("selected");
  });
}

// Helper: Search filter
export function enableSearchFilter(searchInput, tbody, columns = 7) {
  if (!searchInput || !tbody) return;
  searchInput.addEventListener("input", () => {
    const q = searchInput.value.trim().toLowerCase();
    for (const row of Array.from(tbody.rows)) {
      const texts = Array.from(row.cells).slice(0, columns).map(c => (c.textContent || "").toLowerCase());
      row.style.display = (!q || texts.some(t => t.includes(q))) ? "" : "none";
    }
  });
}

// =============================
// Firebase + Counselors API
// =============================
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-app.js";
import { getDatabase, ref, get, set, update, remove, onValue } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-database.js";
import { getAuth, createUserWithEmailAndPassword, sendPasswordResetEmail, signOut, signInWithEmailAndPassword, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-auth.js";
import { getStorage, ref as storageRef, getDownloadURL } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyD4eMHzsieWnIH6nHLgBl1PDTiIETeVmnA",
  authDomain: "rsu-safespace.firebaseapp.com",
  databaseURL: "https://rsu-safespace-default-rtdb.firebaseio.com",
  projectId: "rsu-safespace",
  storageBucket: "rsu-safespace.firebasestorage.app",
  messagingSenderId: "490237933031",
  appId: "1:490237933031:web:0d17829f4359da952db942",
  measurementId: "G-YY33W1QM2N"
};

// Default app (for admin session)
const app = initializeApp(firebaseConfig);
const db = getDatabase(app);
const auth = getAuth(app);

// Export app, auth, db and common helpers so other pages can use the same initialized instances
export {
  app,
  auth,
  db,
  getDatabase,
  ref,
  get,
  set,
  update,
  remove,
  onValue,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  signOut,
  getStorage,
  storageRef,
  getDownloadURL
};

// Create a DB-backed notification for a user (defaults to current authenticated user)
export async function createNotification({ title = 'Notification', body = '', ts = Date.now(), targetUid = null, silent = false, ...extra } = {}) {
  const user = auth.currentUser;
  const uid = targetUid || (user && user.uid);
  if (!uid) throw new Error('No target user for notification');
  const key = String(Date.now()) + '-' + Math.random().toString(36).slice(2,8);
  // Merge known fields first, then spread any extra fields provided (e.g. path, studentId, importCount)
  const payload = Object.assign({ title: title, body: body, ts: ts, read: false }, extra || {});
  if (silent) payload.silent = true;
  await set(ref(db, `notifications/${uid}/${key}`), payload);
  return key;
}

// Expose helper to non-module scripts
window.createNotification = createNotification;

// Broadcast a notification to all admin users (writes one notification per admin uid)
export async function broadcastNotification({ title = 'Notification', body = '', ts = Date.now(), silent = false, ...extra } = {}) {
  try {
    const snap = await get(ref(db, `admins`));
    if (!snap.exists()) return false;
    const admins = snap.val();
    const uids = Object.keys(admins || {}).filter(k => !!k);
    if (!uids.length) return false;
    const promises = [];
    for (const uid of uids) {
      try {
        const key = String(Date.now()) + '-' + Math.random().toString(36).slice(2,8);
        const payload = Object.assign({ title: title, body: body, ts: ts, read: false }, extra || {});
        if (silent) payload.silent = true;
        promises.push(set(ref(db, `notifications/${uid}/${key}`), payload));
      } catch (e) { console.debug('broadcastNotification write skipped for', uid, e); }
    }
    await Promise.all(promises);
    return true;
  } catch (e) {
    console.error('broadcastNotification error', e);
    return false;
  }
}

// Expose broadcast helper globally
window.broadcastNotification = broadcastNotification;

// Secondary app just for creating users safely (avoids messing with admin session)
const secondaryApp = initializeApp(firebaseConfig, "Secondary");
const secondaryAuth = getAuth(secondaryApp);

// Read all counselors
export async function fetchCounselors() {
  const snap = await get(ref(db, "counselors"));
  return snap.exists() ? snap.val() : {};
}

// Read one counselor
export async function getCounselor(id) {
  if (!id) return null;
  const snap = await get(ref(db, `counselors/${id}`));
  return snap.exists() ? snap.val() : null;
}

//Reset counselor password
export async function sendReset(emailreset) {
  try {
    await sendPasswordResetEmail(auth, emailreset);
    alert("A password reset link has been sent to the counselor's registered email address (" + emailreset + ")");
  } catch (error) {
    alert("Error: " + error.message);
  }
}

// Generate next counselor ID as 3 digits (001, 002, ...), avoiding collisions
async function generateNextCounselorId() {
  const snap = await get(ref(db, "counselors"));
  let maxNum = 0;
  if (snap.exists()) {
    const all = snap.val();
    for (const k of Object.keys(all)) {
      const child = all[k];
      let n = null;
      if (child && child.counselor_id) {
        n = parseInt(child.counselor_id, 10);
      } else if (/^\d+$/.test(k)) {
        n = parseInt(k, 10);
      }
      if (!isNaN(n) && n > maxNum) maxNum = n;
    }
  }
  let next = maxNum + 1;
  let id = String(next).padStart(3, "0");
  while ((await get(ref(db, `counselors/${id}`))).exists()) {
    next++;
    id = String(next).padStart(3, "0");
  }
  return id;
}

// Add counselor record and create auth user; returns { id, password, uid }
export async function addCounselorRecord({
  username,
  first_name,
  last_name,
  email_address,
  specialization,
  department,
  status = "Active",
  campus,
  photo_url,
  // accept college aliases that other code may provide
  college,
  college_name,
  collegeName,
  college_display
}) {
  const id = await generateNextCounselorId();
  // Create login account if email provided
  const password = generateRandomString();
  let uid = null;
  if (email_address) {
    try {
      const cred = await createUserWithEmailAndPassword(secondaryAuth, email_address, password);
      uid = cred.user?.uid || null;
    } finally {
      try { await signOut(secondaryAuth); } catch {}
    }
  }

  // Only add to database if Auth user creation succeeded (or no email provided)
  // Normalize college value from any provided alias
  const collegeValue = (college || college_name || collegeName || college_display || "").toString();

  const payload = {
    counselor_id: id,
    username: username || "",
    first_name: first_name || "",
    last_name: last_name || "",
    email_address: email_address || "",
    specialization: specialization || "",
    department: department || "",
    status: status || "Active",
    campus: campus || "",
    photo_url: photo_url || "",
    college: collegeValue,
    login: "Enable",
    login_access: true,
    created_at: new Date().toISOString(),
    uid: uid || null
  };

  await set(ref(db, `counselors/${id}`), payload);

  try {
    // Create notification but mark it silent so it does not produce a toast popup
    await createNotification({ title: 'Counselor added', body: `${payload.first_name} ${payload.last_name} (${id})`, silent: true });
  } catch (e) { console.debug('notify addCounselorRecord failed', e); }

  return { id, password, uid };
}

// Update counselor fields
export async function updateCounselor(id, data) {
  await update(ref(db, `counselors/${id}`), data || {});
  try { await createNotification({ title: 'Counselor updated', body: `ID ${id} updated` }); } catch(e){ console.debug('notify updateCounselor failed', e); }
}

// Delete counselor
export async function deleteCounselor(id) {
  await remove(ref(db, `counselors/${id}`));
  try { await createNotification({ title: 'Counselor removed', body: `Counselor ID ${id} was deleted` }); } catch(e){ console.debug('notify deleteCounselor failed', e); }
}

// Toggle login access
export async function toggleCounselorLogin(id, enabled) {
  await update(ref(db, `counselors/${id}`), {
    login: enabled ? "Enable" : "Disable",
    login_access: !!enabled
  });
  try { await createNotification({ title: 'Counselor login changed', body: `Counselor ${id} login ${enabled ? 'enabled' : 'disabled'}` }); } catch(e){ console.debug('notify toggleCounselorLogin failed', e); }
}

// -----------------------------
// Admin authentication helpers
// -----------------------------
// Checks Realtime Database under `admins/{uid}` for admin record
export async function isAdminUid(uid) {
  if (!uid) return false;
  try {
    console.debug('isAdminUid: checking admins/' + uid);
    const snap = await get(ref(db, `admins/${uid}`));
    console.debug('isAdminUid: db snapshot received for', uid, snap.exists());
    if (!snap.exists()) return false;
    const val = snap.val();
    console.debug('isAdminUid: data=', val);
    if (!val) return false;
    const role = val.role || val.position || '';
    const enabled = (val.enable || val.enabled || '').toString().toLowerCase();
    // treat missing enable as allowed but prefer explicit 'enable'
    const isEnabled = !enabled || enabled === 'enable' || enabled === 'true';
    return (role === 'admin' || role === 'Administrator' || role === 'administrator') && isEnabled;
  } catch (err) {
    console.error('isAdminUid error', err);
    return false;
  }
}

// Sign in and enforce admin-only access. Redirects to admin-dashboard.html on success.
export async function adminLogin(email, password) {
  const cred = await signInWithEmailAndPassword(auth, email, password);
  const user = cred.user;
  console.debug('adminLogin: signed in user', user && user.uid, user && user.email);
  const ok = await isAdminUid(user.uid);
  if (!ok) {
    try { await signOut(auth); } catch (e) {}
    throw new Error('Access denied. User is not an admin.');
  }

  // If the admin has enabled login alerts, write a notification for this sign-in
  try {
    const adminSnap = await get(ref(db, `admins/${user.uid}`));
    const adminRec = adminSnap && adminSnap.exists() ? adminSnap.val() : {};
    const wantsAlerts = !!adminRec.loginAlerts;
    if (wantsAlerts) {
      try {
        const key = String(Date.now());
        const payload = {
          title: 'New sign-in',
          body: `Signed in from device: ${(typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent : 'unknown'}`,
          ts: Date.now(),
          read: false
        };
        await set(ref(db, `notifications/${user.uid}/${key}`), payload);
      } catch (e) { console.debug('write login notification failed', e); }
    }
  } catch (e) { console.debug('login alert check failed', e); }

  // Check per-admin two-factor setting in DB
  try {
    const snap = await get(ref(db, `admins/${user.uid}`));
    const adminRec = snap && snap.exists() ? snap.val() : {};
    const twoFactor = !!(adminRec.twoFactor || adminRec.twoFactorEnabled);
    // If two-factor is enabled, check if this device is trusted and should skip 2FA
    try {
      const localToken = getDeviceToken();
      if (twoFactor && localToken) {
        const trustedSnap = await get(ref(db, `admins/${user.uid}/trustedDevices/${localToken}`));
        if (trustedSnap.exists()) {
          const rec = trustedSnap.val();
          if (!rec.expiresAt || Date.now() < (rec.expiresAt || 0)) {
            // trusted device: mark verified and redirect
            await update(ref(db, `admins/${user.uid}`), { twoFactorVerified: true });
            window.location.href = 'admin_dashboard.html';
            return;
          }
        }
      }
    } catch (e) { console.debug('device token check failed', e); }
    if (!twoFactor) {
      // authorized and no 2FA required
      window.location.href = 'admin_dashboard.html';
      return;
    }

    // Two-factor enabled: generate a temporary code, store it, send it to admin email, and require verification
    const code = String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
    const expiresAt = Date.now() + (5 * 60 * 1000); // 5 minutes
    await update(ref(db, `admins/${user.uid}`), { pending2fa: { code: code, expiresAt: expiresAt, issuedAt: Date.now() }, twoFactorVerified: false });

    // Try sending code by EmailJS if available (some pages include EmailJS). Fallback: rely on DB record.
    try {
      if (window.emailjs && typeof window.emailjs.send === 'function') {
        // Expect an EmailJS template named 'template_2fa' configured in the EmailJS account
        const templateParams = { to_email: user.email || adminRec.email || '', code: code, to_name: adminRec.fullname || adminRec.username || '' };
        try { await window.emailjs.send('default_service', 'template_2fa', templateParams); console.debug('2FA email sent via EmailJS'); } catch (e) { console.debug('EmailJS send failed', e); }
      }
    } catch (e) { console.debug('2FA email send error', e); }

    // Redirect to verification page where user must enter the code
    window.location.href = 'verify_2fa.html';
    return;
  } catch (err) {
    console.error('adminLogin (2FA) error', err);
    try { await signOut(auth); } catch(e){}
    throw err;
  }
}

// Verify a 2FA code for the currently signed-in user.
export async function verify2FACode(code) {
  const user = auth.currentUser;
  if (!user) throw new Error('No authenticated user to verify');
  const snap = await get(ref(db, `admins/${user.uid}/pending2fa`));
  if (!snap.exists()) throw new Error('No pending verification found');
  const pending = snap.val() || {};
  if (Date.now() > (pending.expiresAt || 0)) {
    // cleanup
    await update(ref(db, `admins/${user.uid}`), { pending2fa: null });
    throw new Error('Verification code expired');
  }
  if ((pending.code || '').toString() !== code.toString()) throw new Error('Invalid verification code');

  // success: mark verified and remove pending code
  await update(ref(db, `admins/${user.uid}`), { twoFactorVerified: true, pending2fa: null, last2FAVerifiedAt: Date.now() });
  return true;
}

// Resend a new 2FA code for the currently signed-in user.
export async function resend2FACode() {
  const user = auth.currentUser;
  if (!user) throw new Error('No authenticated user');
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + (5 * 60 * 1000);
  await update(ref(db, `admins/${user.uid}`), { pending2fa: { code, expiresAt, issuedAt: Date.now() }, twoFactorVerified: false });
  try {
    if (window.emailjs && typeof window.emailjs.send === 'function') {
      const snap = await get(ref(db, `admins/${user.uid}`));
      const adminRec = snap && snap.exists() ? snap.val() : {};
      const templateParams = { to_email: user.email || adminRec.email || '', code: code, to_name: adminRec.fullname || adminRec.username || '' };
      try { await window.emailjs.send('default_service', 'template_2fa', templateParams); } catch(e) { console.debug('EmailJS resend failed', e); }
    }
  } catch (e) { console.debug('resend2FACode error', e); }
  return true;
}

export async function signOutUser() {
  try {
    await signOut(auth);
  } catch (err) {
    console.error('signOutUser error', err);
  }
}

// Expose a helper globally so non-module scripts can call logout safely
window.signOutUser = signOutUser;
window.auth = auth;
window.signOut = signOut;
window.db = db;

// Helper that signs out (if possible) and redirects to login.html
window.signOutAndRedirect = async function() {
  try {
    if (typeof window.signOutUser === 'function') {
      await window.signOutUser();
    } else if (window.auth && typeof window.signOut === 'function') {
      await window.signOut(window.auth);
    }
  } catch (err) {
    console.error('signOutAndRedirect error', err);
  } finally {
    try { localStorage.removeItem('authToken'); } catch(e){}
    window.location.href = 'login.html';
  }
};

// Redirect helper: if the user is already authenticated and an admin, redirect away from signin/login pages
export function redirectIfAuthenticated() {
  onAuthStateChanged(auth, async (user) => {
    if (!user) return;
    try {
      const ok = await isAdminUid(user.uid);
      if (ok) {
        window.location.href = 'admin_dashboard.html';
      }
    } catch (err) {
      console.error('redirectIfAuthenticated error', err);
    }
  });
}

// Require admin auth on protected pages; redirects to signin if not authorized
export function requireAdminAuth() {
  onAuthStateChanged(auth, async (user) => {
    if (!user) {
      window.location.href = 'login.html';
      return;
    }
    try {
      const ok = await isAdminUid(user.uid);
      if (!ok) {
        try { await signOut(auth); } catch(e){}
        window.location.href = 'login.html';
      }
      // If admin record requires 2FA, ensure they're verified in DB before allowing access
      try {
        const snap = await get(ref(db, `admins/${user.uid}`));
        const rec = snap && snap.exists() ? snap.val() : {};
        const twoFactor = !!(rec.twoFactor || rec.twoFactorEnabled);
        const verified = !!rec.twoFactorVerified;
        if (twoFactor && !verified) {
          // redirect to 2FA verification page
          window.location.href = 'verify_2fa.html';
        }
        return;
      } catch (e) { /* continue as normal if DB lookup fails */ }
    } catch (err) {
      console.error('requireAdminAuth error', err);
      try { await signOut(auth); } catch(e){}
      window.location.href = 'login.html';
    }
  });
}

// -----------------------------
// Theme handling (global)
// -----------------------------
const THEME_KEY = 'safespace_theme';

function safeGetTheme() {
  try { return localStorage.getItem(THEME_KEY) || 'system'; } catch (e) { return 'system'; }
}

function safeSetTheme(theme) {
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
}

function applyTheme(theme) {
  if (!theme || theme === 'system') {
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
  } else {
    document.documentElement.setAttribute('data-theme', theme === 'dark' ? 'dark' : 'light');
  }
}

export function setTheme(theme) {
  safeSetTheme(theme);
  applyTheme(theme);
}

export function getTheme() {
  return safeGetTheme();
}

export function initTheme() {
  const t = safeGetTheme();
  applyTheme(t);
}

// Listen for system preference changes and update when user selected 'system'
try {
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const mqHandler = () => {
    if (safeGetTheme() === 'system') applyTheme('system');
  };
  if (mq.addEventListener) mq.addEventListener('change', mqHandler);
  else if (mq.addListener) mq.addListener(mqHandler);
} catch (e) { /* no-op */ }

// Initialize immediately on module import so every page respects stored choice
try { initTheme(); } catch (e) { console.error('initTheme error', e); }

// Make setTheme accessible to non-module scripts
window.setTheme = setTheme;

// -----------------------------
// Global notification helpers
// -----------------------------
function renderNotificationItem(n) {
  const ts = n && n.ts ? fmtTime(n.ts) : '';
  const title = n && n.title ? n.title : (n && n.head ? n.head : 'Notification');
  const body = n && n.body ? n.body : (n && n.msg ? n.msg : '');
  const id = n && n.id ? n.id : (n && n._id ? n._id : null);
  const isUnread = !(n && n.read);
  const el = document.createElement('div');
  el.className = 'notif-item' + (isUnread ? ' unread' : '');
  // Visual style: unread items highlighted (like Facebook) and clickable
  el.style = 'padding:10px;border-bottom:1px solid #eee;font-size:13px;cursor:pointer;display:block;';
  if (isUnread) el.style.background = '#eefdf3';
  el.setAttribute('role','button');
  el.setAttribute('tabindex','0');
  el.setAttribute('data-notif-id', id || '');

  // Dot indicator (left) + content container
  const row = document.createElement('div');
  row.style = 'display:flex;align-items:flex-start;gap:10px;';

  const dot = document.createElement('span');
  dot.className = 'notif-dot';
  dot.setAttribute('aria-hidden','true');
  dot.style.cssText = 'flex:0 0 10px;height:10px;width:10px;border-radius:999px;margin-top:6px;transition:transform .28s ease,opacity .28s ease,background-color .28s ease;';
  if (isUnread) { dot.style.backgroundColor = '#ef4444'; dot.style.opacity = '1'; }
  else { dot.style.backgroundColor = '#cbd5e1'; dot.style.opacity = '0.7'; }

  const content = document.createElement('div');
  content.style = 'flex:1;min-width:0';
  content.innerHTML = `<div style="font-weight:${isUnread?700:600};color:#0f172a">${escapeHtml(title)}</div><div style="color:#374151;margin-top:4px">${escapeHtml(body)}</div><div style="font-size:11px;color:#8b8b8b;margin-top:6px">${escapeHtml(ts)}</div>`;

  row.appendChild(dot);
  row.appendChild(content);
  el.appendChild(row);

  // Click handler: mark as read and optionally navigate if the notification contains a link
  el.addEventListener('click', async function(evt){
    try{
      // mark as read immediately in UI
      if (isUnread) {
        el.classList.remove('unread');
        el.style.background = 'transparent';
        try{
          dot.style.transform = 'scale(0.2)';
          dot.style.opacity = '0';
          setTimeout(()=>{
            try{
              const check = document.createElement('span');
              check.className = 'notif-check';
              check.setAttribute('aria-hidden','true');
              check.innerHTML = '✓';
              check.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:#10b981;color:#fff;font-size:12px;transform:scale(0.6);opacity:0;transition:transform .28s ease,opacity .28s ease;';
              dot.replaceWith(check);
              setTimeout(()=>{ try{ check.style.transform = 'scale(1)'; check.style.opacity = '1'; }catch(e){} }, 20);
            }catch(e){}
          }, 300);
        }catch(e){ }
      }

      // Persist read state to DB for authenticated user
      try{
        const user = auth.currentUser;
        if (user && id) {
          await update(ref(db, `notifications/${user.uid}/${id}`), { read: true });
        }
      }catch(e){ console.debug('mark notif read err', e); }

      // Determine where to navigate/open for this notification.
      try {
        // Prefer explicit path/link/url provided by the notification payload
        let href = (n && (n.link || n.url || n.path)) ? (n.link || n.url || n.path) : null;

        // Lowercase title for pattern checks
        const titleLower = (n && (n.title || '')).toString().toLowerCase();
        const isNewReportsHeader = titleLower.indexOf('new reports submitted') === 0;

        // If this is a 'New Reports Submitted' notification (group or per-report),
        // navigate to the reports page and apply the `filter=new` query parameter.
        if (isNewReportsHeader) {
          const link = 'admin_report_management.html?filter=new';
          if (n && n.target === '_blank') window.open(link, '_blank'); else window.location.href = link;
          return;
        }

        // If no explicit href, but we have a reportId, navigate to the reports page for that report
        const rid = (n && (n.reportId || n.reportID || n.report_id)) ? (n.reportId || n.reportID || n.report_id) : null;
        if (!href && rid) {
          href = 'admin_report_management.html?report=' + encodeURIComponent(rid);
        }

        // If still no href, try to derive a sensible link
        if (!href) {
          try { href = deriveNotificationLink(n); } catch(e) { href = null; }
        }

        // If we're already on the reports page and a view-in-place function exists, prefer it
        if (rid && (window.location.pathname && window.location.pathname.toLowerCase().includes('admin_report_management.html'))) {
          if (typeof window.viewReport === 'function') {
            try { window.viewReport(rid); return; } catch(e) { /* fallback to navigation below */ }
          }
        }

        if (href) {
          if (n && n.target === '_blank') window.open(href, '_blank'); else window.location.href = href;
        }
      } catch(e){ console.debug('notif navigation error', e); }
    }catch(e){ console.debug('notif click handler', e); }
  });

  // Keyboard support: Enter/Space to activate
  el.addEventListener('keydown', function(ev){ if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); el.click(); } });

  return el;
}

function escapeHtml(str){ if (str == null) return ''; return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Show an optimistic (temporary) notification in any open popover immediately.
// Payload: { title, body, ts, path, typeLabel }
export function showOptimisticNotification(payload){
  try{
    const { title='Notification', body='', ts=Date.now(), path='', typeLabel='Notice' } = payload || {};
    const lists = Array.from(document.querySelectorAll('#notifList'));
    const tsNow = ts || Date.now();
    for (const list of lists){
      try{
        const el = document.createElement('div');
        el.className = 'notif-item unread';
        el.setAttribute('data-temp','true');
        if (payload && payload.reportId) el.setAttribute('data-report-id', String(payload.reportId));
        el.style.cssText = 'padding:10px;border-bottom:1px solid #eee;font-size:13px;cursor:pointer;display:block;background:#eefdf3;';
        const safeTitle = escapeHtml(title);
        const safeBody = escapeHtml(body);
        const safeType = escapeHtml(typeLabel || 'Notice');
        el.innerHTML = `<div style="display:flex;align-items:flex-start;gap:10px;"><span style=\"flex:0 0 10px;height:10px;width:10px;border-radius:999px;margin-top:6px;background:#ef4444;\"></span><div style=\"flex:1;min-width:0\"><div style=\"display:flex;align-items:center;gap:8px;flex-wrap:wrap\"><span style=\"display:inline-block;background:#f1f5f9;color:#0f172a;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid rgba(15,23,42,0.04)\">${safeType}</span><div style=\"font-weight:700;color:#0f172a\">${safeTitle}</div></div><div style=\"color:#374151;margin-top:6px\">${safeBody}</div><div style=\"font-size:11px;color:#8b8b8b;margin-top:6px\">${new Date(tsNow).toLocaleString()}</div></div></div>`;
        // Click handler for optimistic items: mark locally read, update badge, then open/navigate
        el.addEventListener('click', function(){
          try {
            // visually mark as read
            if (el.classList.contains('unread')) {
              el.classList.remove('unread');
              el.style.background = 'transparent';
              try {
                const dotLocal = el.querySelector('span');
                if (dotLocal) {
                  dotLocal.style.transform = 'scale(0.2)';
                  dotLocal.style.opacity = '0';
                  setTimeout(()=>{
                    try{
                      const check = document.createElement('span');
                      check.className = 'notif-check';
                      check.setAttribute('aria-hidden','true');
                      check.innerHTML = '✓';
                      check.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:#10b981;color:#fff;font-size:12px;transform:scale(0.6);opacity:0;transition:transform .28s ease,opacity .28s ease;';
                      try { dotLocal.replaceWith(check); } catch(e){}
                      setTimeout(()=>{ try{ check.style.transform = 'scale(1)'; check.style.opacity = '1'; }catch(e){} }, 20);
                    }catch(e){}
                  }, 200);
                }
              } catch(e){}
            }

            // decrement optimistic counter and refresh combined badge
            try { window._optimisticNotifCount = Math.max(0, (window._optimisticNotifCount || 0) - 1); } catch(e){}
            try { updateUnreadBadgeFromNotifs(window._lastNotifs || null); } catch(e){}

            // If this optimistic payload represents new reports group, open filtered view
            try {
              const titleLower = (payload && (payload.title || '')).toString().toLowerCase();
              if (titleLower.indexOf('new reports submitted') === 0) {
                try { window.location.href = 'admin_report_management.html?filter=new'; return; } catch(e){}
              }
            } catch(e) {}

            // navigate / open in-place
            if (path && window.location.pathname && window.location.pathname.toLowerCase().includes('admin_report_management.html')) {
              if (typeof window.viewReport === 'function' && payload && payload.reportId) { try { window.viewReport(payload.reportId); return; } catch(e){} }
            }
            if (path) {
              try { window.location.href = path; } catch(e){}
            }
          } catch(e) { console.debug('optimistic notif click err', e); }
        });
        try{ list.insertBefore(el, list.firstChild); } catch(e){ list.appendChild(el); }
        try { window._optimisticNotifCount = (window._optimisticNotifCount || 0) + 1; } catch(e){}
      }catch(e){ console.debug('showOptimisticNotification error', e); }
    }

    // Refresh combined badge (DB unread + optimistic)
    try { updateUnreadBadgeFromNotifs(window._lastNotifs || null); } catch(e) { console.debug('refresh combined badge failed', e); }
  }catch(e){ console.debug('showOptimisticNotification top error', e); }
}

// Expose globally so pages can dispatch optimistic notifications
window.showOptimisticNotification = showOptimisticNotification;
// Allow pages to dispatch a CustomEvent 'optimistic-notif' with detail={...}
window.addEventListener('optimistic-notif', function(ev){ try{ showOptimisticNotification(ev && ev.detail ? ev.detail : {}); }catch(e){console.debug('optimistic-notif handler err', e);} });

// Track optimistic notifications shown locally (not yet backed by DB)
try { if (typeof window !== 'undefined') window._optimisticNotifCount = window._optimisticNotifCount || 0; } catch(e) {}


function updateAllNotifLists(notifsObj){
  try {
    // Normalize into array newest-first
    const items = [];
    if (!notifsObj) { /* clear */ }
    else if (Array.isArray(notifsObj)) { for (const n of notifsObj) if (n) items.push(n); }
    else if (typeof notifsObj === 'object') { for (const k of Object.keys(notifsObj)) { const n = notifsObj[k]; if (n) items.push(Object.assign({ id: k }, n)); } }
    items.sort((a,b)=> (b.ts||0) - (a.ts||0));
    const lists = document.querySelectorAll('#notifList');
    // Only surface notifications that relate to submitted reports.
    function isReportNotification(n){
      try{
        if (!n) return false;
        if (n.reportId) return true;
        const txt = ((n.title||'') + ' ' + (n.body||n.msg||'' )).toString().toLowerCase();
        return /\breport\b/.test(txt) || /new report/i.test(txt);
      }catch(e){ return false; }
    }

    lists.forEach(list => {
      // Preserve any existing optimistic/temp notification elements so they
      // don't vanish when we re-render the authoritative DB-backed list.
      const preservedTemps = Array.from(list.querySelectorAll('[data-temp="true"]')).map(e => e.cloneNode(true));
      // Constrain notification popovers to a short height and enable vertical scrolling
      try { list.style.maxHeight = '260px'; list.style.overflowY = 'auto'; list.style.overflowX = 'hidden'; } catch(e) {}
      list.innerHTML = '';
      if (!items.length) {
        // If we have optimistic temp items, show them instead of the empty placeholder
        if (preservedTemps && preservedTemps.length) {
          try { for (const t of preservedTemps) list.appendChild(t); } catch(e){}
        } else {
          list.innerHTML = '<div class="popover-empty">No new notifications.</div>';
        }
        return;
      }
      // Group notifications: we only show report-related notifications.
      try {
        const visible = items.filter(isReportNotification).slice(0,20);
        const newReports = visible.slice();
        const others = [];

        if (newReports.length) {
          const unreadNewCount = newReports.filter(n => !(n && n.read)).length;
          // Construct a synthetic notification payload and render it using the same
          // renderer so the header matches other notification items exactly.
          const headerPayload = {
            title: `New Reports Submitted (${newReports.length})${unreadNewCount ? ' — ' + unreadNewCount + ' unread' : ''}`,
            body: 'Click to view new reports',
            ts: Date.now(),
            // do not set an `id` so renderNotificationItem won't attempt to write a read flag
            read: unreadNewCount === 0
          };

          const hdr = renderNotificationItem(headerPayload);
          hdr.classList.add('notif-section');

          // Add pill badge on the right when there are unread new reports
          if (unreadNewCount) {
            try {
              const row = hdr.querySelector('div');
              const pill = document.createElement('span');
              pill.className = 'notif-section-pill';
              pill.setAttribute('aria-hidden','false');
              pill.style.cssText = 'margin-left:auto;display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;padding:0 8px;background:#10b981;color:#fff;border-radius:999px;font-size:12px;line-height:1;box-shadow:0 4px 10px rgba(0,0,0,0.08);font-weight:700';
              pill.textContent = String(unreadNewCount > 99 ? '99+' : unreadNewCount);
              if (row) row.appendChild(pill);
            } catch (e) { /* ignore pill append errors */ }
          }

          // Clicking the header should navigate to the reports management page with a filter
          hdr.addEventListener('click', function () { try { window.location.href = 'admin_report_management.html?filter=new'; } catch (e) { } });
          hdr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); try { window.location.href = 'admin_report_management.html?filter=new'; } catch (e) { } } });

          list.appendChild(hdr);
          for (const n of newReports) list.appendChild(renderNotificationItem(n));
          // After rendering authoritative new report items, re-insert any preserved optimistic items.
          // If a preserved temp corresponds to a DB-backed notification (same reportId), replace the temp
          // with the authoritative rendered node so the click/read behavior is consistent.
          try{
            const reportMap = new Map();
            for (const it of visible) {
              try {
                const rid = String((it && (it.reportId || it.id)) || '');
                if (rid) reportMap.set(rid, it);
              } catch(e) {}
            }
            for (const t of preservedTemps) {
              try{
                const rid = t.getAttribute && t.getAttribute('data-report-id') ? String(t.getAttribute('data-report-id')) : null;
                if (rid && reportMap.has(rid)) {
                  const real = reportMap.get(rid);
                  try { const rendered = renderNotificationItem(real); list.insertBefore(rendered, hdr.nextSibling); continue; } catch(e) { /* fallthrough to append temp */ }
                }
                list.insertBefore(t, hdr.nextSibling); // insert after header so temps appear in section
              }catch(e){}
            }
          }catch(e){}
        }

        if (others.length) {
          if (newReports.length) {
            // small separator
            const sep = document.createElement('div'); sep.style = 'height:8px;background:transparent'; list.appendChild(sep);
          }
          for (const n of others) list.appendChild(renderNotificationItem(n));
        }
      } catch(e) {
        // fallback to previous behavior
        for (const n of items.slice(0,20)) { list.appendChild(renderNotificationItem(n)); }
      }
      try {
        // Inject header controls (Mark all read / Clear) into the popover header if available
        const container = list.closest('.popover');
        if (container) {
          const header = container.querySelector('.popover-header');
          if (header && !header.querySelector('.notif-controls')) {
            const controls = document.createElement('div');
            controls.className = 'notif-controls';
            controls.style = 'display:inline-flex;gap:8px;float:right;margin-left:8px;';
            const markBtn = document.createElement('button');
            markBtn.textContent = 'Mark all read';
            markBtn.style = 'background:transparent;border:0;color:#2563eb;cursor:pointer;font-size:12px;padding:4px 6px;border-radius:6px';
            markBtn.addEventListener('click', async function(e){ e.preventDefault(); try { await markAllNotificationsRead(); showToast('All notifications marked read'); } catch(err){ console.debug('markAll read err', err); showToast('Unable to mark read'); } });
            const clearBtn = document.createElement('button');
            clearBtn.textContent = 'Clear';
            clearBtn.style = 'background:transparent;border:0;color:#ef4444;cursor:pointer;font-size:12px;padding:4px 6px;border-radius:6px';
            clearBtn.addEventListener('click', async function(e){ e.preventDefault(); if (!confirm('Clear all notifications?')) return; try { await clearAllNotifications(); showToast('Notifications cleared'); } catch(err){ console.debug('clear notif err', err); showToast('Unable to clear'); } });
            controls.appendChild(markBtn);
            controls.appendChild(clearBtn);
            header.appendChild(controls);
          }
        }
      } catch(e){ console.debug('inject notif controls', e); }
    });
  } catch (e) { console.debug('updateAllNotifLists', e); }
}

// Attempt to derive a likely page URL from a notification payload when no explicit link is provided.
function deriveNotificationLink(n) {
  if (!n) return null;
  // If the notification explicitly includes a path, use it.
  if (n.path) return n.path;
  // If it contains a studentId, prefer opening the user management page with that id.
  if (n.studentId) return 'admin_user_management.html?studentId=' + encodeURIComponent(n.studentId);
  const title = (n.title || '').toString().toLowerCase();
  const body = (n.body || n.msg || '').toString().toLowerCase();

  // Profile-related
  if (/profile/.test(title) || /profile/.test(body) || /password/.test(title) || /password/.test(body)) return 'admin_profile.html';

  // Content / file uploads
  if (/file|upload|link|conversion/.test(title) || /file|uploaded|upload/.test(body)) return 'admin_content_management.html';

  // Reports
  if (/report/.test(title) || /report/.test(body) || /exported/.test(body)) return 'admin_report_management.html';

  // Appointments / students
  if (/appointment/.test(title) || /appointment/.test(body) || /student/.test(body)) return 'admin_user_management.html';

  // Psych test / test results
  if (/test results|test result|results uploaded/.test(title) || /test result/.test(body)) return 'admin_psych_test.html';

  // Default: return null so no navigation occurs
  return null;
}

// Render recent activity cards/lists on pages that include `#recentActivity` or `.recent-activity`
function renderRecentActivityItem(n){
  const el = document.createElement('div');
  el.className = 'recent-activity-item';
  el.style = 'padding:12px;border-bottom:1px solid var(--ss-border, #eee);display:flex;align-items:flex-start;gap:10px;font-size:13px;color:var(--ss-text)';
  const t = n && n.ts ? fmtTime(n.ts) : '';
  const title = n && n.title ? n.title : (n && n.head ? n.head : 'Activity');
  const body = n && n.body ? n.body : (n && n.msg ? n.msg : '');
  // determine icon color class and glyph based on title/type or provided icon
  const typeHint = (n && (n.type || n.event || n.action)) || '';
  const hint = String(typeHint).toLowerCase();
  let iconClass = 'green';
  if (hint.indexOf('file') !== -1 || hint.indexOf('upload') !== -1) iconClass = 'blue';
  else if (hint.indexOf('login') !== -1) iconClass = 'purple';
  else if (hint.indexOf('student') !== -1) iconClass = 'teal';
  // prefer an explicit icon field if present, otherwise pick a glyph by type
  let glyph = (n && n.icon) ? n.icon : '';
  if (!glyph) {
    if (hint.indexOf('file') !== -1 || hint.indexOf('upload') !== -1) glyph = '📁';
    else if (hint.indexOf('login') !== -1) glyph = '🔒';
    else if (hint.indexOf('password') !== -1) glyph = '🔑';
    else if (hint.indexOf('profile') !== -1) glyph = '✏️';
    else glyph = '🔔';
  }
  el.innerHTML = `<div class="activity-icon ${iconClass}" style="flex:0 0 36px;height:36px;width:36px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:700">${escapeHtml(glyph)}</div><div style="flex:1"><div style=\"font-weight:600;color:var(--ss-text)\">${escapeHtml(title)}</div><div style=\"color:var(--ss-muted);margin-top:4px\">${escapeHtml(body)}</div><div style=\"font-size:11px;color:var(--ss-muted);margin-top:6px\">${escapeHtml(t)}</div></div>`;
  return el;
}

function updateAllRecentActivities(notifsObj){
  try{
    const containers = document.querySelectorAll('#recentActivity, .recent-activity');
    if (!containers || !containers.length) return;
    const items = [];
    if (!notifsObj) { /* none */ }
    else if (Array.isArray(notifsObj)) { for (const n of notifsObj) if (n) items.push(n); }
    else if (typeof notifsObj === 'object') { for (const k of Object.keys(notifsObj)) { const n = notifsObj[k]; if (n) items.push(Object.assign({ id: k }, n)); } }
    items.sort((a,b)=> (b.ts||0) - (a.ts||0));
    // Exclude notifications used only for the notifications panel (e.g. "New Reports Submitted")
    const recentItems = items.filter(n => {
      try {
        const t = (n && (n.title || '')).toString().toLowerCase();
        // Skip the synthetic/grouped notification header we use for new reports
        if (t.indexOf('new reports submitted') === 0) return false;
        return true;
      } catch (e) { return true; }
    });

    for (const c of containers){
      // Prefer a dedicated list element inside the container if available
      const target = c.querySelector('#activityList') || c.querySelector('.activity-list') || c;
      target.innerHTML = '';
      if (!recentItems.length) {
        // If client-side local recent-activity exists, prefer showing that instead
        // of the server placeholder to avoid duplicate/conflicting messages.
        try {
          const localRaw = (typeof localStorage !== 'undefined') ? localStorage.getItem('admin_recent_activity') : null;
          const localArr = localRaw ? JSON.parse(localRaw) : null;
          if (Array.isArray(localArr) && localArr.length > 0) {
            // leave target empty so client-side renderer can populate its local list
            continue;
          }
        } catch (e) {
          // If parsing fails, fall back to showing the placeholder
          console.debug('admin_main: local recent activity parse failed', e);
        }
        target.innerHTML = '<div style="padding:18px;color:var(--ss-muted)">No recent activity.</div>';
        continue;
      }
      const list = document.createElement('div');
      list.style = 'display:flex;flex-direction:column;gap:6px;';
      for (const n of recentItems.slice(0,10)) list.appendChild(renderRecentActivityItem(n));
      target.appendChild(list);
    }
  }catch(e){ console.debug('updateAllRecentActivities', e); }
}

// Helper: determine whether a notification is related to a submitted report
function isReportNotificationCandidate(n){
  try{
    if (!n) return false;
    if (n.reportId) return true;
    const text = ((n.title||'') + ' ' + (n.body||n.msg||'')).toString().toLowerCase();
    return /\breport\b/.test(text) || /new report/.test(text) || /report submitted/.test(text);
  }catch(e){ return false; }
}

// Count only report-related unread notifications for the badge
function computeUnreadCount(notifsObj){
  try{
    if (!notifsObj) return 0;
    let cnt = 0;
    if (Array.isArray(notifsObj)){
      for (const n of notifsObj) if (n && !n.read && isReportNotificationCandidate(n)) cnt++;
    } else if (typeof notifsObj === 'object'){
      for (const k of Object.keys(notifsObj)){
        const n = notifsObj[k]; if (n && !n.read && isReportNotificationCandidate(n)) cnt++;
      }
    }
    return cnt;
  }catch(e){ console.debug('computeUnreadCount', e); return 0; }
}

function ensureNotifBadgeElement(btn){
  if (!btn) return null;
  // look for existing badge
  let badge = btn.querySelector('.notif-badge');
  if (badge) return badge;
  // create
  badge = document.createElement('span');
  badge.className = 'notif-badge';
  badge.setAttribute('aria-hidden','false');
  badge.style.cssText = 'position:absolute;top:-6px;right:-6px;min-width:18px;height:18px;padding:0 6px;background:#ef4444;color:#fff;border-radius:999px;font-size:12px;display:inline-flex;align-items:center;justify-content:center;box-shadow:0 4px 10px rgba(0,0,0,0.12);line-height:1;';
  // ensure button is positioned relatively
  const computed = window.getComputedStyle(btn);
  if (computed.position === 'static' || !computed.position) btn.style.position = 'relative';
  btn.appendChild(badge);
  return badge;
}

function updateUnreadBadgeFromNotifs(notifsObj){
  try{
    const dbCount = computeUnreadCount(notifsObj);
    const optimistic = (typeof window !== 'undefined' && window._optimisticNotifCount) ? window._optimisticNotifCount : 0;
    const count = (dbCount || 0) + (optimistic || 0);
    // Find all notification buttons (ids or data attributes)
    const candidates = Array.from(document.querySelectorAll('#notifBtn, .notif-button, [data-notif-bell]'));
    if (!candidates.length){
      // fallback: find any element with 'notifications' icon text
      const btn = document.getElementById('notifBtn'); if (btn) candidates.push(btn);
    }
    for (const btn of candidates){
      try{
        const badge = ensureNotifBadgeElement(btn);
        if (!badge) continue;
        if (!count) { badge.style.display = 'none'; badge.textContent = ''; badge.setAttribute('aria-hidden','true'); }
        else { badge.style.display = 'inline-flex'; badge.textContent = String(count > 99 ? '99+' : count); badge.setAttribute('aria-hidden','false'); }
        // Manage small dot indicator on the bell (red when there are unread items)
        try {
          let dot = btn.querySelector('.notif-dot-bullet');
          if (!dot) {
            dot = document.createElement('span');
            dot.className = 'notif-dot-bullet';
            dot.style.cssText = 'position:absolute;top:6px;right:6px;width:10px;height:10px;border-radius:999px;background:#ef4444;box-shadow:0 6px 12px rgba(239,68,68,0.12);display:block;';
            btn.appendChild(dot);
          }
          if (!count) { dot.style.display = 'none'; dot.setAttribute('aria-hidden','true'); }
          else { dot.style.display = 'block'; dot.setAttribute('aria-hidden','false'); }
        } catch(e) { /* ignore dot errors */ }
      }catch(e){ console.debug('update badge per btn', e); }
    }
  }catch(e){ console.debug('updateUnreadBadgeFromNotifs', e); }
}

// Ensure a notification bell + popover exists on pages that don't include it
function ensureNotifUI() {
  try {
    // Honor page-level opt-out (e.g., login page should not show notifications)
    if (typeof window !== 'undefined' && window.SKIP_NOTIF_UI) return;
    if (document.getElementById('notifPanel') && document.getElementById('notifBtn')) return;

    // Create button wrapper in top-right if header isn't present
    if (!document.getElementById('notifBtn')) {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'position:fixed;right:16px;top:12px;z-index:99999;';
      const btn = document.createElement('button');
      btn.id = 'notifBtn';
      btn.className = 'icon-btn';
      btn.title = 'Notifications';
      btn.style.cssText = 'color:#fff;padding:8px;border:0;border-radius:8px;background:transparent;display:inline-flex;align-items:center;justify-content:center;';
      btn.innerHTML = '<i class="material-icons" style="color:#111;font-size:20px">notifications</i>';
      wrap.appendChild(btn);
      document.body.appendChild(wrap);
    }

    if (!document.getElementById('notifPanel')) {
      const panel = document.createElement('div');
      panel.id = 'notifPanel';
      panel.className = 'popover';
      panel.setAttribute('data-open','false');
      panel.style.cssText = 'position:fixed;right:20px;top:62px;min-width:280px;z-index:4500;display:none;';
      panel.innerHTML = `
        <div class="notif-card" role="dialog" aria-label="Notifications" aria-hidden="true" style="border-radius:10px;overflow:hidden;box-shadow:0 12px 30px rgba(2,6,23,0.08);background:#fff;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;min-width:280px;">
          <div class="notif-header popover-header" style="background:#10b981;color:#fff;padding:12px 14px;display:flex;align-items:center;justify-content:space-between;">
            <div class="notif-title" style="font-weight:700;font-size:15px;">Notifications</div>
          </div>
          <div id="notifList" class="popover-body" style="color:#111827;padding:8px 12px;max-height:320px;overflow:auto;">
            <div class="popover-empty">No new notifications.</div>
          </div>
        </div>
      `;
      document.body.appendChild(panel);
    }

    // Wire toggle behaviour between button and panel
    const btnEl = document.getElementById('notifBtn');
    const panelEl = document.getElementById('notifPanel');
    if (btnEl && panelEl && !btnEl._notifToggleAttached) {
      btnEl._notifToggleAttached = true;
      btnEl.addEventListener('click', (e)=>{
        e.preventDefault();
        const open = panelEl.getAttribute('data-open') === 'true';
        const nowOpen = !open;
        panelEl.setAttribute('data-open', nowOpen ? 'true' : 'false');
        panelEl.style.display = nowOpen ? 'block' : 'none';
        // If opening the panel, remove the visual highlight from the "New Reports Submitted" header
        if (nowOpen) {
          try {
            // header may be rendered as a synthetic notif item with class 'notif-section'
            const hdr = panelEl.querySelector('.notif-section') || panelEl.querySelector('.notif-item.section');
            if (hdr) {
              // remove unread visual highlighting
              hdr.classList.remove('unread');
              hdr.style.background = 'transparent';
              hdr.style.borderLeft = '';
              // reset title color if it was emphasized
              const titleEl = hdr.querySelector('div > div');
              if (titleEl) titleEl.style.color = '';
              // normalize the dot indicator
              const dot = hdr.querySelector('.notif-dot') || hdr.querySelector('span');
              if (dot) { dot.style.backgroundColor = '#cbd5e1'; dot.style.opacity = '0.7'; }
              // keep pill count visible but reduce emphasis by lowering opacity
              const pill = hdr.querySelector('.notif-section-pill'); if (pill) pill.style.opacity = '0.95';
            }
          } catch(e) { console.debug('clear header highlight', e); }

          // Also mark 'new report' notifications as read for the current user when they open the panel
          (async function markNewReportsRead(){
            try{
              const user = auth.currentUser;
              if (!user) return;
              const snap = await get(ref(db, `notifications/${user.uid}`));
              if (!snap.exists()) return;
              const data = snap.val() || {};
              const updates = [];
              for (const k of Object.keys(data)){
                const n = data[k] || {};
                if (n && n.reportId && !n.read) {
                  updates.push(update(ref(db, `notifications/${user.uid}/${k}`), { read: true }));
                }
              }
              if (updates.length) await Promise.all(updates);
            }catch(e){ console.debug('markNewReportsRead failed', e); }
          })();
        }
      });
      // Close panel when clicking outside
      document.addEventListener('click', (ev)=>{
        if (!panelEl || !btnEl) return;
        if (panelEl.getAttribute('data-open') !== 'true') return;
        const inside = ev.target.closest && (ev.target.closest('#notifPanel') || ev.target.closest('#notifBtn'));
        if (!inside) { panelEl.setAttribute('data-open','false'); panelEl.style.display='none'; }
      });
    }

  } catch (e) { console.debug('ensureNotifUI', e); }
}

// Run on DOMContentLoaded so pages without header get the notification UI
function _hideNotifTimestampGlobally(){
  try{
    // Inject CSS rule to hide any #notifTimestamp placed by pages
    const id = 'hide-notif-timestamp-style';
    if (!document.getElementById(id)){
      const s = document.createElement('style');
      s.id = id;
      s.textContent = '#notifTimestamp{display:none !important} .notif-timestamp{display:none !important} .notif-dot, .notif-dot-bullet { display: none !important; }';
      (document.head || document.documentElement).appendChild(s);
    }
    const el = document.getElementById('notifTimestamp'); if (el) el.style.display = 'none';
  }catch(e){/* no-op */}
}

if (typeof window !== 'undefined') {
  if (typeof window.SKIP_NOTIF_UI !== 'undefined' && window.SKIP_NOTIF_UI) {
    // Still hide any timestamp elements even if the page opted-out of notif UI
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _hideNotifTimestampGlobally);
    else _hideNotifTimestampGlobally();
  } else {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ()=>{ ensureNotifUI(); _hideNotifTimestampGlobally(); });
    else { ensureNotifUI(); _hideNotifTimestampGlobally(); }
  }
}

// Mark all notifications as read for current authenticated user
export async function markAllNotificationsRead() {
  const user = auth.currentUser;
  if (!user) throw new Error('Not authenticated');
  const snap = await get(ref(db, `notifications/${user.uid}`));
  if (!snap.exists()) return;
  const val = snap.val();
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i++) {
      if (val[i]) {
        try { await update(ref(db, `notifications/${user.uid}/${i}`), { read: true }); } catch(e){ console.debug('mark read item', e); }
      }
    }
  } else {
    for (const k of Object.keys(val)) {
      try { await update(ref(db, `notifications/${user.uid}/${k}`), { read: true }); } catch(e){ console.debug('mark read item', e); }
    }
  }
}

// Clear (remove) all notifications for current authenticated user
export async function clearAllNotifications() {
  const user = auth.currentUser;
  if (!user) throw new Error('Not authenticated');
  await remove(ref(db, `notifications/${user.uid}`));
}

// Expose to window for non-module pages
window.markAllNotificationsRead = markAllNotificationsRead;
window.clearAllNotifications = clearAllNotifications;

// Toast helper (small top-right toasts)
function ensureToastContainer(){
  let c = document.getElementById('globalToastContainer');
  if (c) return c;
  c = document.createElement('div');
  c.id = 'globalToastContainer';
  c.style = 'position:fixed;top:18px;right:18px;z-index:99999;display:flex;flex-direction:column;gap:8px;max-width:320px';
  document.body.appendChild(c);
  return c;
}

function showToast(message, opts={type:'info',timeout:4000}){
  try{
    if (window.DISABLE_TOASTS) return null;
    const c = ensureToastContainer();
    const t = document.createElement('div');
    t.style = 'background:#111827;color:#fff;padding:10px 12px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.12);font-size:13px';
    t.textContent = message;
    c.appendChild(t);
    setTimeout(()=>{ try{ t.style.opacity='0'; t.style.transform='translateY(-6px)'; setTimeout(()=>t.remove(),300); }catch(e){} }, opts.timeout||4000);
    return t;
  }catch(e){ console.debug('showToast', e); }
}

// Disable toasts globally by default to keep UI clean; pages can opt-in by setting
// `window.DISABLE_TOASTS = false` before importing/using the scripts.
try{ window.DISABLE_TOASTS = true; } catch(e){}

// Allow pages to push a notification programmatically
function pushNotification(n){
  try{
    // n: { title, body, ts }
    updateAllNotifLists([n].concat([]));
    // Respect a silent flag on the notification to avoid popping a toast
    if (!(n && n.silent)) {
      showToast((n && n.body) ? n.body : ((n && n.msg) ? n.msg : (n && n.title ? n.title : '')),{timeout:5000});
    }
  }catch(e){ console.debug('pushNotification', e); }
}

// Expose globally
window.pushNotification = pushNotification;
window.showToast = showToast;

// -----------------------------
// Remember trusted device helpers
// -----------------------------
const DEVICE_TOKEN_KEY = 'safespace_device_token';

export function getDeviceToken() {
  try { return localStorage.getItem(DEVICE_TOKEN_KEY); } catch (e) { return null; }
}

export function clearDeviceToken() {
  try { localStorage.removeItem(DEVICE_TOKEN_KEY); } catch (e) { /* ignore */ }
}

// Create a device token and persist it both locally and in DB under admins/{uid}/trustedDevices/{token}
export async function rememberCurrentDevice(uid, opts = {}) {
  if (!uid) throw new Error('Missing uid');
  const days = parseInt(opts.days || 30, 10) || 30;
  const label = opts.label || (typeof navigator !== 'undefined' ? (navigator.userAgent || 'Unknown device') : 'Unknown device');
  // generate a reasonably-random token
  const raw = (Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 12));
  const token = raw;
  const expiresAt = Date.now() + (days * 24 * 60 * 60 * 1000);
  // store in DB
  try {
    await set(ref(db, `admins/${uid}/trustedDevices/${token}`), { label: label, ts: Date.now(), expiresAt: expiresAt });
    try { localStorage.setItem(DEVICE_TOKEN_KEY, token); } catch(e){}
    return token;
  } catch (e) {
    console.error('rememberCurrentDevice error', e);
    throw e;
  }
}

// Remove a trusted device entry from DB and localStorage
export async function forgetCurrentDevice(uid) {
  try {
    const token = getDeviceToken();
    if (!token) return;
    await remove(ref(db, `admins/${uid}/trustedDevices/${token}`));
    clearDeviceToken();
  } catch(e) { console.debug('forgetCurrentDevice', e); }
}

// Expose device helpers globally for non-module pages
window.getDeviceToken = getDeviceToken;
window.rememberCurrentDevice = rememberCurrentDevice;
window.forgetCurrentDevice = forgetCurrentDevice;

// When an admin signs in, listen to their notifications path and update UI automatically
try{
  onAuthStateChanged(auth, async (user)=>{
    if (!user) return;
    try{
      const userNotifRef = ref(db, `notifications/${user.uid}`);
      onValue(userNotifRef, (snap)=>{
        const val = snap.exists() ? snap.val() : null;
          // remember latest DB snapshot so optimistic badge logic can combine counts
          try { window._lastNotifs = val; } catch(e){}
          updateAllNotifLists(val);
          try { updateUnreadBadgeFromNotifs(val); } catch(e){ console.debug('updateUnreadBadgeFromNotifs', e); }
        try { updateAllRecentActivities(val); } catch(e){ /* ignore */ }
        // If there are new items, show a brief toast for the most recent
        try{
          const arr = [];
          if (val) {
            if (Array.isArray(val)) arr.push(...val.filter(Boolean));
            else for (const k of Object.keys(val)) arr.push(Object.assign({id:k}, val[k]));
          }
          arr.sort((a,b)=> (b.ts||0)-(a.ts||0));
          if (arr.length) {
                  const latest = arr[0];
                  // Prefer showing the body/msg only in the toast; fall back to title if no body/msg exists
                  // Skip toasting if the notification is marked silent
                  if (!latest.silent) {
                    showToast(latest.body || latest.msg || latest.title || '', {timeout:3500});
                  }
          }
        }catch(e){ }
      });
    }catch(e){ console.debug('notification listener error', e); }
  });
}catch(e){ console.debug('setup notif listener error', e); }



