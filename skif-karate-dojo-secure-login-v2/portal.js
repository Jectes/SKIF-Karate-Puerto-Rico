let createClient = null;

const SUPABASE_BROWSER_SDK = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.112.3/dist/umd/supabase.js';

function loadSupabaseBrowserSdk() {
  if (window.supabase?.createClient) return Promise.resolve(window.supabase.createClient);

  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-supabase-browser-sdk]');
    if (existing) {
      existing.addEventListener('load', () => {
        if (window.supabase?.createClient) resolve(window.supabase.createClient);
        else reject(new Error('Supabase browser client did not initialize.'));
      }, { once: true });
      existing.addEventListener('error', () => reject(new Error('Supabase browser client failed to load.')), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.src = SUPABASE_BROWSER_SDK;
    script.async = true;
    script.crossOrigin = 'anonymous';
    script.referrerPolicy = 'no-referrer';
    script.dataset.supabaseBrowserSdk = 'true';
    script.addEventListener('load', () => {
      if (window.supabase?.createClient) resolve(window.supabase.createClient);
      else reject(new Error('Supabase browser client did not initialize.'));
    }, { once: true });
    script.addEventListener('error', () => reject(new Error('Supabase browser client failed to load.')), { once: true });
    document.head.append(script);
  });
}

const config = window.SKIF_CONFIG || {};
const authSecurity = window.SKIFAuthSecurity;
const TURNSTILE_SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const captchaState = { scriptPromise: null, widgets: new Map(), tokens: new Map() };
let idleTimer = null;
let lastActivityWrite = 0;

function isAllowedApiUrl(value) {
  if (typeof value !== 'string' || value.includes('YOUR_')) return false;
  try {
    const url = new URL(value);
    const localHost = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
    return url.protocol === 'https:' || (localHost && url.protocol === 'http:');
  } catch {
    return false;
  }
}

const isConfigured = Boolean(
  isAllowedApiUrl(config.supabaseUrl) &&
  typeof config.supabasePublishableKey === 'string' &&
  config.supabasePublishableKey.length > 20 &&
  !config.supabasePublishableKey.includes('YOUR_')
);


function safeBoolean(value, fallback = false) {
  return typeof value === 'boolean' ? value : fallback;
}

function normalizeEmail(value) {
  return authSecurity?.normalizeEmail ? authSecurity.normalizeEmail(value) : String(value || '').trim().toLowerCase().slice(0, 254);
}

function normalizeDisplayName(value) {
  return authSecurity?.normalizeDisplayName ? authSecurity.normalizeDisplayName(value) : String(value || '').trim().replace(/\s+/g, ' ').slice(0, 120);
}

function isValidEmail(value) {
  return authSecurity?.isValidEmail ? authSecurity.isValidEmail(value) : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(value));
}

function passwordPolicy() {
  return authSecurity?.getPolicy
    ? authSecurity.getPolicy(config)
    : { minimumLength: Number(config.passwordMinimumLength) || 15, maximumLength: Number(config.passwordMaximumLength) || 128 };
}

function passwordContextForForm(form) {
  return {
    email: normalizeEmail(form?.elements?.email?.value || state.user?.email || ''),
    fullName: normalizeDisplayName(
      form?.elements?.fullName?.value
      || state.profile?.full_name
      || state.user?.user_metadata?.full_name
      || '',
    ),
  };
}

function updatePasswordFeedback(form) {
  if (!form || !authSecurity?.evaluatePassword) return null;
  const passwordInput = form.querySelector('[name="password"]');
  if (!passwordInput) return null;
  const result = authSecurity.evaluatePassword(passwordInput.value, passwordContextForForm(form), config);
  const hasValue = passwordInput.value.length > 0;
  const progress = form.querySelector('[data-password-progress]');
  const label = form.querySelector('[data-password-label]');
  if (progress) {
    progress.value = result.score;
    progress.dataset.strength = String(result.score);
    progress.textContent = `${result.score} of 4`;
  }
  if (label) label.textContent = result.label;
  form.querySelectorAll('[data-password-rule]').forEach((item) => {
    const rule = result.rules.find((candidate) => candidate.key === item.dataset.passwordRule);
    if (!rule) return;
    item.textContent = rule.label;
    if (hasValue) item.dataset.met = String(rule.met);
    else delete item.dataset.met;
  });

  const confirmInput = form.querySelector('[name="confirmPassword"]');
  const matchStatus = form.querySelector('[data-password-match]');
  if (confirmInput && matchStatus) {
    const matches = hasValue && confirmInput.value.length > 0 && passwordInput.value === confirmInput.value;
    matchStatus.textContent = confirmInput.value.length ? (matches ? 'Passwords match.' : 'Passwords do not match.') : '';
    matchStatus.classList.toggle('is-match', matches);
    matchStatus.classList.toggle('is-mismatch', confirmInput.value.length > 0 && !matches);
    confirmInput.setAttribute('aria-invalid', String(confirmInput.value.length > 0 && !matches));
  }
  passwordInput.setAttribute('aria-invalid', String(hasValue && !result.valid));
  return result;
}

function wirePasswordVisibility(scope = document) {
  scope.querySelectorAll('[data-toggle-password]:not([data-wired])').forEach((button) => {
    button.dataset.wired = 'true';
    button.addEventListener('click', () => {
      const input = button.closest('.password-input-wrap')?.querySelector('input');
      if (!input) return;
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      button.textContent = showing ? 'Show' : 'Hide';
      button.setAttribute('aria-pressed', String(!showing));
      input.focus({ preventScroll: true });
    });
  });
}

function wireCapsLock(scope = document) {
  scope.querySelectorAll('input[type="password"]:not([data-caps-wired]), input[data-password-input]:not([data-caps-wired])').forEach((input) => {
    input.dataset.capsWired = 'true';
    const warning = input.closest('label')?.querySelector('[data-caps-lock]');
    if (!warning) return;
    const update = (event) => { warning.hidden = !event.getModifierState?.('CapsLock'); };
    input.addEventListener('keydown', update);
    input.addEventListener('keyup', update);
    input.addEventListener('blur', () => { warning.hidden = true; });
  });
}

function wirePasswordForm(form) {
  if (!form || form.dataset.passwordWired === 'true') return;
  form.dataset.passwordWired = 'true';
  const policy = passwordPolicy();
  const passwordInput = form.querySelector('[name="password"]');
  const confirmInput = form.querySelector('[name="confirmPassword"]');
  if (passwordInput) {
    passwordInput.minLength = policy.minimumLength;
    passwordInput.maxLength = policy.maximumLength;
  }
  if (confirmInput) {
    confirmInput.minLength = policy.minimumLength;
    confirmInput.maxLength = policy.maximumLength;
  }
  [passwordInput, confirmInput, form.elements?.email, form.elements?.fullName]
    .filter(Boolean)
    .forEach((input) => input.addEventListener('input', () => updatePasswordFeedback(form)));
  wirePasswordVisibility(form);
  wireCapsLock(form);
  updatePasswordFeedback(form);
}

function validateNewPasswordForm(form) {
  const passwordInput = form?.querySelector('[name="password"]');
  const confirmInput = form?.querySelector('[name="confirmPassword"]');
  if (!passwordInput || !authSecurity?.evaluatePassword) {
    return { valid: false, message: 'Password security controls did not load.' };
  }
  const result = updatePasswordFeedback(form) || authSecurity.evaluatePassword(passwordInput.value, passwordContextForForm(form), config);
  if (!result.valid) return { valid: false, message: `Password requirement not met: ${result.firstFailure}.` };
  if (confirmInput && passwordInput.value !== confirmInput.value) return { valid: false, message: 'The passwords do not match.' };
  return { valid: true, password: result.password, result };
}

function configureAuthMethodVisibility() {
  const googleButton = document.querySelector('[data-google-login]');
  const passkeyButton = document.querySelector('[data-passkey-login]');
  const signupButtons = document.querySelectorAll('[data-show-signup]');
  const googleEnabled = safeBoolean(config.googleOAuthEnabled, false);
  const passkeyEnabled = safeBoolean(config.passkeysEnabled, false)
    && Boolean(window.PublicKeyCredential && navigator.credentials)
    && Boolean(state.supabase?.auth?.signInWithPasskey);
  if (googleButton) googleButton.hidden = !googleEnabled;
  if (passkeyButton) passkeyButton.hidden = !passkeyEnabled;
  signupButtons.forEach((button) => { button.hidden = !safeBoolean(config.selfRegistrationEnabled, true); });
  const socialShell = document.querySelector('[data-social-auth]');
  if (socialShell) socialShell.hidden = !(googleEnabled || passkeyEnabled);
}

function authRedirectUrl(type = '') {
  const url = new URL(window.location.href);
  url.search = '';
  url.hash = '';
  if (type) url.searchParams.set('type', type);
  return url.toString();
}

function captchaEnabled() {
  return typeof config.turnstileSiteKey === 'string' && config.turnstileSiteKey.trim().length > 10;
}

function loadTurnstile() {
  if (!captchaEnabled()) return Promise.resolve(null);
  if (window.turnstile?.render) return Promise.resolve(window.turnstile);
  if (captchaState.scriptPromise) return captchaState.scriptPromise;
  captchaState.scriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = TURNSTILE_SCRIPT;
    script.async = true;
    script.defer = true;
    script.referrerPolicy = 'no-referrer';
    script.addEventListener('load', () => window.turnstile?.render ? resolve(window.turnstile) : reject(new Error('Security check did not initialize.')), { once: true });
    script.addEventListener('error', () => reject(new Error('Security check could not load.')), { once: true });
    document.head.append(script);
  });
  return captchaState.scriptPromise;
}

async function renderCaptchaForView(viewName) {
  if (!captchaEnabled()) return;
  const view = document.querySelector(`[data-auth-view="${CSS.escape(viewName)}"]`);
  const slot = view?.querySelector('[data-captcha-slot]');
  if (!slot) return;
  slot.hidden = false;
  const action = slot.dataset.captchaSlot;
  if (captchaState.widgets.has(action)) return;
  const turnstile = await loadTurnstile();
  const widgetId = turnstile.render(slot, {
    sitekey: config.turnstileSiteKey.trim(),
    theme: 'light',
    action: `dojo_${action}`,
    callback: (token) => captchaState.tokens.set(action, token),
    'expired-callback': () => captchaState.tokens.delete(action),
    'error-callback': () => captchaState.tokens.delete(action),
  });
  captchaState.widgets.set(action, widgetId);
}

function requireCaptchaToken(action) {
  if (!captchaEnabled()) return undefined;
  const token = captchaState.tokens.get(action);
  if (!token) throw new Error('Complete the security check before continuing.');
  return token;
}

function resetCaptcha(action) {
  if (!captchaEnabled()) return;
  captchaState.tokens.delete(action);
  const widgetId = captchaState.widgets.get(action);
  if (widgetId !== undefined && window.turnstile?.reset) window.turnstile.reset(widgetId);
}

function noteUserActivity() {
  if (dom.dashboard?.hidden || state.demo) return;
  const now = Date.now();
  if (now - lastActivityWrite < 5000) return;
  lastActivityWrite = now;
  state.lastActivityAt = now;
  if (state.idleWarningShown) {
    state.idleWarningShown = false;
    showAlert('');
  }
}

function stopIdleSecurity() {
  if (idleTimer) window.clearInterval(idleTimer);
  idleTimer = null;
  state.idleWarningShown = false;
}

function startIdleSecurity() {
  stopIdleSecurity();
  if (state.demo) return;
  const timeoutMinutes = Math.max(0, Number(config.idleTimeoutMinutes) || 0);
  if (!timeoutMinutes) return;
  const warningMinutes = Math.min(timeoutMinutes, Math.max(1, Number(config.idleWarningMinutes) || 2));
  state.lastActivityAt = Date.now();
  idleTimer = window.setInterval(async () => {
    if (!state.session || dom.dashboard.hidden) return;
    const idleMs = Date.now() - state.lastActivityAt;
    const timeoutMs = timeoutMinutes * 60_000;
    const warningMs = warningMinutes * 60_000;
    if (idleMs >= timeoutMs) {
      stopIdleSecurity();
      try { await state.supabase?.auth.signOut({ scope: 'local' }); } catch { /* local cleanup still runs */ }
      resetToLogin();
      setAuthStatus('You were signed out after a period of inactivity.', 'info');
      return;
    }
    if (idleMs >= timeoutMs - warningMs && !state.idleWarningShown) {
      state.idleWarningShown = true;
      showAlert(`For privacy, this session will close after ${timeoutMinutes} minutes without activity. Move, type, or select anything to stay signed in.`, 'warning');
    }
  }, 15_000);
}

const STAFF_ROLES = new Set(['instructor', 'admin']);
const FAMILY_ROLES = new Set(['parent', 'student', 'admin']);
const PROGRESS_WEIGHTS = Object.freeze({ not_started: 0, practicing: 0.35, ready: 0.75, mastered: 1 });

const state = {
  supabase: null,
  session: null,
  user: null,
  profile: null,
  aal: { currentLevel: 'aal1', nextLevel: 'aal1' },
  demo: false,
  students: [],
  studentId: null,
  studentDetails: null,
  announcements: [],
  route: 'overview',
  staffSessions: [],
  staffClassGroups: [],
  attendanceSessionId: null,
  attendanceRoster: [],
  adminData: null,
  enrollFactorId: null,
  recoveryMode: false,
  accountSecurity: { identities: [], passkeys: [] },
  lastActivityAt: Date.now(),
  idleWarningShown: false,
};

const dom = {
  authArea: document.querySelector('[data-auth-area]'),
  authViews: [...document.querySelectorAll('[data-auth-view]')],
  authStatus: document.querySelector('[data-auth-status]'),
  dashboard: document.querySelector('[data-dashboard]'),
  dashboardTitle: document.querySelector('[data-dashboard-title]'),
  dashboardSubtitle: document.querySelector('[data-dashboard-subtitle]'),
  rolePill: document.querySelector('[data-role-pill]'),
  enableMfa: document.querySelector('[data-enable-mfa]'),
  staffRoute: document.querySelector('[data-staff-route]'),
  adminRoute: document.querySelector('[data-admin-route]'),
  billingRoute: document.querySelector('[data-billing-route]'),
  studentSwitcher: document.querySelector('[data-student-switcher]'),
  studentSelect: document.querySelector('[data-student-select]'),
  content: document.querySelector('[data-portal-content]'),
  alert: document.querySelector('[data-portal-alert]'),
  menuButtons: [...document.querySelectorAll('[data-portal-route]')],
  mfaModal: document.querySelector('[data-mfa-modal]'),
  mfaQr: document.querySelector('[data-mfa-qr]'),
  mfaSecret: document.querySelector('[data-mfa-secret]'),
  mfaStatus: document.querySelector('[data-mfa-status]'),
};

const demoData = Object.freeze({
  ranks: [
    { id: 1, name: 'White Belt', level_order: 1, color_hex: '#f5f5f5' },
    { id: 2, name: 'Yellow Belt', level_order: 2, color_hex: '#f5d64e' },
    { id: 3, name: 'Orange Belt', level_order: 3, color_hex: '#f09a43' },
    { id: 4, name: 'Green Belt', level_order: 4, color_hex: '#44a765' },
  ],
  students: [
    { id: 'demo-alex', display_name: 'Alex Rivera', age_group: 'youth', is_minor: true, program: 'Youth Fundamentals', current_rank_id: 2, belt_ranks: { id: 2, name: 'Yellow Belt', level_order: 2, color_hex: '#f5d64e' }, status: 'active' },
    { id: 'demo-mia', display_name: 'Mia Rivera', age_group: 'child', is_minor: true, program: "Children's Karate", current_rank_id: 1, belt_ranks: { id: 1, name: 'White Belt', level_order: 1, color_hex: '#f5f5f5' }, status: 'active' },
  ],
  details: {
    'demo-alex': {
      nextRank: { id: 3, name: 'Orange Belt', level_order: 3, color_hex: '#f09a43' },
      readiness: 68,
      attendanceRate: 88,
      attendanceCount: 16,
      requirements: [
        { id: 'r1', category: 'kihon', title: 'Front stance transitions', description: 'Maintain posture and hip control through forward movement.', status: 'ready', score: 80 },
        { id: 'r2', category: 'kata', title: 'Heian Shodan sequence', description: 'Perform the sequence with correct direction, rhythm, and focus.', status: 'practicing', score: 65 },
        { id: 'r3', category: 'kumite', title: 'Distance and controlled attack', description: 'Demonstrate safe distance, guard, and controlled technique.', status: 'practicing', score: 60 },
        { id: 'r4', category: 'character', title: 'Dojo etiquette', description: 'Consistent respect, effort, and preparedness.', status: 'mastered', score: 95 },
      ],
      upcomingClasses: [
        { id: 'c1', starts_at: nextDate(2, 18, 30), ends_at: nextDate(2, 19, 30), location: 'Honbu Dojo', class_groups: { name: 'Youth Fundamentals' } },
        { id: 'c2', starts_at: nextDate(5, 9, 0), ends_at: nextDate(5, 10, 30), location: 'Honbu Dojo', class_groups: { name: 'Family Class' } },
      ],
      attendance: [
        { id: 'a1', status: 'present', class_sessions: { starts_at: pastDate(2, 18, 30), class_groups: { name: 'Youth Fundamentals' } } },
        { id: 'a2', status: 'present', class_sessions: { starts_at: pastDate(5, 9, 0), class_groups: { name: 'Family Class' } } },
        { id: 'a3', status: 'late', class_sessions: { starts_at: pastDate(7, 18, 30), class_groups: { name: 'Youth Fundamentals' } } },
      ],
      badges: [
        { awarded_on: pastDate(21, 12, 0), badges: { name: 'Kihon Foundation', description: 'Strong basic technique and stances.', icon: '🥋' } },
        { awarded_on: pastDate(14, 12, 0), badges: { name: 'Respect', description: 'Consistent dojo etiquette.', icon: '礼' } },
        { awarded_on: pastDate(7, 12, 0), badges: { name: 'Attendance Streak', description: 'Four weeks of consistent training.', icon: '🔥' } },
      ],
      goals: [
        { id: 'g1', title: 'Complete Heian Shodan without prompts', details: 'Focus on turns and final sequence.', status: 'active', target_date: futureISODate(30) },
        { id: 'g2', title: 'Attend two classes each week', details: 'Build consistency before evaluation.', status: 'active', target_date: futureISODate(45) },
      ],
      notes: [
        { id: 'n1', note: 'Good effort this week. Continue practicing stance width and controlled breathing.', visibility: 'family', created_at: pastDate(3, 17, 0), profiles: { full_name: 'Sensei Rivera' } },
      ],
      billing: [
        { id: 'b1', description: 'September monthly tuition', amount_cents: 8500, due_on: futureISODate(10), status: 'open' },
        { id: 'b2', description: 'August monthly tuition', amount_cents: 8500, due_on: futureISODate(-20), status: 'paid', paid_at: pastDate(18, 10, 0) },
      ],
      consents: [
        { id: 'co1', consent_type: 'portal_privacy', granted: true, policy_version: '2026-08-21', recorded_at: pastDate(40, 12, 0) },
      ],
    },
    'demo-mia': {
      nextRank: { id: 2, name: 'Yellow Belt', level_order: 2, color_hex: '#f5d64e' },
      readiness: 42,
      attendanceRate: 75,
      attendanceCount: 12,
      requirements: [
        { id: 'm1', category: 'kihon', title: 'Basic punches and blocks', description: 'Demonstrate safe form and correct chamber position.', status: 'practicing', score: 55 },
        { id: 'm2', category: 'character', title: 'Line-up and bowing etiquette', description: 'Follow dojo entry, line-up, and bowing procedures.', status: 'ready', score: 80 },
      ],
      upcomingClasses: [{ id: 'mc1', starts_at: nextDate(1, 17, 0), ends_at: nextDate(1, 18, 0), location: 'Honbu Dojo', class_groups: { name: "Children's Karate" } }],
      attendance: [{ id: 'ma1', status: 'present', class_sessions: { starts_at: pastDate(3, 17, 0), class_groups: { name: "Children's Karate" } } }],
      badges: [{ awarded_on: pastDate(10, 12, 0), badges: { name: 'First Class', description: 'Completed the first full class.', icon: '⭐' } }],
      goals: [{ id: 'mg1', title: 'Remember opening etiquette', details: 'Practice bowing and ready stance.', status: 'active', target_date: futureISODate(21) }],
      notes: [{ id: 'mn1', note: 'Mia is becoming more comfortable with class structure and listening cues.', visibility: 'family', created_at: pastDate(2, 17, 0), profiles: { full_name: 'Sensei Rivera' } }],
      billing: [{ id: 'mb1', description: 'September monthly tuition', amount_cents: 7500, due_on: futureISODate(10), status: 'open' }],
      consents: [],
    },
  },
  announcements: [
    { id: 'an1', title: 'Belt evaluation preparation', body: 'Students preparing for the next evaluation should attend at least two classes each week and review assigned kata goals.', published_at: pastDate(1, 9, 0) },
    { id: 'an2', title: 'Saturday family class', body: 'Families are invited to observe the final 20 minutes of Saturday training.', published_at: pastDate(4, 9, 0) },
  ],
});

function nextDate(daysAhead, hour, minute) {
  const value = new Date();
  value.setDate(value.getDate() + daysAhead);
  value.setHours(hour, minute, 0, 0);
  return value.toISOString();
}

function pastDate(daysAgo, hour, minute) {
  const value = new Date();
  value.setDate(value.getDate() - daysAgo);
  value.setHours(hour, minute, 0, 0);
  return value.toISOString();
}

function futureISODate(daysAhead) {
  const value = new Date();
  value.setDate(value.getDate() + daysAhead);
  return value.toISOString().slice(0, 10);
}

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function titleCase(value) {
  return String(value || '')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatDate(value) {
  if (!value) return 'Not set';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(date);
}

function formatDateTime(value) {
  if (!value) return 'Not set';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return new Intl.DateTimeFormat(undefined, {
    weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
  }).format(date);
}

function money(cents) {
  return new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD' }).format((Number(cents) || 0) / 100);
}

function statusChip(status) {
  const clean = String(status || 'unknown').toLowerCase();
  return `<span class="status-chip ${esc(clean)}">${esc(titleCase(clean))}</span>`;
}

function isStaff() {
  return STAFF_ROLES.has(state.profile?.role);
}

function isAdmin() {
  return state.profile?.role === 'admin';
}

function isAal2() {
  return state.aal?.currentLevel === 'aal2';
}

function showAuthView(name) {
  let activeView = null;
  dom.authViews.forEach((view) => {
    view.hidden = view.dataset.authView !== name;
    if (!view.hidden) activeView = view;
  });
  setAuthStatus('');
  configureAuthMethodVisibility();
  activeView?.querySelectorAll('form').forEach((form) => {
    if (form.querySelector('[data-password-feedback]')) wirePasswordForm(form);
  });
  wirePasswordVisibility(activeView || document);
  wireCapsLock(activeView || document);
  renderCaptchaForView(name).catch(() => setAuthStatus('The security check could not load. Refresh the page and try again.'));
}

function setAuthStatus(message, type = 'error') {
  if (!dom.authStatus) return;
  dom.authStatus.textContent = message || '';
  dom.authStatus.className = `form-status ${type}`;
}

function showAlert(message, type = 'info') {
  if (!dom.alert) return;
  if (!message) {
    dom.alert.hidden = true;
    dom.alert.textContent = '';
    return;
  }
  dom.alert.hidden = false;
  dom.alert.className = `portal-alert ${type}`;
  dom.alert.textContent = message;
}

function setBusy(button, busy, busyText = 'Working…') {
  if (!button) return;
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

function cleanAuthUrl() {
  if (!window.history?.replaceState) return;
  const url = new URL(window.location.href);
  ['code', 'type', 'token', 'token_hash'].forEach((key) => url.searchParams.delete(key));
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash.startsWith('#access_token') ? '' : url.hash}`);
}

function authFlowType() {
  const query = new URLSearchParams(window.location.search);
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  return query.get('type') || hash.get('type') || '';
}

async function initialize() {
  bindStaticEvents();
  wirePasswordVisibility(document);
  wireCapsLock(document);
  document.querySelectorAll('form[data-signup-form], form[data-password-form]').forEach(wirePasswordForm);
  configureAuthMethodVisibility();
  if (!authSecurity) {
    showAuthView('login');
    setAuthStatus('The password security module could not load.');
    return;
  }
  // Admin invitation links use Supabase's client-side implicit flow. Capture
  // the link type before the Auth client consumes the URL fragment.
  const initialAuthFlow = authFlowType();

  if (!isConfigured) {
    showAuthView('setup');
    return;
  }

  try {
    createClient = await loadSupabaseBrowserSdk();
  } catch {
    showAuthView('login');
    setAuthStatus('The secure authentication library could not load. Check the network connection and content-security policy.');
    return;
  }

  state.supabase = createClient(config.supabaseUrl, config.supabasePublishableKey, {
    auth: {
      persistSession: true,
      storage: safeBoolean(config.rememberSession, false) ? window.localStorage : window.sessionStorage,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      flowType: 'implicit',
      experimental: { passkey: safeBoolean(config.passkeysEnabled, false) },
    },
  });
  configureAuthMethodVisibility();

  state.supabase.auth.onAuthStateChange((event, session) => {
    if (event === 'PASSWORD_RECOVERY') {
      state.recoveryMode = true;
      state.session = session;
      state.user = session?.user || null;
      showAuthView('set-password');
      return;
    }
    if (event === 'SIGNED_OUT') resetToLogin();
  });

  const { data, error } = await state.supabase.auth.getSession();
  if (error) {
    showAuthView('login');
    setAuthStatus(friendlyAuthError(error));
    return;
  }

  const flow = initialAuthFlow || authFlowType();
  if (data.session && ['invite', 'recovery'].includes(flow)) {
    state.session = data.session;
    state.user = data.session.user;
    state.recoveryMode = true;
    showAuthView('set-password');
    return;
  }

  if (data.session) {
    await handleAuthenticatedSession(data.session);
  } else {
    showAuthView('login');
  }
}

function bindStaticEvents() {
  document.querySelector('[data-login-form]')?.addEventListener('submit', handleLogin);
  document.querySelector('[data-signup-form]')?.addEventListener('submit', handleSignup);
  document.querySelector('[data-recovery-form]')?.addEventListener('submit', handleRecoveryRequest);
  document.querySelector('[data-password-form]')?.addEventListener('submit', handlePasswordUpdate);
  document.querySelector('[data-mfa-challenge-form]')?.addEventListener('submit', handleMfaChallenge);
  document.querySelector('[data-mfa-enroll-form]')?.addEventListener('submit', handleMfaEnrollmentVerify);
  document.querySelector('[data-show-recovery]')?.addEventListener('click', () => showAuthView('recovery'));
  document.querySelectorAll('[data-show-login]').forEach((button) => button.addEventListener('click', () => showAuthView('login')));
  document.querySelectorAll('[data-show-signup]').forEach((button) => button.addEventListener('click', () => showAuthView('signup')));
  document.querySelector('[data-google-login]')?.addEventListener('click', handleGoogleLogin);
  document.querySelector('[data-passkey-login]')?.addEventListener('click', handlePasskeyLogin);
  document.querySelectorAll('[data-sign-out], [data-dashboard-sign-out], [data-pending-sign-out]').forEach((button) => button.addEventListener('click', signOut));
  document.querySelector('[data-demo-parent]')?.addEventListener('click', () => enterDemo('parent'));
  document.querySelector('[data-demo-instructor]')?.addEventListener('click', () => enterDemo('instructor'));
  document.querySelector('[data-demo-admin]')?.addEventListener('click', () => enterDemo('admin'));
  dom.enableMfa?.addEventListener('click', beginMfaEnrollment);
  document.querySelector('[data-close-mfa]')?.addEventListener('click', closeMfaModal);
  dom.mfaModal?.addEventListener('click', (event) => { if (event.target === dom.mfaModal) closeMfaModal(); });
  ['pointerdown', 'keydown', 'touchstart'].forEach((eventName) => document.addEventListener(eventName, noteUserActivity, { passive: true }));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) noteUserActivity(); });

  dom.menuButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      state.route = button.dataset.portalRoute;
      await renderRoute();
    });
  });

  dom.studentSelect?.addEventListener('change', async (event) => {
    state.studentId = event.target.value || null;
    state.studentDetails = null;
    await renderRoute();
  });
}

async function handleGoogleLogin(event) {
  const button = event.currentTarget;
  if (!state.supabase || !safeBoolean(config.googleOAuthEnabled, false)) return;
  setBusy(button, true, 'Opening Google…');
  setAuthStatus('');
  try {
    const { error } = await state.supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: authRedirectUrl(),
        queryParams: { prompt: 'select_account' },
      },
    });
    if (error) throw error;
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
    setBusy(button, false);
  }
}

async function handlePasskeyLogin(event) {
  const button = event.currentTarget;
  if (!state.supabase?.auth?.signInWithPasskey || !safeBoolean(config.passkeysEnabled, false)) return;
  setBusy(button, true, 'Checking passkey…');
  setAuthStatus('');
  try {
    const captchaToken = requireCaptchaToken('login');
    const credentials = captchaToken ? { options: { captchaToken } } : {};
    const { data, error } = await state.supabase.auth.signInWithPasskey(credentials);
    if (error) throw error;
    await handleAuthenticatedSession(data.session);
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    resetCaptcha('login');
    setBusy(button, false);
  }
}

async function handleSignup(event) {
  event.preventDefault();
  if (!state.supabase || !safeBoolean(config.selfRegistrationEnabled, true)) return;
  const formElement = event.currentTarget;
  const button = event.submitter;
  const form = new FormData(formElement);
  const fullName = normalizeDisplayName(form.get('fullName'));
  const email = normalizeEmail(form.get('email'));
  const requestedRole = String(form.get('requestedRole') || 'parent');
  const adultAffirmation = form.get('adultAffirmation') === 'yes';
  const privacyConsent = form.get('privacyConsent') === 'yes';
  const passwordCheck = validateNewPasswordForm(formElement);

  if (fullName.length < 2) return setAuthStatus('Enter your full name.');
  if (!isValidEmail(email)) return setAuthStatus('Enter a valid email address.');
  if (!['parent', 'student'].includes(requestedRole)) return setAuthStatus('Choose a valid account type.');
  if (!adultAffirmation) return setAuthStatus('A parent, legal guardian, or adult student must create this account.');
  if (!privacyConsent) return setAuthStatus('Review and accept the privacy and portal rules.');
  if (!passwordCheck.valid) return setAuthStatus(passwordCheck.message);

  setBusy(button, true, 'Creating…');
  setAuthStatus('');
  try {
    const captchaToken = requireCaptchaToken('signup');
    const options = {
      data: {
        full_name: fullName,
        requested_role: requestedRole,
        registration_source: 'dojo_portal',
      },
      emailRedirectTo: authRedirectUrl('signup'),
      ...(captchaToken ? { captchaToken } : {}),
    };
    const { data, error } = await state.supabase.auth.signUp({
      email,
      password: passwordCheck.password,
      options,
    });
    if (error && !/already registered|user already exists|user_already_exists/i.test(String(error.message || error.code || ''))) throw error;

    formElement.reset();
    updatePasswordFeedback(formElement);
    if (data?.session) {
      await handleAuthenticatedSession(data.session);
    } else {
      showAuthView('signup-success');
    }
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    resetCaptcha('signup');
    setBusy(button, false);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  if (!state.supabase) return;
  const button = event.submitter;
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const email = normalizeEmail(form.get('email'));
  const password = String(form.get('password') || '');
  if (!isValidEmail(email) || !password) return setAuthStatus('Enter a valid email and password.');
  setBusy(button, true, 'Signing in…');
  setAuthStatus('');

  try {
    const captchaToken = requireCaptchaToken('login');
    const credentials = {
      email,
      password,
      ...(captchaToken ? { options: { captchaToken } } : {}),
    };
    const { data, error } = await state.supabase.auth.signInWithPassword(credentials);
    if (error) throw error;
    formElement.querySelector('[name="password"]').value = '';
    await handleAuthenticatedSession(data.session);
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    resetCaptcha('login');
    setBusy(button, false);
  }
}

async function handleRecoveryRequest(event) {
  event.preventDefault();
  const button = event.submitter;
  const email = normalizeEmail(new FormData(event.currentTarget).get('email'));
  if (!isValidEmail(email)) return setAuthStatus('Enter a valid email address.');
  setBusy(button, true, 'Sending…');
  setAuthStatus('');
  try {
    const captchaToken = requireCaptchaToken('recovery');
    const options = {
      redirectTo: authRedirectUrl('recovery'),
      ...(captchaToken ? { captchaToken } : {}),
    };
    const { error } = await state.supabase.auth.resetPasswordForEmail(email, options);
    if (error) throw error;
    setAuthStatus('A reset link has been sent if that email belongs to an account.', 'success');
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    resetCaptcha('recovery');
    setBusy(button, false);
  }
}

async function handlePasswordUpdate(event) {
  event.preventDefault();
  const button = event.submitter;
  const formElement = event.currentTarget;
  const passwordCheck = validateNewPasswordForm(formElement);
  if (!passwordCheck.valid) return setAuthStatus(passwordCheck.message);

  setBusy(button, true, 'Saving…');
  try {
    const { error } = await state.supabase.auth.updateUser({ password: passwordCheck.password });
    if (error) throw error;
    state.recoveryMode = false;
    cleanAuthUrl();
    formElement.reset();
    updatePasswordFeedback(formElement);
    setAuthStatus('Password saved securely.', 'success');
    const { data } = await state.supabase.auth.getSession();
    if (data.session) await handleAuthenticatedSession(data.session);
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    setBusy(button, false);
  }
}

async function handleAuthenticatedSession(session) {
  if (!session?.user) {
    showAuthView('login');
    return;
  }
  state.demo = false;
  state.session = session;
  state.user = session.user;
  showAuthView('loading');

  try {
    const { data: profile, error } = await state.supabase
      .from('profiles')
      .select('id,full_name,role,active,created_at')
      .eq('id', session.user.id)
      .single();
    if (error) throw error;
    state.profile = profile;
    if (!profile.active) {
      stopIdleSecurity();
      showAuthView('pending');
      return;
    }

    const { data: aal, error: aalError } = await state.supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (aalError) throw aalError;
    state.aal = aal;

    if (aal.nextLevel === 'aal2' && aal.currentLevel !== 'aal2') {
      showAuthView('mfa');
      return;
    }

    if (STAFF_ROLES.has(profile.role) && aal.currentLevel !== 'aal2') {
      await openDashboard({ limitedForMfa: true });
      showAlert('Instructor and administrator records stay locked until authenticator MFA is enabled.', 'warning');
      await beginMfaEnrollment();
      return;
    }

    await openDashboard();
  } catch (error) {
    console.warn('Account initialization failed.', { code: String(error?.code || error?.status || '').slice(0, 80) });
    stopIdleSecurity();
    showAuthView('login');
    setAuthStatus('The account could not be opened securely. Try signing in again or contact the dojo.');
  }
}

async function handleMfaChallenge(event) {
  event.preventDefault();
  const button = event.submitter;
  const code = String(new FormData(event.currentTarget).get('code') || '').trim();
  setBusy(button, true, 'Verifying…');
  setAuthStatus('');

  try {
    const { data: factors, error: factorError } = await state.supabase.auth.mfa.listFactors();
    if (factorError) throw factorError;
    const factor = factors.totp?.find((item) => item.status === 'verified') || factors.totp?.[0];
    if (!factor) throw new Error('No verified authenticator factor was found. Contact the dojo administrator.');
    const { data: challenge, error: challengeError } = await state.supabase.auth.mfa.challenge({ factorId: factor.id });
    if (challengeError) throw challengeError;
    const { error: verifyError } = await state.supabase.auth.mfa.verify({ factorId: factor.id, challengeId: challenge.id, code });
    if (verifyError) throw verifyError;
    const { data } = await state.supabase.auth.getSession();
    await handleAuthenticatedSession(data.session);
  } catch (error) {
    setAuthStatus(friendlyAuthError(error));
  } finally {
    setBusy(button, false);
  }
}

async function openDashboard({ limitedForMfa = false } = {}) {
  dom.authArea.hidden = true;
  dom.dashboard.hidden = false;
  startIdleSecurity();
  dom.dashboardTitle.textContent = `Welcome, ${state.profile.full_name || 'dojo member'}`;
  dom.dashboardSubtitle.textContent = limitedForMfa
    ? 'Complete two-step verification to unlock staff records.'
    : 'Your portal is limited to the records authorized for this account.';
  dom.rolePill.textContent = titleCase(state.profile.role);
  dom.staffRoute.hidden = !STAFF_ROLES.has(state.profile.role);
  dom.adminRoute.hidden = state.profile.role !== 'admin';
  dom.billingRoute.hidden = !FAMILY_ROLES.has(state.profile.role);
  dom.enableMfa.textContent = isAal2() ? 'MFA enabled' : 'Enable MFA';
  dom.enableMfa.disabled = isAal2();

  if (limitedForMfa) {
    state.students = [];
    state.studentId = null;
    state.route = 'account';
    syncRouteButtons();
    renderAccount();
    return;
  }

  await Promise.all([loadAccessibleStudents(), loadAnnouncements()]);
  state.route = state.route || 'overview';
  syncRouteButtons();
  renderStudentSwitcher();
  await renderRoute();
}

async function loadAccessibleStudents() {
  if (state.demo) return;
  const columns = 'id,user_id,display_name,age_group,is_minor,program,status,joined_on,current_rank_id,belt_ranks:current_rank_id(id,name,level_order,color_hex)';
  let students = [];

  if (state.profile.role === 'student') {
    const { data, error } = await state.supabase.from('students').select(columns).eq('user_id', state.user.id).eq('status', 'active');
    if (error) throw error;
    students = data || [];
  } else if (state.profile.role === 'parent') {
    const { data: links, error: linkError } = await state.supabase
      .from('guardian_students')
      .select('student_id,relationship,is_primary')
      .eq('guardian_user_id', state.user.id)
      .eq('active', true);
    if (linkError) throw linkError;
    const ids = (links || []).map((link) => link.student_id);
    if (ids.length) {
      const { data, error } = await state.supabase.from('students').select(columns).in('id', ids).eq('status', 'active').order('display_name');
      if (error) throw error;
      students = data || [];
    }
  } else if (STAFF_ROLES.has(state.profile.role)) {
    const { data, error } = await state.supabase.from('students').select(columns).eq('status', 'active').order('display_name');
    if (error) throw error;
    students = data || [];
  }

  state.students = students;
  if (!students.some((student) => student.id === state.studentId)) state.studentId = students[0]?.id || null;
  state.studentDetails = null;
}

async function loadAnnouncements() {
  if (state.demo) {
    state.announcements = [...demoData.announcements];
    return;
  }
  const { data, error } = await state.supabase
    .from('announcements')
    .select('id,title,body,published_at,expires_at,audience')
    .order('published_at', { ascending: false })
    .limit(30);
  if (error) throw error;
  state.announcements = data || [];
}

function renderStudentSwitcher() {
  const show = state.students.length > 0;
  dom.studentSwitcher.hidden = !show;
  if (!show) return;
  dom.studentSelect.innerHTML = state.students
    .map((student) => `<option value="${esc(student.id)}" ${student.id === state.studentId ? 'selected' : ''}>${esc(student.display_name)}</option>`)
    .join('');
}

async function getStudentDetails() {
  if (!state.studentId) return null;
  if (state.studentDetails?.student?.id === state.studentId) return state.studentDetails;

  const student = state.students.find((item) => item.id === state.studentId);
  if (!student) return null;

  if (state.demo) {
    state.studentDetails = { student, ...structuredClone(demoData.details[state.studentId]) };
    return state.studentDetails;
  }

  const { data: ranks, error: rankError } = await state.supabase.from('belt_ranks').select('id,name,level_order,color_hex').eq('active', true).order('level_order');
  if (rankError) throw rankError;
  const currentOrder = student.belt_ranks?.level_order || 0;
  const nextRank = (ranks || []).find((rank) => rank.level_order > currentOrder) || null;

  const requirementPromise = nextRank
    ? state.supabase.from('requirements').select('id,target_rank_id,category,title,description,sort_order').eq('target_rank_id', nextRank.id).eq('active', true).order('sort_order')
    : Promise.resolve({ data: [], error: null });

  const [requirementsResult, progressResult, attendanceResult, enrollmentResult, badgeResult, goalResult, noteResult] = await Promise.all([
    requirementPromise,
    state.supabase.from('student_requirement_progress').select('requirement_id,status,score,family_note,updated_at').eq('student_id', student.id),
    state.supabase.from('attendance').select('id,status,recorded_at,class_sessions:session_id(id,starts_at,ends_at,location,class_groups:class_group_id(name))').eq('student_id', student.id).order('recorded_at', { ascending: false }).limit(40),
    state.supabase.from('enrollments').select('class_group_id').eq('student_id', student.id).eq('active', true),
    state.supabase.from('student_badges').select('awarded_on,note,badges:badge_id(name,description,icon)').eq('student_id', student.id).order('awarded_on', { ascending: false }),
    state.supabase.from('student_goals').select('id,title,details,status,target_date,family_visible,created_at').eq('student_id', student.id).order('created_at', { ascending: false }),
    state.supabase.from('student_notes').select('id,note,visibility,created_at,profiles:author_user_id(full_name)').eq('student_id', student.id).order('created_at', { ascending: false }).limit(20),
  ]);

  [requirementsResult, progressResult, attendanceResult, enrollmentResult, badgeResult, goalResult, noteResult].forEach((result) => {
    if (result.error) throw result.error;
  });

  const groupIds = [...new Set((enrollmentResult.data || []).map((row) => row.class_group_id))];
  let upcomingClasses = [];
  if (groupIds.length) {
    const { data, error } = await state.supabase
      .from('class_sessions')
      .select('id,class_group_id,starts_at,ends_at,location,status,class_groups:class_group_id(name)')
      .in('class_group_id', groupIds)
      .gte('starts_at', new Date().toISOString())
      .eq('status', 'scheduled')
      .order('starts_at')
      .limit(8);
    if (error) throw error;
    upcomingClasses = data || [];
  }

  let billing = [];
  let consents = [];
  if (FAMILY_ROLES.has(state.profile.role)) {
    const [billingResult, consentResult] = await Promise.all([
      state.supabase.from('billing_items').select('id,description,amount_cents,due_on,status,paid_at,external_reference').eq('student_id', student.id).order('due_on', { ascending: false }).limit(24),
      state.profile.role === 'parent' || state.profile.role === 'admin'
        ? state.supabase.from('consents').select('id,consent_type,granted,policy_version,recorded_at').eq('student_id', student.id).order('recorded_at', { ascending: false })
        : Promise.resolve({ data: [], error: null }),
    ]);
    if (billingResult.error) throw billingResult.error;
    if (consentResult.error) throw consentResult.error;
    billing = billingResult.data || [];
    consents = consentResult.data || [];
  }

  const progressMap = new Map((progressResult.data || []).map((row) => [row.requirement_id, row]));
  const requirements = (requirementsResult.data || []).map((requirement) => ({
    ...requirement,
    ...(progressMap.get(requirement.id) || { status: 'not_started', score: null, family_note: null }),
  }));
  const readiness = calculateReadiness(requirements);
  const attendance = attendanceResult.data || [];
  const attendanceRate = calculateAttendanceRate(attendance);

  state.studentDetails = {
    student,
    ranks: ranks || [],
    nextRank,
    requirements,
    readiness,
    attendance,
    attendanceRate,
    attendanceCount: attendance.length,
    upcomingClasses,
    badges: badgeResult.data || [],
    goals: goalResult.data || [],
    notes: noteResult.data || [],
    billing,
    consents,
  };
  return state.studentDetails;
}

function calculateReadiness(requirements) {
  if (!requirements.length) return 0;
  const total = requirements.reduce((sum, item) => sum + (PROGRESS_WEIGHTS[item.status] ?? 0), 0);
  return Math.round((total / requirements.length) * 100);
}

function calculateAttendanceRate(attendance) {
  if (!attendance.length) return 0;
  const attended = attendance.filter((row) => ['present', 'late'].includes(row.status)).length;
  return Math.round((attended / attendance.length) * 100);
}

async function renderRoute() {
  syncRouteButtons();
  showAlert('');
  dom.content.innerHTML = '<div class="portal-empty"><div class="loading-ring" aria-hidden="true"></div>Loading authorized records…</div>';

  try {
    switch (state.route) {
      case 'overview': await renderOverview(); break;
      case 'progress': await renderProgress(); break;
      case 'schedule': await renderSchedule(); break;
      case 'announcements': renderAnnouncements(); break;
      case 'billing': await renderBilling(); break;
      case 'staff': await renderStaff(); break;
      case 'admin': await renderAdmin(); break;
      case 'account': await renderAccount(); break;
      default: state.route = 'overview'; await renderOverview();
    }
  } catch (error) {
    dom.content.innerHTML = `<div class="portal-empty"><strong>Unable to load this section.</strong><p>${esc(friendlyOperationError(error, 'The authorized records could not be loaded.'))}</p></div>`;
  }
}

function syncRouteButtons() {
  dom.menuButtons.forEach((button) => button.classList.toggle('is-active', button.dataset.portalRoute === state.route));
}

function noStudentMarkup() {
  const staffMessage = isStaff()
    ? 'Create or link a student account from Administration.'
    : 'Ask the dojo to link your account to the correct student record.';
  return `<div class="portal-empty"><h2>No linked student</h2><p>${esc(staffMessage)}</p></div>`;
}

async function renderOverview() {
  const details = await getStudentDetails();
  if (!details) {
    dom.content.innerHTML = noStudentMarkup();
    return;
  }
  const nextClass = details.upcomingClasses[0];
  const currentBelt = details.student.belt_ranks?.name || 'Rank not set';
  const goals = details.goals.filter((goal) => goal.status !== 'completed').slice(0, 4);
  const notes = details.notes.filter((note) => note.visibility === 'family' || isStaff()).slice(0, 3);
  const announcements = state.announcements.slice(0, 3);

  dom.content.innerHTML = `
    <div class="portal-page-heading">
      <div><h2>${esc(details.student.display_name)}</h2><p>${esc(details.student.program || titleCase(details.student.age_group))}</p></div>
      ${details.nextRank ? `<span class="role-pill">Next: ${esc(details.nextRank.name)}</span>` : '<span class="role-pill">Highest listed rank</span>'}
    </div>
    <div class="portal-summary-grid">
      <article class="portal-stat-card"><small>Current rank</small><strong>${esc(currentBelt)}</strong><span>Official student record</span></article>
      <article class="portal-stat-card"><small>Next-rank readiness</small><strong>${details.readiness}%</strong><span>${details.nextRank ? esc(details.nextRank.name) : 'No next rank configured'}</span></article>
      <article class="portal-stat-card"><small>Attendance</small><strong>${details.attendanceRate}%</strong><span>${details.attendanceCount} recent records</span></article>
      <article class="portal-stat-card"><small>Next class</small><strong>${nextClass ? esc(formatDateTime(nextClass.starts_at)) : 'No class scheduled'}</strong><span>${nextClass ? esc(nextClass.class_groups?.name || nextClass.location || '') : 'Check announcements'}</span></article>
    </div>
    <div class="portal-grid-2">
      <section class="portal-panel">
        <div class="portal-panel-head"><h3>Belt progress</h3><button class="text-button" type="button" data-jump-route="progress">View details</button></div>
        <div class="panel-row"><span>${details.nextRank ? esc(details.nextRank.name) : 'Current rank complete'}</span><strong>${details.readiness}%</strong></div>
        <div class="progress-bar progress-meter-large"><span style="width:${Math.max(0, Math.min(100, details.readiness))}%"></span></div>
        <p class="portal-muted">Progress reflects the requirements entered by authorized instructors. It is guidance, not an automatic promotion decision.</p>
      </section>
      <section class="portal-panel">
        <div class="portal-panel-head"><h3>Active goals</h3><span>${goals.length}</span></div>
        ${goals.length ? `<div class="portal-list">${goals.map((goal) => `<div class="portal-list-item"><div><strong>${esc(goal.title)}</strong><small>${esc(goal.details || '')}</small></div><div>${statusChip(goal.status)}<small>${goal.target_date ? `Target ${esc(formatDate(goal.target_date))}` : ''}</small></div></div>`).join('')}</div>` : '<p class="portal-muted">No active goals have been entered.</p>'}
      </section>
    </div>
    <div class="portal-grid-2">
      <section class="portal-panel">
        <div class="portal-panel-head"><h3>Recent badges</h3><span>${details.badges.length}</span></div>
        ${details.badges.length ? `<div class="badge-card-grid">${details.badges.slice(0, 6).map((item) => `<article class="badge-card"><span>${esc(item.badges?.icon || '★')}</span><strong>${esc(item.badges?.name || 'Badge')}</strong><small>${esc(item.badges?.description || '')}</small></article>`).join('')}</div>` : '<p class="portal-muted">No badges have been awarded yet.</p>'}
      </section>
      <section class="portal-panel">
        <div class="portal-panel-head"><h3>Instructor updates</h3><span>${notes.length}</span></div>
        ${notes.length ? `<div class="portal-list">${notes.map((note) => `<div class="portal-list-item"><div><strong>${esc(note.profiles?.full_name || 'Instructor')}</strong><small>${esc(note.note)}</small></div><div><small>${esc(formatDate(note.created_at))}</small></div></div>`).join('')}</div>` : '<p class="portal-muted">No family-visible instructor updates yet.</p>'}
      </section>
    </div>
    <section class="portal-panel">
      <div class="portal-panel-head"><h3>Latest announcements</h3><button class="text-button" type="button" data-jump-route="announcements">View all</button></div>
      ${announcements.length ? `<div class="portal-list">${announcements.map(announcementMarkup).join('')}</div>` : '<p class="portal-muted">No current announcements.</p>'}
    </section>`;

  bindCommonContentEvents();
}

async function renderProgress() {
  const details = await getStudentDetails();
  if (!details) {
    dom.content.innerHTML = noStudentMarkup();
    return;
  }
  const staffCanEdit = isStaff() && isAal2();
  const requirementRows = details.requirements.length
    ? details.requirements.map((item) => `
      <div class="requirement-row">
        <div><span class="card-kicker">${esc(titleCase(item.category))}</span><h4>${esc(item.title)}</h4><p>${esc(item.description || '')}</p></div>
        <div>
          ${staffCanEdit ? `<select data-progress-status="${esc(item.id)}" aria-label="Progress status for ${esc(item.title)}">
            ${['not_started', 'practicing', 'ready', 'mastered'].map((status) => `<option value="${status}" ${item.status === status ? 'selected' : ''}>${esc(titleCase(status))}</option>`).join('')}
          </select>` : statusChip(item.status)}
        </div>
      </div>`).join('')
    : '<p class="portal-muted">No requirements are configured for the next rank.</p>';

  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Belt progress</h2><p>${esc(details.student.display_name)} • ${esc(details.student.belt_ranks?.name || 'Rank not set')}</p></div>${details.nextRank ? `<span class="role-pill">Working toward ${esc(details.nextRank.name)}</span>` : ''}</div>
    <section class="portal-panel">
      <div class="panel-row"><span>Readiness summary</span><strong>${details.readiness}%</strong></div>
      <div class="progress-bar progress-meter-large"><span style="width:${details.readiness}%"></span></div>
      <p class="portal-muted">Only authorized instructors can change requirement status. Belt promotion remains an instructor decision.</p>
    </section>
    <section class="portal-panel" style="margin-top:1rem">
      <div class="portal-panel-head"><h3>${details.nextRank ? `${esc(details.nextRank.name)} requirements` : 'Requirements'}</h3><span>${details.requirements.length}</span></div>
      ${requirementRows}
    </section>
    <div class="portal-grid-2" style="margin-top:1rem">
      <section class="portal-panel">
        <h3>Goals</h3>
        ${details.goals.length ? `<div class="portal-list">${details.goals.map((goal) => `<div class="portal-list-item"><div><strong>${esc(goal.title)}</strong><small>${esc(goal.details || '')}</small></div><div>${statusChip(goal.status)}<small>${goal.target_date ? esc(formatDate(goal.target_date)) : ''}</small></div></div>`).join('')}</div>` : '<p class="portal-muted">No goals entered.</p>'}
      </section>
      <section class="portal-panel">
        <h3>Instructor notes</h3>
        ${details.notes.length ? `<div class="portal-list">${details.notes.map((note) => `<div class="portal-list-item"><div><strong>${esc(note.profiles?.full_name || 'Instructor')}</strong><small>${esc(note.note)}</small></div><div>${statusChip(note.visibility)}<small>${esc(formatDate(note.created_at))}</small></div></div>`).join('')}</div>` : '<p class="portal-muted">No notes entered.</p>'}
        ${staffCanEdit ? `<hr class="portal-separator" /><form class="portal-form-grid" data-note-form><label class="portal-field full">New note<textarea name="note" rows="3" maxlength="1000" required></textarea></label><label class="portal-field">Visibility<select name="visibility"><option value="family">Student / family</option><option value="staff_only">Staff only</option></select></label><div class="portal-form-actions"><button class="btn btn-primary" type="submit">Save note</button></div></form>` : ''}
      </section>
    </div>`;

  dom.content.querySelectorAll('[data-progress-status]').forEach((select) => {
    select.addEventListener('change', () => updateRequirementProgress(select.dataset.progressStatus, select.value));
  });
  dom.content.querySelector('[data-note-form]')?.addEventListener('submit', addStudentNote);
}

async function updateRequirementProgress(requirementId, status) {
  if (state.demo) {
    const requirement = state.studentDetails.requirements.find((item) => item.id === requirementId);
    if (requirement) requirement.status = status;
    state.studentDetails.readiness = calculateReadiness(state.studentDetails.requirements);
    showAlert('Demo updated locally. No database record was changed.', 'info');
    await renderProgress();
    return;
  }
  try {
    const { error } = await state.supabase.from('student_requirement_progress').upsert({
      student_id: state.studentId,
      requirement_id: requirementId,
      status,
      assessed_by: state.user.id,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'student_id,requirement_id' });
    if (error) throw error;
    state.studentDetails = null;
    showAlert('Progress saved.', 'success');
    await renderProgress();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'Progress could not be saved.'), 'error');
  }
}

async function addStudentNote(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const note = String(form.get('note') || '').trim();
  const visibility = String(form.get('visibility') || 'family');
  if (!note) return;
  if (state.demo) {
    state.studentDetails.notes.unshift({ id: crypto.randomUUID(), note, visibility, created_at: new Date().toISOString(), profiles: { full_name: state.profile.full_name } });
    showAlert('Demo note added locally.', 'info');
    await renderProgress();
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Saving…');
  try {
    const { error } = await state.supabase.from('student_notes').insert({ student_id: state.studentId, note, visibility, author_user_id: state.user.id });
    if (error) throw error;
    state.studentDetails = null;
    showAlert('Note saved.', 'success');
    await renderProgress();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The note could not be saved.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function renderSchedule() {
  const details = await getStudentDetails();
  if (!details) {
    dom.content.innerHTML = noStudentMarkup();
    return;
  }
  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Schedule & attendance</h2><p>${esc(details.student.display_name)}</p></div><span class="role-pill">${details.attendanceRate}% attendance</span></div>
    <div class="portal-grid-2">
      <section class="portal-panel"><div class="portal-panel-head"><h3>Upcoming classes</h3><span>${details.upcomingClasses.length}</span></div>
        ${details.upcomingClasses.length ? `<div class="portal-list">${details.upcomingClasses.map((session) => `<div class="portal-list-item"><div><strong>${esc(session.class_groups?.name || 'Class')}</strong><small>${esc(session.location || 'Location to be announced')}</small></div><div><strong>${esc(formatDateTime(session.starts_at))}</strong><small>${session.ends_at ? `Ends ${esc(new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(new Date(session.ends_at)))}` : ''}</small></div></div>`).join('')}</div>` : '<p class="portal-muted">No upcoming class session is connected to this student.</p>'}
      </section>
      <section class="portal-panel"><div class="portal-panel-head"><h3>Attendance summary</h3><span>${details.attendanceCount} records</span></div><div class="panel-row"><span>Present or late</span><strong>${details.attendanceRate}%</strong></div><div class="progress-bar progress-meter-large"><span style="width:${details.attendanceRate}%"></span></div><p class="portal-muted">Excused absences remain visible but are not counted as attended.</p></section>
    </div>
    <section class="portal-panel"><div class="portal-panel-head"><h3>Recent attendance</h3><span>${details.attendance.length}</span></div>
      ${details.attendance.length ? `<div class="portal-table-wrap"><table class="portal-table"><thead><tr><th>Date</th><th>Class</th><th>Status</th></tr></thead><tbody>${details.attendance.map((row) => `<tr><td>${esc(formatDateTime(row.class_sessions?.starts_at || row.recorded_at))}</td><td>${esc(row.class_sessions?.class_groups?.name || 'Class')}</td><td>${statusChip(row.status)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="portal-muted">No attendance has been recorded.</p>'}
    </section>`;
}

function announcementMarkup(item) {
  return `<div class="portal-list-item"><div><strong>${esc(item.title)}</strong><small>${esc(item.body)}</small></div><div><small>${esc(formatDate(item.published_at))}</small></div></div>`;
}

function renderAnnouncements() {
  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Announcements</h2><p>Messages published for your account role.</p></div><span class="role-pill">${state.announcements.length} current</span></div>
    <section class="portal-panel">${state.announcements.length ? `<div class="portal-list">${state.announcements.map(announcementMarkup).join('')}</div>` : '<p class="portal-muted">There are no current announcements.</p>'}</section>`;
}

async function renderBilling() {
  if (!FAMILY_ROLES.has(state.profile.role)) {
    dom.content.innerHTML = '<div class="portal-empty"><h2>Billing is private</h2><p>Instructor accounts do not have access to family billing information.</p></div>';
    return;
  }
  const details = await getStudentDetails();
  if (!details) {
    dom.content.innerHTML = noStudentMarkup();
    return;
  }
  const outstanding = details.billing.filter((item) => ['open', 'overdue'].includes(item.status)).reduce((sum, item) => sum + Number(item.amount_cents || 0), 0);
  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Billing</h2><p>${esc(details.student.display_name)} • status records only</p></div><span class="role-pill">Outstanding ${esc(money(outstanding))}</span></div>
    <div class="portal-alert info">The portal stores invoice status and amounts only. Card or bank information must stay with a dedicated payment processor.</div>
    <section class="portal-panel">
      ${details.billing.length ? `<div class="portal-table-wrap"><table class="portal-table"><thead><tr><th>Description</th><th>Due</th><th>Amount</th><th>Status</th></tr></thead><tbody>${details.billing.map((item) => `<tr><td>${esc(item.description)}</td><td>${esc(formatDate(item.due_on))}</td><td>${esc(money(item.amount_cents))}</td><td>${statusChip(item.status)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="portal-muted">No billing items are visible for this student.</p>'}
    </section>`;
}

async function renderStaff() {
  if (!isStaff()) {
    dom.content.innerHTML = '<div class="portal-empty"><h2>Instructor access required</h2></div>';
    return;
  }
  if (!isAal2() && !state.demo) {
    renderAccount();
    showAlert('Authenticator MFA is required before staff records can be opened.', 'warning');
    return;
  }
  await loadStaffData();
  const sessionOptions = state.staffSessions.map((session) => `<option value="${esc(session.id)}" ${session.id === state.attendanceSessionId ? 'selected' : ''}>${esc(formatDateTime(session.starts_at))} — ${esc(session.class_groups?.name || 'Class')}</option>`).join('');
  const staffStudentOptions = state.students.map((student) => `<option value="${esc(student.id)}">${esc(student.display_name)}</option>`).join('');
  const badgeOptions = state.staffBadges.map((badge) => `<option value="${esc(badge.id)}">${esc(badge.name)}</option>`).join('');
  const rosterRows = state.attendanceRoster.map((row) => `<tr><td><strong>${esc(row.student.display_name)}</strong><br><small>${esc(row.student.belt_ranks?.name || 'Rank not set')}</small></td><td><select data-attendance-student="${esc(row.student.id)}"><option value="present" ${row.status === 'present' ? 'selected' : ''}>Present</option><option value="late" ${row.status === 'late' ? 'selected' : ''}>Late</option><option value="absent" ${row.status === 'absent' ? 'selected' : ''}>Absent</option><option value="excused" ${row.status === 'excused' ? 'selected' : ''}>Excused</option></select></td></tr>`).join('');

  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Instructor tools</h2><p>Staff actions require an MFA-verified session.</p></div><span class="role-pill">AAL2 verified</span></div>
    <div class="portal-grid-2">
      <section class="portal-panel"><div class="portal-panel-head"><h3>Student roster</h3><span>${state.students.length}</span></div>
        <div class="portal-list">${state.students.slice(0, 30).map((student) => `<div class="portal-list-item"><div><strong>${esc(student.display_name)}</strong><small>${esc(student.program || titleCase(student.age_group))} • ${esc(student.belt_ranks?.name || 'Rank not set')}</small></div><div><button class="btn btn-small btn-secondary" type="button" data-view-student="${esc(student.id)}">Open progress</button></div></div>`).join('')}</div>
      </section>
      <section class="portal-panel"><h3>Create class session</h3>
        <form class="portal-form-grid" data-session-form>
          <label class="portal-field full">Class group<select name="class_group_id" required><option value="">Choose a group</option>${state.staffClassGroups.map((group) => `<option value="${esc(group.id)}">${esc(group.name)}</option>`).join('')}</select></label>
          <label class="portal-field">Starts<input type="datetime-local" name="starts_at" required /></label>
          <label class="portal-field">Ends<input type="datetime-local" name="ends_at" required /></label>
          <label class="portal-field full">Location<input type="text" name="location" maxlength="150" value="Honbu Dojo" /></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Create session</button></div>
        </form>
      </section>
    </div>
    <section class="portal-panel">
      <div class="portal-panel-head"><h3>Attendance</h3><span>${state.attendanceRoster.length} students</span></div>
      <form class="portal-form-grid" data-attendance-session-form>
        <label class="portal-field full">Class session<select name="session_id" required><option value="">Choose a session</option>${sessionOptions}</select></label>
        <div class="portal-form-actions"><button class="btn btn-secondary" type="submit">Load roster</button></div>
      </form>
      ${state.attendanceSessionId ? `<hr class="portal-separator" />${rosterRows ? `<form data-attendance-save-form><div class="portal-table-wrap"><table class="portal-table"><thead><tr><th>Student</th><th>Status</th></tr></thead><tbody>${rosterRows}</tbody></table></div><div class="portal-form-actions" style="margin-top:1rem"><button class="btn btn-primary" type="submit">Save attendance</button></div></form>` : '<p class="portal-muted">No active enrollments are connected to this class group.</p>'}` : '<p class="portal-muted">Choose a class session to mark attendance.</p>'}
    </section>
    <div class="portal-grid-2">
      <section class="portal-panel"><h3>Award badge</h3>
        <form class="portal-form-grid" data-badge-form>
          <label class="portal-field full">Student<select name="student_id" required><option value="">Choose student</option>${staffStudentOptions}</select></label>
          <label class="portal-field full">Badge<select name="badge_id" required><option value="">Choose badge</option>${badgeOptions}</select></label>
          <label class="portal-field full">Note<input type="text" name="note" maxlength="1000" /></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Award badge</button></div>
        </form>
      </section>
      <section class="portal-panel"><h3>Create student goal</h3>
        <form class="portal-form-grid" data-goal-form>
          <label class="portal-field full">Student<select name="student_id" required><option value="">Choose student</option>${staffStudentOptions}</select></label>
          <label class="portal-field full">Goal<input type="text" name="title" maxlength="150" required /></label>
          <label class="portal-field full">Details<textarea name="details" rows="3" maxlength="1500"></textarea></label>
          <label class="portal-field">Target date<input type="date" name="target_date" /></label>
          <label class="portal-field">Family visibility<select name="family_visible"><option value="true">Visible</option><option value="false">Staff only</option></select></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Create goal</button></div>
        </form>
      </section>
    </div>
    <section class="portal-panel" style="margin-top:1rem"><h3>Publish announcement</h3>
      <form class="portal-form-grid" data-announcement-form>
        <label class="portal-field full">Title<input type="text" name="title" maxlength="150" required /></label>
        <label class="portal-field full">Message<textarea name="body" rows="4" maxlength="3000" required></textarea></label>
        <label class="portal-field full">Audience<select name="audience"><option value="all">Everyone</option><option value="parent">Parents</option><option value="student">Students</option><option value="instructor">Instructors</option></select></label>
        <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Publish</button></div>
      </form>
    </section>`;

  dom.content.querySelectorAll('[data-view-student]').forEach((button) => button.addEventListener('click', async () => {
    state.studentId = button.dataset.viewStudent;
    state.studentDetails = null;
    renderStudentSwitcher();
    state.route = 'progress';
    await renderRoute();
  }));
  dom.content.querySelector('[data-session-form]')?.addEventListener('submit', createClassSession);
  dom.content.querySelector('[data-attendance-session-form]')?.addEventListener('submit', loadAttendanceRosterFromForm);
  dom.content.querySelector('[data-attendance-save-form]')?.addEventListener('submit', saveAttendance);
  dom.content.querySelector('[data-announcement-form]')?.addEventListener('submit', publishAnnouncement);
  dom.content.querySelector('[data-badge-form]')?.addEventListener('submit', awardBadge);
  dom.content.querySelector('[data-goal-form]')?.addEventListener('submit', createStudentGoal);
}

async function loadStaffData() {
  if (state.demo) {
    state.staffClassGroups = [{ id: 'cg1', name: 'Youth Fundamentals' }, { id: 'cg2', name: 'Teen & Adult Shotokan' }];
    state.staffSessions = demoData.details['demo-alex'].upcomingClasses.map((item, index) => ({ ...item, id: `staff-${index}`, class_group_id: index === 0 ? 'cg1' : 'cg2' }));
    state.staffBadges = [{ id: 'badge-1', name: 'Kata Focus' }, { id: 'badge-2', name: 'Leadership' }];
    return;
  }
  const start = new Date();
  start.setDate(start.getDate() - 30);
  const end = new Date();
  end.setDate(end.getDate() + 60);
  const [groupsResult, sessionsResult, badgesResult] = await Promise.all([
    state.supabase.from('class_groups').select('id,name,description,active').eq('active', true).order('name'),
    state.supabase.from('class_sessions').select('id,class_group_id,starts_at,ends_at,location,status,class_groups:class_group_id(name)').gte('starts_at', start.toISOString()).lte('starts_at', end.toISOString()).order('starts_at', { ascending: false }).limit(80),
    state.supabase.from('badges').select('id,name').eq('active', true).order('name'),
  ]);
  if (groupsResult.error) throw groupsResult.error;
  if (sessionsResult.error) throw sessionsResult.error;
  if (badgesResult.error) throw badgesResult.error;
  state.staffClassGroups = groupsResult.data || [];
  state.staffSessions = sessionsResult.data || [];
  state.staffBadges = badgesResult.data || [];
}

async function createClassSession(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const startsAt = new Date(String(form.get('starts_at')));
  const endsAt = new Date(String(form.get('ends_at')));
  if (!(startsAt < endsAt)) {
    showAlert('The end time must be after the start time.', 'error');
    return;
  }
  if (state.demo) {
    showAlert('Demo session created locally only.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Creating…');
  try {
    const { error } = await state.supabase.from('class_sessions').insert({
      class_group_id: form.get('class_group_id'),
      starts_at: startsAt.toISOString(),
      ends_at: endsAt.toISOString(),
      location: String(form.get('location') || '').trim() || null,
      instructor_user_id: state.user.id,
      status: 'scheduled',
      created_by: state.user.id,
    });
    if (error) throw error;
    state.staffSessions = [];
    showAlert('Class session created.', 'success');
    await renderStaff();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The session could not be created.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function loadAttendanceRosterFromForm(event) {
  event.preventDefault();
  state.attendanceSessionId = String(new FormData(event.currentTarget).get('session_id') || '');
  state.attendanceRoster = [];
  if (!state.attendanceSessionId) return renderStaff();
  if (state.demo) {
    state.attendanceRoster = state.students.map((student) => ({ student, status: 'present' }));
    return renderStaff();
  }
  const session = state.staffSessions.find((item) => item.id === state.attendanceSessionId);
  if (!session) return;
  const { data: enrollments, error: enrollmentError } = await state.supabase.from('enrollments').select('student_id').eq('class_group_id', session.class_group_id).eq('active', true);
  if (enrollmentError) throw enrollmentError;
  const ids = (enrollments || []).map((row) => row.student_id);
  if (!ids.length) return renderStaff();
  const [studentsResult, attendanceResult] = await Promise.all([
    state.supabase.from('students').select('id,display_name,belt_ranks:current_rank_id(name)').in('id', ids).order('display_name'),
    state.supabase.from('attendance').select('student_id,status').eq('session_id', state.attendanceSessionId).in('student_id', ids),
  ]);
  if (studentsResult.error) throw studentsResult.error;
  if (attendanceResult.error) throw attendanceResult.error;
  const attendanceMap = new Map((attendanceResult.data || []).map((row) => [row.student_id, row.status]));
  state.attendanceRoster = (studentsResult.data || []).map((student) => ({ student, status: attendanceMap.get(student.id) || 'present' }));
  await renderStaff();
}

async function saveAttendance(event) {
  event.preventDefault();
  const rows = [...event.currentTarget.querySelectorAll('[data-attendance-student]')].map((select) => ({
    session_id: state.attendanceSessionId,
    student_id: select.dataset.attendanceStudent,
    status: select.value,
    recorded_by: state.user?.id || null,
    recorded_at: new Date().toISOString(),
  }));
  if (state.demo) {
    showAlert('Demo attendance saved locally only.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Saving…');
  try {
    const { error } = await state.supabase.from('attendance').upsert(rows, { onConflict: 'session_id,student_id' });
    if (error) throw error;
    showAlert('Attendance saved.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'Attendance could not be saved.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function awardBadge(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  if (state.demo) {
    showAlert('Demo badge awarded locally only.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Awarding…');
  try {
    const { error } = await state.supabase.from('student_badges').upsert({
      student_id: form.get('student_id'),
      badge_id: form.get('badge_id'),
      note: String(form.get('note') || '').trim() || null,
      awarded_by: state.user.id,
      awarded_on: new Date().toISOString().slice(0, 10),
    }, { onConflict: 'student_id,badge_id' });
    if (error) throw error;
    event.currentTarget.reset();
    state.studentDetails = null;
    showAlert('Badge awarded.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The badge could not be awarded.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function createStudentGoal(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  if (state.demo) {
    showAlert('Demo goal created locally only.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Creating…');
  try {
    const targetDate = String(form.get('target_date') || '');
    const { error } = await state.supabase.from('student_goals').insert({
      student_id: form.get('student_id'),
      title: String(form.get('title') || '').trim(),
      details: String(form.get('details') || '').trim() || null,
      target_date: targetDate || null,
      family_visible: form.get('family_visible') !== 'false',
      status: 'active',
      created_by: state.user.id,
    });
    if (error) throw error;
    event.currentTarget.reset();
    state.studentDetails = null;
    showAlert('Student goal created.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The goal could not be created.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function publishAnnouncement(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  if (state.demo) {
    state.announcements.unshift({ id: crypto.randomUUID(), title: form.get('title'), body: form.get('body'), published_at: new Date().toISOString() });
    showAlert('Demo announcement published locally.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Publishing…');
  try {
    const { error } = await state.supabase.from('announcements').insert({
      title: String(form.get('title') || '').trim(),
      body: String(form.get('body') || '').trim(),
      audience: [String(form.get('audience') || 'all')],
      published_at: new Date().toISOString(),
      created_by: state.user.id,
    });
    if (error) throw error;
    await loadAnnouncements();
    event.currentTarget.reset();
    showAlert('Announcement published.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The announcement could not be published.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function renderAdmin() {
  if (!isAdmin()) {
    dom.content.innerHTML = '<div class="portal-empty"><h2>Administrator access required</h2></div>';
    return;
  }
  if (!isAal2() && !state.demo) {
    await renderAccount();
    showAlert('Administrator tools require authenticator MFA.', 'warning');
    return;
  }
  await loadAdminData();
  const data = state.adminData;
  const parentOptions = data.parentProfiles.map((profile) => `<option value="${esc(profile.id)}">${esc(profile.full_name)}</option>`).join('');
  const studentAccountOptions = data.studentProfiles.map((profile) => `<option value="${esc(profile.id)}">${esc(profile.full_name)}</option>`).join('');
  const studentOptions = data.students.map((student) => `<option value="${esc(student.id)}">${esc(student.display_name)}</option>`).join('');
  const unlinkedStudentOptions = data.students.filter((student) => !student.user_id).map((student) => `<option value="${esc(student.id)}">${esc(student.display_name)}</option>`).join('');
  const rankOptions = data.ranks.map((rank) => `<option value="${esc(rank.id)}">${esc(rank.name)}</option>`).join('');
  const classOptions = data.classGroups.map((group) => `<option value="${esc(group.id)}">${esc(group.name)}</option>`).join('');
  const pendingAccounts = data.pendingAccounts || [];
  const pendingMarkup = pendingAccounts.length
    ? pendingAccounts.map((account) => {
      const verificationText = account.emailVerified === true
        ? 'Email verified'
        : account.emailVerified === false
          ? 'Email not verified'
          : 'Verification status unavailable';
      const verificationClass = account.emailVerified === true ? 'verified' : account.emailVerified === false ? 'unverified' : '';
      const approvalDisabled = account.emailVerified === false ? 'disabled aria-disabled="true" title="Email verification is required before approval"' : '';
      return `<form class="pending-account-card" data-approve-account-form><input type="hidden" name="userId" value="${esc(account.id)}" /><div><strong>${esc(account.fullName || 'Dojo member')}</strong><small>${esc(account.email || 'Email available in Supabase Auth')} • Requested: ${esc(titleCase(account.requestedRole || 'parent'))} • ${esc(formatDate(account.createdAt))}</small><span class="verification-status ${verificationClass}">${esc(verificationText)}</span></div><div class="pending-account-actions"><select name="role" aria-label="Approved account role" ${account.emailVerified === false ? 'disabled' : ''}><option value="parent" ${account.requestedRole === 'parent' ? 'selected' : ''}>Parent / guardian</option><option value="student" ${account.requestedRole === 'student' ? 'selected' : ''}>Adult student</option></select><button class="btn btn-small btn-primary" type="submit" ${approvalDisabled}>Approve</button></div></form>`;
    }).join('')
    : `<p class="portal-muted">${esc(data.pendingAccountsError || 'No unapproved account requests.')}</p>`;

  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Administration</h2><p>Account invitations, approvals, and relationship management.</p></div><span class="role-pill">Administrator • AAL2</span></div>
    <section class="portal-panel"><div class="portal-panel-head"><div><h3>Pending self-registration requests</h3><p class="portal-muted">Approval activates only the login. Link the correct student separately.</p></div><span class="role-pill">${pendingAccounts.length}</span></div><div class="portal-list">${pendingMarkup}</div></section>
    <div class="portal-grid-2" style="margin-top:1rem">
      <section class="portal-panel"><h3>Invite account</h3><p class="portal-muted">The invitation link lets the user set a normal email/password login. The service key remains inside the Edge Function.</p>
        <form class="portal-form-grid" data-invite-form>
          <label class="portal-field full">Full name<input type="text" name="fullName" maxlength="120" required /></label>
          <label class="portal-field full">Email<input type="email" name="email" autocomplete="off" required /></label>
          <label class="portal-field full">Role<select name="role"><option value="parent">Parent / guardian</option><option value="student">Student account (teen/adult or parent-approved)</option><option value="instructor">Instructor</option><option value="admin">Administrator (server setting required)</option></select></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Send invitation</button></div>
        </form>
      </section>
      <section class="portal-panel"><h3>Create student record</h3>
        <form class="portal-form-grid" data-create-student-form>
          <label class="portal-field full">Display name<input type="text" name="display_name" maxlength="120" required /></label>
          <label class="portal-field">Age group<select name="age_group"><option value="child">Child</option><option value="youth">Youth</option><option value="teen">Teen</option><option value="adult">Adult</option></select></label>
          <label class="portal-field">Minor?<select name="is_minor"><option value="true">Yes</option><option value="false">No</option></select></label>
          <label class="portal-field full">Program<input type="text" name="program" maxlength="120" /></label>
          <label class="portal-field full">Current rank<select name="current_rank_id"><option value="">Not set</option>${rankOptions}</select></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Create student</button></div>
        </form>
      </section>
    </div>
    <div class="portal-grid-2">
      <section class="portal-panel"><h3>Link parent to student</h3>
        <form class="portal-form-grid" data-link-guardian-form>
          <label class="portal-field full">Parent account<select name="guardian_user_id" required><option value="">Choose parent</option>${parentOptions}</select></label>
          <label class="portal-field full">Student<select name="student_id" required><option value="">Choose student</option>${studentOptions}</select></label>
          <label class="portal-field full">Relationship<input type="text" name="relationship" maxlength="60" value="Parent" /></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Link records</button></div>
        </form>
      </section>
      <section class="portal-panel"><h3>Link student login</h3>
        <form class="portal-form-grid" data-link-student-account-form>
          <label class="portal-field full">Student account<select name="user_id" required><option value="">Choose account</option>${studentAccountOptions}</select></label>
          <label class="portal-field full">Student record<select name="student_id" required><option value="">Choose unlinked student</option>${unlinkedStudentOptions}</select></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Link login</button></div>
        </form>
      </section>
    </div>
    <div class="portal-grid-2">
      <section class="portal-panel"><h3>Enroll student in a class</h3>
        <form class="portal-form-grid" data-enrollment-form>
          <label class="portal-field full">Student<select name="student_id" required><option value="">Choose student</option>${studentOptions}</select></label>
          <label class="portal-field full">Class group<select name="class_group_id" required><option value="">Choose class</option>${classOptions}</select></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Save enrollment</button></div>
        </form>
      </section>
      <section class="portal-panel"><h3>Add billing-status item</h3><p class="portal-muted">Amounts and status only—never card or bank data.</p>
        <form class="portal-form-grid" data-billing-item-form>
          <label class="portal-field full">Student<select name="student_id" required><option value="">Choose student</option>${studentOptions}</select></label>
          <label class="portal-field full">Description<input type="text" name="description" maxlength="180" required /></label>
          <label class="portal-field">Amount (USD)<input type="number" name="amount" min="0" step="0.01" required /></label>
          <label class="portal-field">Due date<input type="date" name="due_on" /></label>
          <div class="portal-form-actions"><button class="btn btn-primary" type="submit">Add item</button></div>
        </form>
      </section>
    </div>
    <section class="portal-panel"><div class="portal-panel-head"><h3>Student records</h3><span>${data.students.length}</span></div>
      <div class="portal-table-wrap"><table class="portal-table"><thead><tr><th>Student</th><th>Program</th><th>Rank</th><th>Login linked</th></tr></thead><tbody>${data.students.map((student) => `<tr><td>${esc(student.display_name)}</td><td>${esc(student.program || titleCase(student.age_group))}</td><td>${esc(student.belt_ranks?.name || 'Not set')}</td><td>${student.user_id ? 'Yes' : 'No'}</td></tr>`).join('')}</tbody></table></div>
    </section>`;

  dom.content.querySelectorAll('[data-approve-account-form]').forEach((form) => form.addEventListener('submit', approvePendingAccount));
  dom.content.querySelector('[data-invite-form]')?.addEventListener('submit', inviteAccount);
  dom.content.querySelector('[data-create-student-form]')?.addEventListener('submit', createStudent);
  dom.content.querySelector('[data-link-guardian-form]')?.addEventListener('submit', linkGuardian);
  dom.content.querySelector('[data-link-student-account-form]')?.addEventListener('submit', linkStudentAccount);
  dom.content.querySelector('[data-enrollment-form]')?.addEventListener('submit', enrollStudent);
  dom.content.querySelector('[data-billing-item-form]')?.addEventListener('submit', createBillingItem);
}

async function loadAdminData() {
  if (state.demo) {
    state.adminData = {
      parentProfiles: [{ id: 'parent-1', full_name: 'Jordan Rivera' }],
      studentProfiles: [{ id: 'student-1', full_name: 'Alex Rivera' }],
      pendingAccounts: [{ id: 'pending-demo', fullName: 'Taylor Family', email: 'taylor.family@example.com', requestedRole: 'parent', createdAt: new Date().toISOString() }],
      students: state.students,
      ranks: demoData.ranks,
      classGroups: [{ id: 'cg1', name: 'Youth Fundamentals' }, { id: 'cg2', name: 'Teen & Adult Shotokan' }],
    };
    return;
  }
  const [profilesResult, studentsResult, ranksResult, classGroupsResult] = await Promise.all([
    state.supabase.from('profiles').select('id,full_name,role,active,approved_at,created_at').order('full_name'),
    state.supabase.from('students').select('id,user_id,display_name,age_group,program,status,current_rank_id,belt_ranks:current_rank_id(name)').order('display_name'),
    state.supabase.from('belt_ranks').select('id,name,level_order').eq('active', true).order('level_order'),
    state.supabase.from('class_groups').select('id,name').eq('active', true).order('name'),
  ]);
  if (profilesResult.error) throw profilesResult.error;
  if (studentsResult.error) throw studentsResult.error;
  if (ranksResult.error) throw ranksResult.error;
  if (classGroupsResult.error) throw classGroupsResult.error;
  const profiles = profilesResult.data || [];
  const activeProfiles = profiles.filter((profile) => profile.active);
  let pendingAccounts = profiles.filter((profile) => !profile.active && !profile.approved_at).map((profile) => ({
    id: profile.id,
    fullName: profile.full_name,
    requestedRole: profile.role,
    createdAt: profile.created_at,
  }));
  let pendingAccountsError = '';
  try {
    const response = await invokeManageAccounts('list-pending');
    pendingAccounts = response.accounts || pendingAccounts;
  } catch (error) {
    pendingAccountsError = friendlyOperationError(error, 'The pending-account helper is not deployed or available yet.');
  }
  state.adminData = {
    parentProfiles: activeProfiles.filter((profile) => profile.role === 'parent'),
    studentProfiles: activeProfiles.filter((profile) => profile.role === 'student'),
    pendingAccounts,
    pendingAccountsError,
    students: studentsResult.data || [],
    ranks: ranksResult.data || [],
    classGroups: classGroupsResult.data || [],
  };
}

async function invokeManageAccounts(action, payload = {}) {
  const functionName = encodeURIComponent(config.manageAccountsFunctionName || 'manage-accounts');
  const response = await fetch(`${config.supabaseUrl}/functions/v1/${functionName}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${state.session.access_token}`,
      apikey: config.supabasePublishableKey,
    },
    body: JSON.stringify({ action, ...payload }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || 'Account management request failed.');
  return body;
}

async function approvePendingAccount(event) {
  event.preventDefault();
  if (state.demo) return showAlert('Demo account approval simulated.', 'info');
  const form = new FormData(event.currentTarget);
  const userId = String(form.get('userId') || '');
  const role = String(form.get('role') || 'parent');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId) || !['parent', 'student'].includes(role)) {
    return showAlert('The approval request is invalid.', 'error');
  }
  const button = event.submitter;
  setBusy(button, true, 'Approving…');
  try {
    await invokeManageAccounts('approve', { userId, role });
    state.adminData = null;
    showAlert('Account approved. Now link it to the correct student record.', 'success');
    await renderAdmin();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The account could not be approved.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function inviteAccount(event) {
  event.preventDefault();
  if (state.demo) {
    showAlert('Demo invitation simulated. No email was sent.', 'info');
    return;
  }
  const button = event.submitter;
  const payload = Object.fromEntries(new FormData(event.currentTarget));
  setBusy(button, true, 'Sending…');
  try {
    const response = await fetch(`${config.supabaseUrl}/functions/v1/${encodeURIComponent(config.inviteFunctionName || 'invite-user')}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${state.session.access_token}`,
        apikey: config.supabasePublishableKey,
      },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Invitation failed.');
    event.currentTarget.reset();
    state.adminData = null;
    showAlert(`Invitation sent to ${payload.email}.`, 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The invitation could not be sent.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function createStudent(event) {
  event.preventDefault();
  if (state.demo) {
    showAlert('Demo student created locally only.', 'info');
    return;
  }
  const button = event.submitter;
  const form = new FormData(event.currentTarget);
  setBusy(button, true, 'Creating…');
  try {
    const rank = String(form.get('current_rank_id') || '');
    const { error } = await state.supabase.from('students').insert({
      display_name: String(form.get('display_name') || '').trim(),
      age_group: form.get('age_group'),
      is_minor: form.get('is_minor') === 'true',
      program: String(form.get('program') || '').trim() || null,
      current_rank_id: rank ? Number(rank) : null,
      created_by: state.user.id,
    });
    if (error) throw error;
    event.currentTarget.reset();
    state.adminData = null;
    await loadAccessibleStudents();
    renderStudentSwitcher();
    showAlert('Student record created.', 'success');
    await renderAdmin();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The student could not be created.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function linkGuardian(event) {
  event.preventDefault();
  if (state.demo) {
    showAlert('Demo relationship linked locally only.', 'info');
    return;
  }
  const button = event.submitter;
  const form = new FormData(event.currentTarget);
  setBusy(button, true, 'Linking…');
  try {
    const { error } = await state.supabase.from('guardian_students').upsert({
      guardian_user_id: form.get('guardian_user_id'),
      student_id: form.get('student_id'),
      relationship: String(form.get('relationship') || 'Parent').trim(),
      active: true,
      created_by: state.user.id,
    }, { onConflict: 'guardian_user_id,student_id' });
    if (error) throw error;
    showAlert('Parent and student records linked.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The relationship could not be linked.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function enrollStudent(event) {
  event.preventDefault();
  if (state.demo) {
    showAlert('Demo enrollment saved locally only.', 'info');
    return;
  }
  const button = event.submitter;
  const form = new FormData(event.currentTarget);
  setBusy(button, true, 'Saving…');
  try {
    const { error } = await state.supabase.from('enrollments').upsert({
      student_id: form.get('student_id'),
      class_group_id: form.get('class_group_id'),
      active: true,
      ended_on: null,
      created_by: state.user.id,
    }, { onConflict: 'student_id,class_group_id' });
    if (error) throw error;
    showAlert('Class enrollment saved.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The enrollment could not be saved.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function createBillingItem(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const amount = Number(form.get('amount'));
  if (!Number.isFinite(amount) || amount < 0) {
    showAlert('Enter a valid non-negative amount.', 'error');
    return;
  }
  if (state.demo) {
    showAlert('Demo billing item created locally only.', 'info');
    return;
  }
  const button = event.submitter;
  setBusy(button, true, 'Adding…');
  try {
    const dueOn = String(form.get('due_on') || '');
    const { error } = await state.supabase.from('billing_items').insert({
      student_id: form.get('student_id'),
      description: String(form.get('description') || '').trim(),
      amount_cents: Math.round(amount * 100),
      due_on: dueOn || null,
      status: 'open',
      created_by: state.user.id,
    });
    if (error) throw error;
    event.currentTarget.reset();
    state.studentDetails = null;
    showAlert('Billing-status item added.', 'success');
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The billing item could not be added.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function linkStudentAccount(event) {
  event.preventDefault();
  if (state.demo) {
    showAlert('Demo student login linked locally only.', 'info');
    return;
  }
  const button = event.submitter;
  const form = new FormData(event.currentTarget);
  setBusy(button, true, 'Linking…');
  try {
    const { error } = await state.supabase.from('students').update({ user_id: form.get('user_id') }).eq('id', form.get('student_id'));
    if (error) throw error;
    state.adminData = null;
    showAlert('Student login linked.', 'success');
    await renderAdmin();
  } catch (error) {
    showAlert(friendlyOperationError(error, 'The student login could not be linked.'), 'error');
  } finally {
    setBusy(button, false);
  }
}

function passwordRulesMarkup(policy) {
  const rules = [
    ['length', `${policy.minimumLength}–${policy.maximumLength} characters`],
    ['uppercase', 'At least one uppercase letter'],
    ['lowercase', 'At least one lowercase letter'],
    ['number', 'At least one number'],
    ['symbol', 'At least one special character'],
    ['repeats', 'No three identical characters in a row'],
    ['sequences', 'No obvious four-character sequence'],
    ['personal', 'Does not contain your name or email name'],
    ['common', 'Not a common or dojo-themed password'],
  ];
  return rules.map(([key, label]) => `<li data-password-rule="${key}">${esc(label)}</li>`).join('');
}

async function loadAccountSecurityData() {
  if (state.demo) {
    state.accountSecurity = {
      identities: [{ provider: 'email' }, { provider: 'google' }],
      passkeys: [{ id: 'demo-passkey', friendly_name: 'Demo device passkey', created_at: new Date().toISOString() }],
    };
    return state.accountSecurity;
  }

  const result = { identities: state.user?.identities || [], passkeys: [] };
  try {
    const { data, error } = await state.supabase.auth.getUserIdentities();
    if (!error && data?.identities) result.identities = data.identities;
  } catch { /* identity display is non-critical */ }

  if (safeBoolean(config.passkeysEnabled, false) && state.supabase.auth.passkey?.list) {
    try {
      const { data, error } = await state.supabase.auth.passkey.list();
      if (!error) result.passkeys = Array.isArray(data) ? data : (data?.passkeys || []);
    } catch { /* passkey display is non-critical */ }
  }
  state.accountSecurity = result;
  return result;
}

async function renderAccount() {
  const securityData = await loadAccountSecurityData();
  const providers = new Set((securityData.identities || []).map((identity) => String(identity.provider || '').toLowerCase()).filter(Boolean));
  if (!providers.size && state.user?.email) providers.add('email');
  const hasPasswordIdentity = providers.has('email');
  const passkeyReady = safeBoolean(config.passkeysEnabled, false) && Boolean(state.supabase?.auth?.registerPasskey);
  const mfaLabel = state.demo ? 'Demo only' : (isAal2() ? 'Enabled and verified' : 'Not enabled');
  const staffWarning = isStaff() && !isAal2() && !state.demo
    ? '<div class="aal-warning"><strong>MFA required:</strong> staff data and write operations remain locked until you enroll an authenticator app.</div>'
    : '';
  const methodLabels = [...providers].map((provider) => {
    const label = provider === 'email' ? 'Email + password' : provider === 'google' ? 'Google' : titleCase(provider);
    return `<span class="connected-method">${esc(label)}</span>`;
  }).join('') || '<span class="portal-muted">No identity information returned.</span>';
  const passkeys = securityData.passkeys || [];
  const passkeyRows = passkeys.length
    ? passkeys.map((passkey) => `<div class="passkey-row"><div><strong>${esc(passkey.friendly_name || 'Passkey')}</strong><small>Added ${esc(formatDate(passkey.created_at))}${passkey.last_used_at ? ` • Last used ${esc(formatDate(passkey.last_used_at))}` : ''}</small></div><button class="danger-text-button" type="button" data-delete-passkey="${esc(passkey.id)}">Remove</button></div>`).join('')
    : '<p class="portal-muted">No passkeys registered on this account.</p>';
  const policy = passwordPolicy();
  const currentPasswordField = hasPasswordIdentity ? `<label class="portal-field full">Current password<span class="password-input-wrap"><input type="password" name="currentPassword" autocomplete="current-password" maxlength="${policy.maximumLength}" autocapitalize="none" spellcheck="false" required /><button class="password-toggle" type="button" data-toggle-password aria-pressed="false">Show</button></span><span class="caps-lock-warning" data-caps-lock hidden>Caps Lock is on.</span></label>` : '';

  dom.content.innerHTML = `
    <div class="portal-page-heading"><div><h2>Account & security</h2><p>Manage the security of your own login.</p></div><span class="role-pill">${esc(titleCase(state.profile?.role || 'account'))}</span></div>
    ${staffWarning}
    <div class="session-security-note"><span aria-hidden="true">🔒</span><span>This portal closes the local session after ${Math.max(0, Number(config.idleTimeoutMinutes) || 0)} minutes of inactivity and, by default, does not keep the login after the browser closes.</span></div>
    <div class="portal-grid-2" style="margin-top:1rem">
      <section class="portal-panel"><h3>Account details</h3><div class="portal-list"><div class="portal-list-item"><div><strong>Name</strong></div><div>${esc(state.profile?.full_name || '')}</div></div><div class="portal-list-item"><div><strong>Email</strong></div><div>${esc(state.user?.email || (state.demo ? 'demo@example.com' : ''))}</div></div><div class="portal-list-item"><div><strong>Role</strong></div><div>${esc(titleCase(state.profile?.role || ''))}</div></div></div><h4>Connected sign-in methods</h4><div class="connected-methods">${methodLabels}</div></section>
      <section class="portal-panel"><h3>Multi-factor authentication</h3><p class="portal-muted">Authenticator MFA protects the account even if a password is stolen.</p><div class="portal-list-item"><div><strong>Status</strong></div><div>${esc(mfaLabel)}</div></div><button class="btn btn-primary" type="button" data-account-enable-mfa ${isAal2() ? 'disabled' : ''}>${isAal2() ? 'MFA enabled' : 'Enable authenticator MFA'}</button></section>
    </div>
    <section class="portal-panel"><div class="portal-panel-head"><div><h3>Passkeys</h3><p class="portal-muted">Use your device PIN, biometric unlock, password manager, or hardware key instead of typing a password.</p></div>${passkeyReady ? '<button class="btn btn-secondary" type="button" data-register-passkey>Add passkey</button>' : ''}</div><div class="passkey-list">${passkeyRows}</div>${!passkeyReady ? '<p class="portal-muted">Passkeys remain off until the production domain and WebAuthn settings are configured.</p>' : ''}</section>
    <section class="portal-panel" style="margin-top:1rem"><h3>${hasPasswordIdentity ? 'Change password' : 'Set a password'}</h3><p class="portal-muted">Use a password manager and a unique password. Do not reuse your Google password.</p>
      <form class="portal-form-grid" data-account-password-form novalidate>
        ${currentPasswordField}
        <label class="portal-field full">New password<span class="password-input-wrap"><input type="password" name="password" autocomplete="new-password" minlength="${policy.minimumLength}" maxlength="${policy.maximumLength}" autocapitalize="none" spellcheck="false" required data-password-input /><button class="password-toggle" type="button" data-toggle-password aria-pressed="false">Show</button></span><span class="caps-lock-warning" data-caps-lock hidden>Caps Lock is on.</span></label>
        <div class="password-feedback portal-field full" data-password-feedback aria-live="polite"><div class="password-strength-row"><span>Password strength</span><strong data-password-label>Not entered</strong></div><progress class="password-strength" data-password-progress max="4" value="0">0 of 4</progress><ul class="password-rules">${passwordRulesMarkup(policy)}</ul></div>
        <label class="portal-field full">Confirm password<span class="password-input-wrap"><input type="password" name="confirmPassword" autocomplete="new-password" minlength="${policy.minimumLength}" maxlength="${policy.maximumLength}" autocapitalize="none" spellcheck="false" required /><button class="password-toggle" type="button" data-toggle-password aria-pressed="false">Show</button></span><span class="password-match" data-password-match aria-live="polite"></span></label>
        <div class="portal-form-actions"><button class="btn btn-primary" type="submit">${hasPasswordIdentity ? 'Change password' : 'Set password'}</button></div>
      </form>
    </section>
    <section class="portal-panel" style="margin-top:1rem"><h3>Privacy</h3><p>Do not place card data, Social Security numbers, government identifiers, or unnecessary medical details in this portal. Review the <a href="privacy.html">privacy and data handling page</a>.</p></section>`;

  dom.content.querySelector('[data-account-enable-mfa]')?.addEventListener('click', beginMfaEnrollment);
  const passwordForm = dom.content.querySelector('[data-account-password-form]');
  passwordForm?.addEventListener('submit', changePasswordFromAccount);
  wirePasswordForm(passwordForm);
  dom.content.querySelector('[data-register-passkey]')?.addEventListener('click', registerPasskeyFromAccount);
  dom.content.querySelectorAll('[data-delete-passkey]').forEach((button) => button.addEventListener('click', deletePasskeyFromAccount));
}

async function changePasswordFromAccount(event) {
  event.preventDefault();
  const formElement = event.currentTarget;
  const passwordCheck = validateNewPasswordForm(formElement);
  if (!passwordCheck.valid) return showAlert(passwordCheck.message, 'error');
  if (state.demo) return showAlert('Demo password was not changed.', 'info');
  const currentPassword = String(new FormData(formElement).get('currentPassword') || '');
  const requiresCurrent = Boolean(formElement.elements.currentPassword);
  if (requiresCurrent && !currentPassword) return showAlert('Enter the current password.', 'error');
  const button = event.submitter;
  setBusy(button, true, 'Changing…');
  try {
    const payload = {
      password: passwordCheck.password,
      ...(currentPassword ? { current_password: currentPassword } : {}),
    };
    const { error } = await state.supabase.auth.updateUser(payload);
    if (error) throw error;
    formElement.reset();
    updatePasswordFeedback(formElement);
    showAlert('Password changed.', 'success');
  } catch (error) {
    showAlert(friendlyAuthError(error), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function registerPasskeyFromAccount(event) {
  const button = event.currentTarget;
  if (state.demo) return showAlert('Demo passkey enrollment was simulated.', 'info');
  if (!state.supabase?.auth?.registerPasskey || !safeBoolean(config.passkeysEnabled, false)) return;
  setBusy(button, true, 'Opening device…');
  try {
    const { error } = await state.supabase.auth.registerPasskey();
    if (error) throw error;
    showAlert('Passkey registered.', 'success');
    await renderAccount();
  } catch (error) {
    showAlert(friendlyAuthError(error), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function deletePasskeyFromAccount(event) {
  const button = event.currentTarget;
  const passkeyId = String(button.dataset.deletePasskey || '');
  if (!passkeyId || state.demo) return showAlert('Demo passkey was not removed.', 'info');
  if (!window.confirm('Remove this passkey from your account?')) return;
  setBusy(button, true, 'Removing…');
  try {
    const { error } = await state.supabase.auth.passkey.delete({ passkeyId });
    if (error) throw error;
    showAlert('Passkey removed.', 'success');
    await renderAccount();
  } catch (error) {
    showAlert(friendlyAuthError(error), 'error');
  } finally {
    setBusy(button, false);
  }
}

async function beginMfaEnrollment() {
  if (state.demo) {
    showAlert('MFA enrollment is available after the Supabase project is connected.', 'info');
    return;
  }
  if (!state.supabase || isAal2()) return;
  dom.mfaStatus.textContent = '';
  dom.mfaModal.hidden = false;
  dom.mfaQr.removeAttribute('src');
  dom.mfaSecret.textContent = 'Preparing QR code…';

  try {
    const { data: factors } = await state.supabase.auth.mfa.listFactors();
    const unverified = factors?.all?.filter((factor) => factor.status === 'unverified') || [];
    for (const factor of unverified) {
      await state.supabase.auth.mfa.unenroll({ factorId: factor.id });
    }
    const { data, error } = await state.supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'SKIF Dojo Portal' });
    if (error) throw error;
    state.enrollFactorId = data.id;
    dom.mfaQr.src = data.totp.qr_code;
    dom.mfaSecret.textContent = data.totp.secret ? `Manual setup key: ${data.totp.secret}` : '';
  } catch (error) {
    dom.mfaStatus.textContent = friendlyAuthError(error);
  }
}

async function handleMfaEnrollmentVerify(event) {
  event.preventDefault();
  const code = String(new FormData(event.currentTarget).get('code') || '').trim();
  const button = event.submitter;
  if (!state.enrollFactorId) return;
  setBusy(button, true, 'Verifying…');
  dom.mfaStatus.textContent = '';
  try {
    const { data: challenge, error: challengeError } = await state.supabase.auth.mfa.challenge({ factorId: state.enrollFactorId });
    if (challengeError) throw challengeError;
    const { error: verifyError } = await state.supabase.auth.mfa.verify({ factorId: state.enrollFactorId, challengeId: challenge.id, code });
    if (verifyError) throw verifyError;
    closeMfaModal();
    const { data } = await state.supabase.auth.getSession();
    await handleAuthenticatedSession(data.session);
    showAlert('Authenticator MFA enabled.', 'success');
  } catch (error) {
    dom.mfaStatus.textContent = friendlyAuthError(error);
  } finally {
    setBusy(button, false);
  }
}

function closeMfaModal() {
  dom.mfaModal.hidden = true;
  state.enrollFactorId = null;
  const form = document.querySelector('[data-mfa-enroll-form]');
  form?.reset();
}

function bindCommonContentEvents() {
  dom.content.querySelectorAll('[data-jump-route]').forEach((button) => button.addEventListener('click', async () => {
    state.route = button.dataset.jumpRoute;
    await renderRoute();
  }));
}

function enterDemo(role) {
  const staffDemo = ['instructor', 'admin'].includes(role);
  const demoIdentity = role === 'parent'
    ? { id: 'demo-parent', email: 'parent.demo@example.com', fullName: 'Jordan Rivera' }
    : role === 'admin'
      ? { id: 'demo-admin', email: 'admin.demo@example.com', fullName: 'Dojo Administrator' }
      : { id: 'demo-instructor', email: 'instructor.demo@example.com', fullName: 'Sensei Rivera' };
  state.demo = true;
  state.session = { access_token: 'demo' };
  state.user = { id: demoIdentity.id, email: demoIdentity.email };
  state.profile = { id: state.user.id, full_name: demoIdentity.fullName, role, active: true };
  state.aal = { currentLevel: staffDemo ? 'aal2' : 'aal1', nextLevel: staffDemo ? 'aal2' : 'aal1' };
  state.students = structuredClone(demoData.students);
  state.studentId = state.students[0].id;
  state.studentDetails = null;
  state.announcements = structuredClone(demoData.announcements);
  state.route = 'overview';
  openDashboard();
}

async function signOut() {
  stopIdleSecurity();
  if (state.demo) {
    state.demo = false;
    resetToLogin();
    showAuthView(isConfigured ? 'login' : 'setup');
    return;
  }
  try {
    await state.supabase?.auth.signOut();
  } catch (error) {
    console.warn('Remote sign-out failed; clearing the local session.', { code: String(error?.code || error?.status || '').slice(0, 80) });
  } finally {
    resetToLogin();
  }
}

function resetToLogin() {
  stopIdleSecurity();
  state.session = null;
  state.user = null;
  state.profile = null;
  state.aal = { currentLevel: 'aal1', nextLevel: 'aal1' };
  state.students = [];
  state.studentId = null;
  state.studentDetails = null;
  state.announcements = [];
  state.staffSessions = [];
  state.staffClassGroups = [];
  state.adminData = null;
  state.attendanceSessionId = null;
  state.attendanceRoster = [];
  state.accountSecurity = { identities: [], passkeys: [] };
  state.recoveryMode = false;
  state.idleWarningShown = false;
  showAlert('');
  document.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ''; });
  dom.dashboard.hidden = true;
  dom.authArea.hidden = false;
  showAuthView(isConfigured ? 'login' : 'setup');
}

function friendlyOperationError(error, fallback = 'The request could not be completed.') {
  const message = String(error?.message || error?.details || '');
  const code = String(error?.code || error?.status || '');
  const combined = `${code} ${message}`;
  if (/jwt|session|auth|token.*expired|not authenticated/i.test(combined)) return 'Your secure session expired. Sign in again.';
  if (/42501|row.level|permission|not authorized|forbidden/i.test(combined)) return 'Your account is not authorized to perform that action.';
  if (/23505|duplicate|already exists|unique constraint/i.test(combined)) return 'That record already exists.';
  if (/23503|foreign key|referenced record/i.test(combined)) return 'A required linked record is missing or no longer available.';
  if (/verify.*email|email.*verified|confirm.*email/i.test(combined)) return 'The user must verify the email address before approval.';
  if (/already active|already approved|cannot be approved/i.test(combined)) return 'That account is already active or is no longer awaiting approval.';
  if (/network|failed to fetch|load failed|timeout/i.test(combined)) return 'The secure service could not be reached. Check the connection and try again.';
  console.warn('Portal operation failed.', { code: code.slice(0, 80) });
  return fallback;
}

function friendlyAuthError(error) {
  const message = String(error?.message || error?.error_description || 'Authentication failed.');
  const code = String(error?.code || error?.name || '');
  const combined = `${code} ${message}`;
  if (/invalid login credentials|invalid_credentials/i.test(combined)) return 'The email or password is incorrect.';
  if (/email not confirmed|email_not_confirmed/i.test(combined)) return 'Confirm your email before signing in.';
  if (/captcha|security check|challenge failed/i.test(combined)) return 'The security check was not accepted. Complete it again.';
  if (/rate limit|over_request_rate_limit|too many requests/i.test(combined)) return 'Too many attempts. Wait a few minutes and try again.';
  if (/weak password|password.*(weak|pwned|breach)|same password/i.test(combined)) return 'Choose a different, unique password that satisfies every requirement.';
  if (/current.?password|reauthentication|reauth/i.test(combined)) return 'The current password is incorrect or the session must be verified again.';
  if (/notallowederror|aborterror|passkey.*cancel|webauthn.*cancel|operation.*timed out/i.test(combined)) return 'The passkey request was cancelled or timed out.';
  if (/passkey|webauthn|publickeycredential/i.test(combined)) return 'Passkey sign-in is not available for this account or device.';
  if (/oauth|provider.*not.*enabled|unsupported provider/i.test(combined)) return 'Google sign-in is not available right now. Use email and password or contact the dojo.';
  if (/network|failed to fetch|load failed/i.test(combined)) return 'The secure login service could not be reached. Check the connection and try again.';
  if (/session.*(invalid|expired)|jwt.*expired/i.test(combined)) return 'Your secure session expired. Sign in again.';
  console.warn('Authentication request failed.', { code: code.slice(0, 80) });
  return 'The request could not be completed securely. Try again or contact the dojo.';
}

initialize().catch((error) => {
  showAuthView(isConfigured ? 'login' : 'setup');
  setAuthStatus(friendlyOperationError(error, 'The portal could not start securely. Refresh the page.'));
});
