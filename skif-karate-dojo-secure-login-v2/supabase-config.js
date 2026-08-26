/*
  Browser-safe configuration only.
  Never place a Supabase service-role/secret key, CAPTCHA secret, Google client
  secret, or database password in this file.
*/
window.SKIF_CONFIG = Object.freeze({
  supabaseUrl: 'YOUR_SUPABASE_PROJECT_URL',
  supabasePublishableKey: 'YOUR_SUPABASE_PUBLISHABLE_KEY',

  inviteFunctionName: 'invite-user',
  manageAccountsFunctionName: 'manage-accounts',
  demoMode: true,

  // Modern login choices. Enable each only after completing DEPLOYMENT.md.
  selfRegistrationEnabled: true,
  googleOAuthEnabled: false,
  passkeysEnabled: false, // Supabase currently marks passkeys experimental.

  // Cloudflare Turnstile. The public site key is safe in the browser; the
  // secret key belongs only in the Supabase dashboard.
  turnstileSiteKey: '',

  // Strict policy requested for this portal. Supabase must enforce matching
  // server-side settings; browser validation is only the first layer.
  passwordMinimumLength: 15,
  passwordMaximumLength: 128,
  passwordRequireUppercase: true,
  passwordRequireLowercase: true,
  passwordRequireNumber: true,
  passwordRequireSymbol: true,
  passwordRejectTripleRepeats: true,
  passwordRejectSequences: true,
  passwordRejectPersonalInfo: true,
  passwordRejectCommonPasswords: true,

  // Safer shared-device defaults. Sessions use sessionStorage and close with
  // the browser unless rememberSession is explicitly enabled.
  rememberSession: false,
  idleTimeoutMinutes: 30,
  idleWarningMinutes: 2,
});
