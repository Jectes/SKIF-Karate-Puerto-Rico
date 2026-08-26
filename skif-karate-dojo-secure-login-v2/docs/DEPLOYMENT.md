# Production Deployment

The package runs as a local demo immediately. These steps connect it to a real Supabase Auth/PostgreSQL backend and enable the hardened login features.

## 1. Finish the dojo information before collecting data

Replace every public placeholder:

- official address, phone/WhatsApp, email, schedule, and instructor information
- `[PRIVACY EMAIL]`, `[SECURITY CONTACT]`, and other bracketed fields in `privacy.html`
- the generic belt requirements in `supabase/seed.sql` with the dojo-approved syllabus
- approved retention periods for accounts, student records, attendance, billing status, consent, audit history, and backups

Do not enter real child or family data while the privacy notice still says **Draft**.

## 2. Create the Supabase project

1. Create a project in the appropriate region.
2. Record only the project URL and **publishable** key for the browser.
3. Never copy a service-role/secret key into HTML, browser JavaScript, a screenshot, Git, or a support message.
4. Configure the final Site URL and exact allowed redirect URLs, including the production `portal.html` URL.
5. Configure production SMTP or another reliable transactional-email service before inviting families.

## 3. Configure email/password authentication

In the Auth settings:

1. Keep email/password authentication enabled.
2. Allow email sign-up because this package supports family self-registration.
3. Require email confirmation before the account can be approved.
4. Set the provider minimum password length to **15 characters**.
5. Require digits, lowercase letters, uppercase letters, and symbols.
6. Enable leaked-password rejection when available for the selected plan.
7. Keep secure password-change protections enabled. The account page supplies the current password when the identity has a password provider.
8. Review Auth rate limits and tighten them based on expected dojo traffic.

The browser also checks repeated characters, obvious sequences, personal information, and a local common-password list. Those extra checks improve the normal website experience, but the provider-level minimum/composition/leaked-password settings are the server-enforced password controls.

Do not require routine password rotation without evidence of compromise. Encourage unique passwords, password managers, paste, and autofill.

## 4. Configure Cloudflare Turnstile CAPTCHA

Turnstile is feature-gated and disabled in the sample configuration.

1. Create a Turnstile site for the final production domain.
2. In Supabase Auth bot/abuse protection, enable CAPTCHA, select Cloudflare Turnstile, and enter the **secret key**.
3. Put only the public **site key** in `supabase-config.js` as `turnstileSiteKey`.
4. Add the exact production and staging hostnames to the Turnstile configuration.
5. Test sign-up, password sign-in, passkey sign-in, and password recovery.

The portal passes the CAPTCHA token to Auth and resets the widget after each attempt. A CAPTCHA reduces automated abuse; it does not replace rate limits, email verification, approval, MFA, or RLS.

## 5. Configure Google sign-in

Google sign-in is implemented but disabled until the provider is configured.

1. Create or select a Google Cloud project.
2. Configure the Google OAuth consent/branding screen.
3. Create a Web application OAuth client.
4. Add the website's exact HTTPS origin under authorized JavaScript origins.
5. Add the Supabase callback URL shown by the Google provider configuration—normally `https://YOUR_PROJECT_REF.supabase.co/auth/v1/callback`—as an authorized redirect URI in Google.
6. Enable the Google provider in Supabase and enter the client ID and client secret there.
7. Confirm the Supabase Site URL and redirect allowlist include the final portal URL.
8. Set `googleOAuthEnabled: true` in `supabase-config.js`.

Google users are still subject to the same inactive-profile and dojo-approval process. A successful Google login alone does not grant access to a student.

Use verified branding and, where practical, a custom Auth domain so families can more easily recognize the legitimate login flow.

## 6. Configure optional passkeys

Passkey support in the selected Supabase client is currently experimental. Keep it off until it has been tested on the final domain.

1. Choose the final stable HTTPS domain before anyone enrolls a passkey.
2. Enable passkeys in Supabase Auth.
3. Set a human-readable relying-party display name.
4. Set the relying-party ID to the bare domain, without scheme, port, or path.
5. Add exact allowed HTTPS origins.
6. Set `passkeysEnabled: true` in `supabase-config.js`.
7. Test enrollment, sign-in, listing, deletion, device loss, and account recovery on major browsers and mobile devices.

Changing the relying-party ID later makes existing passkeys unusable. Keep password/recovery access available during the experimental rollout and document a verified recovery process.

## 7. Create the database

Open the Supabase SQL editor and run, in this order:

1. `supabase/schema.sql`
2. `supabase/seed.sql`

The schema creates all application tables, indexes, triggers, audit functions, grants, and RLS policies. The seed file contains generic reference data only; it creates no real families or students.

Every Auth identity receives an inactive `profiles` record. Self-registration metadata cannot activate the account or promote its role.

## 8. Bootstrap the first administrator

1. In **Authentication > Users**, create or invite the first administrator account.
2. Confirm its email.
3. Open `supabase/bootstrap-admin.sql`.
4. Replace both occurrences of `REPLACE_WITH_ADMIN_EMAIL@example.com` with the exact email.
5. Run the SQL and confirm the final query returns exactly one active `admin` profile.
6. Sign in and enroll an authenticator app immediately.
7. Sign out, sign back in, complete the MFA challenge, and confirm the session reaches AAL2.

Leave `ALLOW_ADMIN_INVITES=false` unless there is a documented need for an administrator to invite another administrator.

## 9. Deploy both Edge Functions

Install/authenticate the Supabase CLI, link the project, and run from the package root:

```bash
supabase login
supabase link --project-ref YOUR_PROJECT_REF

supabase secrets set \
  ALLOWED_ORIGINS="https://YOUR-DOMAIN.example,https://staging.YOUR-DOMAIN.example,http://localhost:8000" \
  PORTAL_REDIRECT_URL="https://YOUR-DOMAIN.example/portal.html" \
  ALLOW_ADMIN_INVITES="false"

supabase functions deploy invite-user
supabase functions deploy manage-accounts
```

For local function testing, copy `.env.example` to a private `.env` file. Never commit or deploy that file with the static website.

Both functions must retain these controls:

- `verify_jwt = true` in `supabase/config.toml`
- exact production origins instead of `*`
- valid Auth session verification
- AAL2 MFA requirement
- active administrator-profile requirement
- strict action/input validation and request-size limits
- service-role/secret key only in the function environment

`invite-user` sends staff-controlled invitations. `manage-accounts` lists inactive self-registrations and approves only verified `parent` or `student` requests. It cannot self-service an instructor or administrator role.

## 10. Connect the browser

Edit `supabase-config.js`:

```js
window.SKIF_CONFIG = Object.freeze({
  supabaseUrl: 'https://YOUR_PROJECT_REF.supabase.co',
  supabasePublishableKey: 'sb_publishable_YOUR_KEY',
  inviteFunctionName: 'invite-user',
  manageAccountsFunctionName: 'manage-accounts',

  demoMode: true,
  selfRegistrationEnabled: true,
  googleOAuthEnabled: true,
  passkeysEnabled: false,
  turnstileSiteKey: 'YOUR_PUBLIC_TURNSTILE_SITE_KEY',

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

  rememberSession: false,
  idleTimeoutMinutes: 30,
  idleWarningMinutes: 2,
});
```

The project URL, publishable key, provider flags, and Turnstile site key are public browser configuration. The service-role/secret key, Google client secret, Turnstile secret, SMTP credentials, and backup credentials are server-only.

Keep `demoMode: true` through staging. Set it to `false` only after the authorization matrix passes.

## 11. Host over HTTPS with security headers

The package includes `_headers` and `vercel.json` examples. Deploy to HTTPS only and verify the headers in the actual production response, not merely in the repository.

Update when needed:

- CSP `connect-src` for a Supabase custom domain
- CSP script/frame sources if the CAPTCHA provider changes
- `ALLOWED_ORIGINS` for both Edge Functions
- Supabase Site URL and redirect allowlist
- Google OAuth authorized origins/redirects
- Turnstile hostnames
- passkey relying-party ID/origins
- `PORTAL_REDIRECT_URL`

Do not deploy `.env`, SQL-editor exports, backups, logs, or private keys in the public site directory.

## 12. Production account workflows

### Self-registration

1. Parent/guardian or adult student creates an account using their own email and password.
2. Auth sends an email-confirmation link.
3. The database profile remains inactive.
4. An AAL2 administrator reviews the pending request.
5. The administrator approves only the correct role.
6. The administrator creates or identifies the student record and links the parent/student account.
7. Only then can RLS return the linked student information.

### Administrator invitation

1. An AAL2 administrator sends an invitation.
2. The recipient confirms the address and chooses a password.
3. The administrator creates/links the relevant student relationship and enrollment.

For children under 13, use a parent-managed login by default. Do not issue a direct child account or collect information directly from a child until the dojo has resolved applicable notice/consent requirements.

## 13. Session policy

The browser stores the session in `sessionStorage` by default, so closing the tab/window removes that browser copy. The portal also performs a client-side inactivity logout after the configured interval.

Treat client-side idle logout as convenience and defense-in-depth, not the sole session-control boundary. Review Supabase server-side session timebox, inactivity, refresh-token, and concurrent-session settings for the dojo's risk level. Test multiple devices, password changes, account disabling, staff offboarding, and explicit sign-out.

## 14. Final release gate

Production is not ready until all of these are true:

- anonymous requests cannot read any application table
- two unrelated test families cannot read each other's students through either UI or direct API calls
- a newly registered or Google-created identity remains inactive
- an unverified pending email cannot be approved
- pending approval can grant only `parent` or `student`
- a parent/student sees nothing until explicitly linked
- an AAL1 instructor cannot read student records
- an AAL2 instructor can read/write authorized training records but cannot read billing
- an AAL1 administrator cannot perform sensitive administration
- an AAL2 administrator can manage relationships, pending accounts, and billing status
- disabling a profile removes application access even with an existing Auth session
- CAPTCHA, recovery, Google, and optional passkeys have been tested on staging
- the provider rejects too-short/noncompliant/leaked passwords as configured
- no service-role/secret key or provider secret exists in public files or Git history
- security headers are present on the deployed HTTPS site
- backups and restoration have been tested
- privacy contacts, actual providers, and retention periods are published

The full test matrix is in `docs/SECURITY.md`.
