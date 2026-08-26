# S.K.I.F. Puerto Rico Honbu Dojo — Hardened Login & Family Portal

This package upgrades the original static karate website into a student, parent, instructor, and administrator portal backed by Supabase Auth and PostgreSQL Row Level Security (RLS).

## Login experience included

- Users may create an account with **their own email address and password**.
- New accounts must confirm the email and remain inactive until a dojo administrator approves the requested role and links the correct student.
- Optional **Continue with Google** login.
- Optional **passkey/WebAuthn** login and passkey management.
- Password recovery that does not reveal whether an email exists.
- Show/hide password controls, Caps Lock warning, password-manager/autofill support, and generic authentication errors.
- Cloudflare Turnstile CAPTCHA integration for sign-up, sign-in, passkey sign-in, and recovery when configured.
- Authenticator-app MFA and AAL2 enforcement for instructors and administrators.
- Session storage by default plus a 30-minute client-side inactivity timeout.

## Password controls

The live password meter requires, by default:

- 15–128 characters
- uppercase and lowercase letters
- at least one number
- at least one special character
- no three identical characters in a row
- no obvious four-character keyboard/alphabet/number sequence
- no usable portion of the person's name or email name
- no common or dojo-themed password

Configure the Supabase Auth provider to enforce the 15-character minimum, upper/lower/digit/symbol requirements, and leaked-password rejection on the server. The extra repeat, sequence, personal-information, and local common-password checks run in the browser as an additional usability/security layer; they are not a substitute for provider-side policy.

## Portal features

- Parent-to-student and optional student-login relationships
- Belt rank and requirement progress
- Class groups, enrollments, sessions, and attendance
- Badges, goals, family-visible notes, and staff-only notes
- Role-filtered announcements
- Billing **status and amount only**—no payment-card storage
- Consent records and metadata-only audit logging
- Pending self-registration review for administrators
- A local demo mode containing fictional records only

## Security architecture

- Supabase Auth owns email/password, Google identity, passkeys, recovery, and MFA.
- The application database contains no password column.
- All 18 application tables have RLS enabled.
- Parents and students can only read linked records.
- Instructor/admin data access requires an AAL2 MFA session where specified by the database policies.
- Browser values are escaped before HTML rendering.
- Edge Functions validate JWTs, MFA assurance, administrator status, origin, input size, and allowed actions.
- Service-role/secret keys remain server-side and never belong in `supabase-config.js`.
- CSP and related response headers restrict scripts, frames, connections, browser permissions, and caching of the portal/configuration pages.

No web application is literally “injection-proof.” This package uses layered controls so a single mistake does not automatically expose every family record. Review `docs/SECURITY.md` before production deployment.

## Important status

The code and database design are ready for staging, but this ZIP is not connected to a live Supabase project. The default configuration keeps demo mode on and leaves Google, passkeys, and CAPTCHA off until their provider settings are supplied.

Do not enter real family or child information until:

1. the database has been deployed to a staging Supabase project;
2. email confirmation, provider password policy, CAPTCHA, and production email have been configured;
3. the RLS test matrix has passed with two unrelated test families;
4. official privacy contacts and retention periods have replaced the placeholders; and
5. the production site is hosted over HTTPS.

## Important files

- `index.html` — public dojo website
- `portal.html` / `portal.js` — login, onboarding, dashboard, account, MFA, and passkey workflows
- `auth-security.js` — password meter, normalization, and password-rule checks
- `supabase-config.js` — public browser feature flags; **never place a service key here**
- `supabase/schema.sql` — database, triggers, indexes, RLS policies, and audit controls
- `supabase/seed.sql` — editable starter ranks, requirements, groups, badges, and announcement
- `supabase/bootstrap-admin.sql` — one-time first-administrator setup
- `supabase/functions/invite-user/index.ts` — MFA-protected administrator invitations
- `supabase/functions/manage-accounts/index.ts` — MFA-protected pending-account review and approval
- `privacy.html` — privacy/data-handling draft
- `docs/DEPLOYMENT.md` — production setup and provider configuration
- `docs/SECURITY.md` — security model and authorization test matrix
- `docs/DATABASE_MODEL.md` — relationship and table guide
- `docs/TEST_REPORT.md` — checks completed before packaging

## Run the local demo

```bash
cd skif-karate-dojo-secure-login-v2
python -m http.server 8000
```

Open `http://localhost:8000/portal.html`, then choose the parent, instructor, or administrator demo. Demo actions do not create accounts or write personal information.

## Production sequence

1. Complete the privacy/contact placeholders and approved data-retention schedule.
2. Create and secure a Supabase project.
3. Run `supabase/schema.sql`, then `supabase/seed.sql`.
4. Bootstrap the first administrator and enroll authenticator MFA.
5. Deploy both Edge Functions.
6. Configure email/password, Google, Turnstile, and optional passkeys.
7. Add the project URL, publishable key, provider feature flags, and Turnstile site key to `supabase-config.js`.
8. Complete the staging authorization/security tests.
9. Set `demoMode: false` and deploy to the final HTTPS domain.

Detailed commands and release gates are in `docs/DEPLOYMENT.md`.
