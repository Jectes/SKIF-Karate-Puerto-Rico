# Security and Privacy Operating Guide

## Security model

```text
Browser over HTTPS
  ├── Supabase Auth
  │     ├── email/password + confirmation/recovery
  │     ├── optional Google OAuth
  │     ├── optional experimental passkeys/WebAuthn
  │     ├── optional Turnstile CAPTCHA
  │     └── authenticator-app MFA / AAL2
  ├── Supabase Data API
  │     └── publishable key + user JWT + PostgreSQL grants/RLS
  ├── invite-user Edge Function
  │     └── verified JWT + AAL2 + active admin + server secret
  └── manage-accounts Edge Function
        └── verified JWT + AAL2 + active admin + limited actions
```

The visible interface is not the authorization boundary. A person can skip buttons, change browser JavaScript, or call the API directly. PostgreSQL grants, RLS policies, protected database triggers, Auth policy, and server-side Edge Function checks must therefore deny access independently of the interface.

No web application can honestly promise to be completely “injection-proof.” The goal is defense in depth: prevent common injection paths, limit what a compromised layer can do, detect sensitive changes, and verify the controls in staging.

## Controls built into this package

### Account creation and authentication

- People may use their own email/password account.
- Email confirmation is required in production configuration.
- Every newly created Auth identity receives an inactive application profile.
- Self-registration metadata cannot activate the profile or grant an instructor/admin role.
- AAL2 administrators may approve only verified `parent` or `student` self-registration requests.
- Student records stay unavailable until an administrator creates an explicit guardian/student or student-login relationship.
- Google OAuth is optional and follows the same inactive-profile/approval process.
- Passkeys are optional, feature-gated, and explicitly enabled as an experimental Supabase capability.
- Password recovery uses a generic success response so the page does not confirm whether an email exists.
- Authentication errors shown to users are intentionally generic.
- Cloudflare Turnstile tokens are supported on sign-up, password sign-in, passkey sign-in, and recovery.
- Authenticator-app MFA enrollment and challenge flows are included.
- Instructor/admin database access is tied to the JWT's AAL2 assurance level where required by RLS.

### Password policy

The portal's live meter requires by default:

- 15–128 characters
- uppercase, lowercase, number, and special character
- no three identical characters in a row
- no obvious four-character alphabet, number, or keyboard sequence
- no four-or-more-character token taken from the user's name or email local part
- no listed common or dojo-themed password

Configure Supabase Auth to enforce on the server:

- minimum length of 15
- digits, lowercase, uppercase, and symbols
- leaked-password rejection when available
- Auth rate limits and abuse controls

The repeat, sequence, personal-information, and local common-password checks are client-side additions. A modified client can bypass them, so they must never be described as server-enforced. A direct self-registration that bypasses those extra checks still creates only an inactive profile, but the provider-side policy should reject the core password violations before the user is created.

The account page supplies `current_password` when a password identity changes its password. Passwords are never placed in application tables, logs, query strings, URLs, analytics, or administrative forms.

Permit password-manager generation, paste, autofill, and show/hide controls. Do not force routine password changes without compromise evidence. Never ask a user to send a password, reset link, authenticator code, or recovery token by email, SMS, WhatsApp, or support chat.

### Authorization

- `parent`: reads only students linked through active `guardian_students` records.
- `student`: reads only the student record linked through `students.user_id`.
- `instructor`: accesses authorized training records only after MFA; no billing access.
- `admin`: manages account relationships, consent, billing status, and audit history only after MFA.
- Inactive profiles lose application access even if the Auth session has not yet expired.
- All 18 exposed application tables enable RLS.
- Anonymous table/sequence privileges are revoked.
- Role and activation changes are protected by a database trigger.
- Student identity/account-linkage fields are protected by a database trigger.
- Creator, author, assessor, and attendance-recorder IDs are assigned or preserved by database triggers rather than trusted from browser input.

### Injection and browser defenses

- Browser database access uses the Supabase client API; the code does not concatenate user input into SQL statements.
- Edge Functions use fixed Supabase client operations rather than building SQL strings from request fields.
- Edge Functions accept POST/OPTIONS only, limit request size, require a JSON object, validate action/role/UUID/email/name values, and use exact origin allowlists.
- Dynamic text inserted into HTML templates is encoded by `esc()`; status/alert text uses `textContent`.
- The password/name normalization layer removes control characters from display names and caps field length.
- Database columns include types, length checks, enums, foreign keys, uniqueness constraints, and protected triggers.
- The package has no file-upload or user-supplied HTML feature.
- The Content Security Policy blocks inline scripts, unapproved script hosts, framing, plugins/objects, and unapproved API connections.
- `X-Content-Type-Options`, `frame-ancestors`, `X-Frame-Options`, HSTS, referrer policy, browser permission restrictions, and no-store caching are included in deployment examples.
- The browser never receives the service-role/secret key. A service key bypasses RLS and must stay in the Edge Function environment.
- RLS still evaluates object-level access even when a person invents record UUIDs or sends requests outside the interface.

Escaping output does not make authorization unnecessary, and RLS does not make output encoding unnecessary. Both are required.

### Data minimization

- Exact birth dates are not in the schema; use broad age group plus minor/adult flag.
- Email remains in managed Auth rather than being duplicated in application tables.
- Billing stores amount/status/reference information only, never card or bank credentials.
- Audit events contain limited metadata, not note bodies or payment credentials.
- No application columns exist for plaintext passwords, Social Security numbers, government IDs, card numbers, CVVs, bank accounts, or full medical histories.

## Required production configuration

Code alone does not provide:

- domain ownership and HTTPS-only hosting
- correct Auth Site URL and redirect allowlist
- email confirmation and reliable transactional email
- provider-side password requirements and leaked-password rejection
- Auth rate limits
- Turnstile secret/site-key configuration
- Google OAuth client/consent/branding configuration
- stable passkey relying-party configuration
- exact Edge Function CORS origins
- mandatory staff MFA enrollment and recovery procedures
- server-side session timebox/inactivity settings
- same-day staff offboarding
- encrypted backup and tested restoration
- monitoring/alerting
- a written retention/deletion schedule
- a completed privacy notice and incident-response contact
- independent security review appropriate to the amount and sensitivity of real data

## Google OAuth policy

- Request only the identity scopes required for login.
- Configure exact authorized origins and callback URLs.
- Use verified branding/custom domains where practical so families can identify the legitimate consent flow.
- Treat social login as AAL1. Staff with an enrolled factor must complete the AAL2 challenge before protected data or administration becomes available.
- Do not automatically link an OAuth identity to a family record solely because a name or email appears similar.

## Passkey policy

Passkeys are WebAuthn credentials and are phishing-resistant, but the selected Supabase API is experimental.

- Enable only after testing on the final HTTPS domain.
- Choose a stable relying-party ID before enrollment.
- Keep recovery and at least one other tested sign-in method during rollout.
- Verify identity before assisting with lost-device recovery.
- Review passkey lists and delete unknown/unused credentials.
- Re-test whenever the pinned Supabase client is upgraded because experimental APIs may change.

## MFA policy

- Required: instructors and administrators.
- Recommended: parents and adult students.
- The database checks the signed JWT `aal` claim; merely hiding menus at AAL1 is insufficient.
- Losing an authenticator requires identity-verified recovery. Do not remove MFA because someone knows a name and email.
- Review enrolled factors during offboarding and suspected compromise.
- Do not store TOTP secrets or one-time codes in application records or logs.

TOTP is a substantial improvement over password-only access but is not phishing-resistant. Passkeys may strengthen authentication after the experimental integration is accepted for production.

## Session policy

- `sessionStorage` is the default, so the browser copy normally ends when that tab/window session closes.
- The portal provides a configurable client-side inactivity warning/logout.
- Idle logout uses local sign-out; the explicit Sign out action uses the provider's default global sign-out behavior.
- Client-side idle timers are defense in depth and can be modified by the user; use provider/server session controls for the authoritative policy.
- Test password changes, account disabling, explicit logout, refresh-token behavior, multiple devices, and staff offboarding.
- Never put access/refresh tokens into logs, URLs, screenshots, local demo data, or support tickets.

## Secrets

Public browser values:

- Supabase project URL
- Supabase publishable key
- Google provider availability flag
- Turnstile site key
- passkey/self-registration feature flags

Server-only values:

- Supabase service-role/secret key
- Google OAuth client secret
- Turnstile secret key
- SMTP credentials
- payment-provider secrets
- backup credentials

Exposure of a service key or provider secret is a high-severity incident: rotate it, preserve logs, investigate access, remove it from history, and invalidate affected sessions/credentials where appropriate.

## Data-handling table

| Data | Portal handling |
|---|---|
| Login email | Supabase Auth only |
| Password | Managed Auth; never available to administrators or stored in app tables |
| Google identity | Managed Auth identity/provider metadata |
| Passkey | Public-key credential managed by Auth; no private key enters the portal |
| Student age | Broad age group and minor flag |
| Training | Rank, requirements, attendance, badges, goals, limited notes |
| Billing | Description, amount, due date, status, external reference |
| Payment credential | Dedicated payment processor only |
| Emergency/medical detail | Separate approved process; minimum necessary only |
| SSN/government ID | Do not collect |

## Children and parent control

For children under 13, use a parent-managed account by default. Before direct child accounts or child-submitted information are enabled, determine whether parental notice and verifiable consent are required for the dojo's actual operation and jurisdiction. Give authorized parents access/control, collect only what is necessary, avoid behavioral advertising, and use qualified legal review.

## Staging authorization and abuse test matrix

Create at least these identities:

- Parent A linked to Student A
- Parent B linked to Student B
- Student A login
- Pending verified parent
- Pending unverified parent
- Pending user requesting `admin` in metadata
- Instructor at AAL1 and AAL2
- Administrator at AAL1 and AAL2
- Disabled user

Test from both the interface and direct Auth/Data API requests:

| Test | Expected result |
|---|---|
| Anonymous selects any application table | Denied/empty |
| New email/password registration | Inactive profile; no student data |
| New Google identity | Inactive profile; no student data |
| Unverified pending user is approved | Denied |
| Pending user requests `admin` or `instructor` metadata | Cannot receive that role through self-service approval |
| Parent A reads Student A | Allowed |
| Parent A guesses Student B UUID | Denied/empty |
| Student A reads another student | Denied/empty |
| Unlinked active parent reads students | Empty |
| Instructor at AAL1 reads students | Denied/empty |
| Instructor at AAL2 reads progress/attendance | Allowed |
| Instructor at AAL2 reads billing | Denied/empty |
| Admin at AAL1 opens admin data/functions | Denied |
| Admin at AAL2 manages relationships/pending accounts/billing | Allowed |
| Disabled profile uses a still-valid Auth session | Application access denied |
| Client attempts to change its own role/active flag | Database error |
| Browser invents a service key | No real server secret exists in public files |
| Cross-origin site calls Edge Functions | CORS denied; server authorization still required |
| Oversized/non-JSON Edge Function body | Rejected |
| Invalid UUID/action/role sent to account function | Rejected |
| SQL-like input such as `' OR 1=1 --` in a text field | Stored/handled as literal text; query shape unchanged |
| HTML/script payload in name/note | Rendered as text; script does not execute |
| Password below provider minimum/composition policy through direct Auth call | Rejected by Auth |
| Password failing only browser repeat/sequence rule through a modified client | Provider behavior may allow it; profile remains inactive; document this distinction |
| CAPTCHA omitted when provider protection is enabled | Auth request rejected |
| Recovery requested for existing and nonexistent email | Same generic page response |
| Passkey registered on one account | Cannot authenticate another account |
| CSP tested with an injected inline script | Browser blocks it |

Do not turn off demo mode or load real data until this matrix passes.

## Operational access review

At least quarterly and whenever personnel change:

1. List active profiles and roles.
2. Verify every instructor/admin still requires access.
3. Confirm staff MFA enrollment and review factors/passkeys.
4. Disable inactive accounts rather than leaving them dormant.
5. Review role, activation, billing, relationship, and sensitive-table audit events.
6. Verify guardian/student relationships, especially after custody/authorization changes.
7. Test password recovery, CAPTCHA, Google login, passkeys if enabled, and one backup restoration.
8. Review provider security advisories and deliberately update the pinned client version.

## Logging and monitoring

Monitor:

- repeated failed sign-in, CAPTCHA, and recovery attempts
- unusual sign-up volume
- email confirmation failures
- new or removed MFA factors/passkeys
- role or activation changes
- unusual bulk reads/exports
- repeated denied RLS/API requests
- Edge Function 401/403/413/429/5xx patterns
- service-key use
- large or unexpected data changes

Do not log passwords, current passwords, access/refresh tokens, CAPTCHA tokens, OAuth codes, recovery links, TOTP secrets/codes, passkey ceremony payloads, note bodies, card information, or full personal-data request bodies.

## Retention and deletion

Approve a record-specific schedule covering:

- active/inactive account profiles and Auth identities
- guardian relationships
- student identity and enrollment records
- attendance and grading progress
- family-visible and staff-only notes
- consent history
- billing status/external references
- audit logs
- email-provider records
- backups and deletion propagation

Document the legal/business reason, deletion or de-identification method, exception approval, and the family-facing period in `privacy.html`.

## Incident response

1. Preserve relevant Auth, Edge Function, database, hosting, CAPTCHA, OAuth, and email logs.
2. Disable compromised accounts and revoke/rotate affected keys, OAuth secrets, passkeys, factors, and sessions.
3. Determine which students, families, fields, and dates were involved.
4. Fix the vulnerability and repeat direct RLS/injection/authorization tests before restoring access.
5. Restore altered data from a trusted backup when needed.
6. Coordinate legally required notices with qualified counsel and insurers.
7. Record lessons learned and update code, policy, training, and monitoring.

## Official references

- Supabase password security: `https://supabase.com/docs/guides/auth/password-security`
- Supabase password-based Auth: `https://supabase.com/docs/guides/auth/passwords`
- Supabase CAPTCHA: `https://supabase.com/docs/guides/auth/auth-captcha`
- Supabase Google login: `https://supabase.com/docs/guides/auth/social-login/auth-google`
- Supabase passkeys: `https://supabase.com/docs/guides/auth/passkeys`
- Supabase MFA: `https://supabase.com/docs/guides/auth/auth-mfa`
- Supabase sessions: `https://supabase.com/docs/guides/auth/sessions`
- Supabase RLS: `https://supabase.com/docs/guides/database/postgres/row-level-security`
- Supabase Edge Function authentication: `https://supabase.com/docs/guides/functions/auth`
- NIST SP 800-63B: `https://pages.nist.gov/800-63-4/sp800-63b.html`
- FTC children's privacy guidance: `https://www.ftc.gov/business-guidance/privacy-security/childrens-privacy`
