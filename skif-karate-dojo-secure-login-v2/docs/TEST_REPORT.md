# Build and Security Test Report

Build date: 2026-08-21

## Scope

This report covers the packaged S.K.I.F. Puerto Rico student and family portal, including the public pages, email/password authentication interface, optional Google and passkey controls, self-registration approval workflow, Supabase database schema, Row Level Security definitions, server-side account-management functions, security headers, and responsive browser behavior.

## Completed automated checks

### Password policy module

- Executed 24 assertions against `auth-security.js`.
- Confirmed the live evaluator accepts a strong 15-character-plus password containing uppercase, lowercase, numeric, and special characters.
- Confirmed rejection of passwords that are too short or too long.
- Confirmed rejection of three identical consecutive characters.
- Confirmed rejection of obvious alphabetic, numeric, and keyboard sequences.
- Confirmed rejection of passwords containing recognizable name or email tokens.
- Confirmed rejection of locally blocked common and dojo-themed passwords.
- Confirmed Unicode NFC normalization and a deterministic 0–4 strength score.

Result: `24 assertions passed`.

### Source, markup, and configuration validation

- Checked all five top-level JavaScript files with Node syntax validation.
- Parsed/transpiled both Supabase Edge Functions without TypeScript diagnostics:
  - `supabase/functions/invite-user/index.ts`
  - `supabase/functions/manage-accounts/index.ts`
- Parsed every HTML page and confirmed there are no duplicate element IDs.
- Confirmed referenced form controls, labels, local scripts, stylesheets, images, pages, and manifest assets resolve correctly.
- Confirmed there are no inline event-handler attributes in the packaged HTML.
- Confirmed `auth-security.js` loads before `portal.js`.
- Parsed the stylesheet without CSS parser errors.
- Parsed `manifest.json` and `vercel.json` as valid JSON.
- Confirmed browser and Edge Function Supabase dependencies are pinned to version `2.112.3` rather than an unbounded `latest` version.

### Database authorization and data model checks

- Confirmed the schema creates 18 application tables.
- Confirmed all 18 application tables enable Row Level Security.
- Confirmed anonymous table and sequence privileges are revoked.
- Compared every Supabase table queried by `portal.js` against the schema; no unknown table references were found.
- Confirmed the profile lifecycle includes `approved_at`, an active-profile approval constraint, and a pending-approval index.
- Confirmed new Auth registrations create inactive profiles and require administrative approval before application access.
- Confirmed disabled previously approved accounts retain their approval history and do not reappear as new pending registrations.
- Confirmed database trigger protections prevent a normal user from changing protected profile fields such as role, active state, or approval state.
- Confirmed the schema contains no application password fields, full birth-date fields, Social Security numbers, government-ID numbers, card numbers, CVVs, bank-account numbers, or routing numbers.

### Server-side account-management checks

- Confirmed both account-management Edge Functions require a valid authenticated caller.
- Confirmed administrator operations require an active administrator profile and an AAL2 session.
- Confirmed exact-origin CORS handling rather than a wildcard origin.
- Confirmed POST-only handling, JSON validation, request-body size limits, and server-side input validation.
- Confirmed self-registration approval is limited to supported parent/student roles and verified portal registrations.
- Confirmed service-role credentials remain server-side and are not present in browser configuration.

### Browser security and user-experience tests

Headless Chromium tests exercised the public pages, demo dashboards, configured production-authentication path, responsive layout, and inactive-profile gate.

- Opened the homepage and privacy page successfully.
- Opened the parent, instructor, and administrator demo dashboards successfully.
- Initialized the production authentication screen with a stubbed pinned Supabase client.
- Confirmed configured sessions use `sessionStorage` by default rather than persistent `localStorage`.
- Exercised email/password sign-in, Google OAuth initiation, passkey initiation, self-registration, and password-recovery flows.
- Confirmed login, registration, recovery, and passkey requests carry the supplied CAPTCHA token in the tested client integration.
- Confirmed a weak password containing a prohibited triple repetition is rejected.
- Confirmed the strong test password `Cedar!Moon7Falcon#84` receives the highest local meter score.
- Confirmed registration sends the expected portal metadata and CAPTCHA token.
- Submitted a malicious HTML-shaped name value and confirmed it did not execute script or create an injected image element.
- Confirmed the shared output-escaping function encodes script-shaped content before display.
- Confirmed recovery produces an account-enumeration-resistant response.
- Confirmed an authenticated but inactive profile cannot enter the application dashboard.
- Tested the authentication screen at a 390×844 viewport and confirmed zero horizontal overflow; the login card appears before the explanatory content on mobile.
- Observed zero browser console errors and zero page errors during the completed browser tests.

Browser-test result:

```json
{
  "ok": true,
  "result": {
    "demo_and_public": {
      "demo_roles": 3,
      "public_pages": 2
    },
    "production_auth": {
      "auth_methods_tested": [
        "email_password",
        "google",
        "passkey",
        "signup",
        "recovery"
      ],
      "captured_calls": 5,
      "password_score": 4
    },
    "mobile_auth": {
      "viewport": "390x844",
      "horizontal_overflow": 0
    },
    "pending_gate": {
      "inactive_profile_blocked": true
    }
  }
}
```

### Headers, secret, and injection-surface checks

- Confirmed the deployment files define a restrictive Content Security Policy, frame-ancestor protection, content-type sniffing protection, referrer policy, HSTS, permissions restrictions, and no-store handling for portal/config responses.
- Confirmed the portal avoids inline handlers and uses output escaping for rendered user-controlled text.
- Confirmed database access uses the Supabase client/query builder rather than browser-built SQL strings.
- Confirmed privileged account changes occur in server-side functions and are validated again at the database boundary.
- Scanned the package for embedded JWTs, real Supabase secret/service-role keys, and private-key blocks; no live secrets were found.

## Required staging and production checks

No live Supabase project, production domain, email provider, Google OAuth client, Turnstile site/secret keys, or passkey relying-party configuration was supplied. Therefore, the following could not be executed against real infrastructure and remain mandatory before entering real family information:

1. Apply `supabase/schema.sql` to a fresh staging database and verify that every statement succeeds.
2. Configure Auth password enforcement, email verification, redirect allowlists, rate limits, CAPTCHA, and leaked-password protection in the selected Supabase plan.
3. Test invitation, verification, recovery, Google OAuth, and approval email delivery using non-production accounts.
4. Test passkey enrollment and authentication only after confirming the current Supabase passkey feature and WebAuthn relying-party settings are appropriate for the production domain.
5. Execute the complete two-family authorization matrix in `docs/SECURITY.md`, including direct API attempts by unrelated parents and students, an inactive account, an AAL1 staff session, an AAL2 instructor session, and an AAL2 administrator session.
6. Verify that disabled accounts lose application access and that revoked or expired sessions behave as expected.
7. Perform abuse testing for repeated login, registration, recovery, OAuth, CAPTCHA failure, malformed JSON, oversized requests, and unapproved-role manipulation.
8. Replace every bracketed privacy contact, retention period, and policy owner before publication.
9. Review logs and alerting without recording passwords, session tokens, recovery links, or unnecessary child information.
10. Obtain an independent security review before treating the portal as the system of record for minors or payment-related records.

## Result

The packaged code passed the local static, unit, browser, and packaging checks described above. These tests substantially reduce obvious implementation mistakes, but they do not prove that a deployed website is immune to every injection, authentication, authorization, browser, dependency, configuration, or operational attack. Production readiness depends on completing the staging checks, securely configuring the external providers, and maintaining the system after deployment.
