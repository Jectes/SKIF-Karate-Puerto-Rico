# Database Model

## Account relationships

```text
auth.users
   │ 1:1
profiles (pending approval / active / disabled; parent | student | instructor | admin)
   │
   ├── guardian_students ──> students <── optional student login via students.user_id
   │                              │
   │                              ├── enrollments ──> class_groups ──> class_sessions
   │                              │                                  └── attendance
   │                              ├── student_requirement_progress ──> requirements ──> belt_ranks
   │                              ├── student_badges ──> badges
   │                              ├── student_goals
   │                              ├── student_notes
   │                              ├── billing_items
   │                              └── consents
   └── announcements and audit_log are filtered by account role
```

## Account lifecycle

`profiles.active` controls application access. `profiles.approved_at` separates a new registration from an account that was previously approved and later disabled.

| State | `active` | `approved_at` | Meaning |
|---|---:|---|---|
| Pending self-registration | `false` | `NULL` | Email identity exists, but no student data is authorized |
| Active approved/invited account | `true` | timestamp | RLS may return records permitted by role and relationships |
| Disabled former account | `false` | timestamp | Application access is removed and the account does not return to the pending queue |

A database constraint prevents an active profile from having a null approval timestamp. Approval/activation fields are protected from ordinary users by a trigger.

## Role behavior

| Role | Authorized scope |
|---|---|
| Parent | Students linked through active `guardian_students`; family-visible records and billing status |
| Student | The one `students` record linked through `students.user_id` |
| Instructor | Student training records after an AAL2/MFA session; no billing access |
| Administrator | Account relationships, pending accounts, all student records, billing, consent, and audit after AAL2/MFA |

## Data-minimization decisions

- Email, password identities, Google identities, passkeys, recovery, and MFA remain in Supabase Auth rather than being duplicated in `profiles`.
- Student records use `age_group` and `is_minor`; the schema intentionally has no exact date-of-birth field.
- `billing_items` contains description, amount, dates, status, and an external reference only.
- `audit_log.details` contains limited identifiers/status metadata, never note text, passwords, tokens, or payment credentials.
- The schema has no SSN, government ID, card, bank, CVV, or full medical-history columns.

## Self-registration workflow

1. Parent/guardian or adult student creates an Auth identity with their own email/password, Google identity, or other enabled first-factor method.
2. The `auth.users` trigger creates an inactive `profiles` row with `approved_at = NULL` and a fail-closed parent default role.
3. Email confirmation occurs in Auth.
4. The `manage-accounts` Edge Function lists only eligible, original self-registration requests.
5. An AAL2 administrator approves only `parent` or `student`; the function sets the role, `active = true`, and `approved_at`.
6. The administrator explicitly links the parent/student account to the correct `students` record.
7. RLS then permits only the linked records.

## Invitation workflow

1. An AAL2 administrator invokes `invite-user`.
2. The Edge Function validates the administrator, role, email, name, origin, and request size.
3. Auth sends the invitation.
4. The function sets the invited profile's role, `active = true`, and `approved_at`.
5. The administrator creates the correct student relationship and enrollment.

## Training workflow

1. Administrator creates a student record and enrollment.
2. Instructor creates class sessions and records attendance.
3. Instructor updates belt requirements, notes, badges, and goals.
4. Parent/student views are filtered by PostgreSQL RLS, not merely hidden by the interface.
