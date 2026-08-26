-- One-time first-administrator bootstrap.
-- 1. In Supabase Dashboard > Authentication > Users, create or invite your own user.
-- 2. Replace the email below.
-- 3. Run this file in the SQL editor.
-- 4. Sign in, enroll authenticator MFA, and use the portal for all later invitations.

update public.profiles
set role = 'admin'::public.app_role,
    active = true,
    approved_at = coalesce(approved_at, now()),
    updated_at = now()
where id = (
  select id from auth.users where lower(email) = lower('REPLACE_WITH_ADMIN_EMAIL@example.com')
);

-- Confirm exactly one row is returned and the role is admin.
select p.id, u.email, p.full_name, p.role, p.active, p.approved_at
from public.profiles p
join auth.users u on u.id = p.id
where lower(u.email) = lower('REPLACE_WITH_ADMIN_EMAIL@example.com');
