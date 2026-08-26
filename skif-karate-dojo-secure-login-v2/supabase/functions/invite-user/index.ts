import { createClient } from 'npm:@supabase/supabase-js@2.112.3';

type AppRole = 'parent' | 'student' | 'instructor' | 'admin';

const VALID_ROLES = new Set<AppRole>(['parent', 'student', 'instructor', 'admin']);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_BODY_BYTES = 20_000;

function getAllowedOrigins(): string[] {
  return (Deno.env.get('ALLOWED_ORIGINS') ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function corsHeaders(origin: string | null, allowedOrigins: string[]): HeadersInit {
  const allowAny = allowedOrigins.includes('*');
  const allowedOrigin = origin && (allowAny || allowedOrigins.includes(origin))
    ? (allowAny ? '*' : origin)
    : null;

  return {
    ...(allowedOrigin ? { 'Access-Control-Allow-Origin': allowedOrigin } : {}),
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Max-Age': '86400',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
}

function jsonResponse(
  body: Record<string, unknown>,
  status: number,
  headers: HeadersInit,
): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

function normalizeName(value: unknown): string {
  return String(value ?? '').trim().replace(/\s+/g, ' ');
}

function normalizeEmail(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

function decodeVerifiedJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) return {};
  const base64Url = parts[1];
  const padded = base64Url.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    base64Url.length + (4 - (base64Url.length % 4 || 4)),
    '=',
  );
  try {
    return JSON.parse(atob(padded));
  } catch {
    return {};
  }
}

Deno.serve(async (request: Request) => {
  const origin = request.headers.get('origin');
  const allowedOrigins = getAllowedOrigins();
  const headers = corsHeaders(origin, allowedOrigins);

  if (request.method === 'OPTIONS') {
    if (origin && !allowedOrigins.includes('*') && !allowedOrigins.includes(origin)) {
      return jsonResponse({ error: 'Origin is not allowed.' }, 403, headers);
    }
    return new Response(null, { status: 204, headers });
  }

  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed.' }, 405, headers);
  }

  if (origin && !allowedOrigins.includes('*') && !allowedOrigins.includes(origin)) {
    return jsonResponse({ error: 'Origin is not allowed.' }, 403, headers);
  }

  const contentLength = Number(request.headers.get('content-length') || '0');
  if (contentLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: 'Request is too large.' }, 413, headers);
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
  const publicKey = Deno.env.get('SUPABASE_PUBLISHABLE_KEY')
    ?? Deno.env.get('SUPABASE_ANON_KEY')
    ?? '';
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    ?? Deno.env.get('SUPABASE_SECRET_KEY')
    ?? '';
  const portalRedirectUrl = Deno.env.get('PORTAL_REDIRECT_URL') ?? '';

  if (!supabaseUrl || !publicKey || !serviceRoleKey || !portalRedirectUrl) {
    console.error('Required Edge Function environment variables are missing.');
    return jsonResponse({ error: 'Server configuration is incomplete.' }, 500, headers);
  }

  const authorization = request.headers.get('authorization') ?? '';
  const tokenMatch = authorization.match(/^Bearer\s+(.+)$/i);
  if (!tokenMatch) {
    return jsonResponse({ error: 'Authentication is required.' }, 401, headers);
  }
  const accessToken = tokenMatch[1];

  const userClient = createClient(supabaseUrl, publicKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // Validate the token with Supabase Auth before reading its AAL claim.
  const { data: userData, error: userError } = await userClient.auth.getUser(accessToken);
  const caller = userData.user;
  if (userError || !caller) {
    return jsonResponse({ error: 'Your session is invalid or expired.' }, 401, headers);
  }

  const claims = decodeVerifiedJwtPayload(accessToken);
  if (claims.aal !== 'aal2') {
    return jsonResponse({ error: 'Authenticator MFA is required for account invitations.' }, 403, headers);
  }

  const { data: callerProfile, error: profileError } = await adminClient
    .from('profiles')
    .select('role,active')
    .eq('id', caller.id)
    .maybeSingle();

  if (profileError) {
    console.error('Caller profile lookup failed:', profileError.message);
    return jsonResponse({ error: 'Authorization could not be verified.' }, 500, headers);
  }
  if (!callerProfile?.active || callerProfile.role !== 'admin') {
    return jsonResponse({ error: 'Administrator access is required.' }, 403, headers);
  }

  let body: Record<string, unknown>;
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
      return jsonResponse({ error: 'Request is too large.' }, 413, headers);
    }
    const parsed = JSON.parse(rawBody);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid body');
    body = parsed as Record<string, unknown>;
  } catch {
    return jsonResponse({ error: 'A valid JSON object is required.' }, 400, headers);
  }

  const email = normalizeEmail(body.email);
  const fullName = normalizeName(body.fullName);
  const role = String(body.role ?? '') as AppRole;

  if (!EMAIL_PATTERN.test(email) || email.length > 254) {
    return jsonResponse({ error: 'Enter a valid email address.' }, 400, headers);
  }
  if (fullName.length < 1 || fullName.length > 120) {
    return jsonResponse({ error: 'Full name must be between 1 and 120 characters.' }, 400, headers);
  }
  if (!VALID_ROLES.has(role)) {
    return jsonResponse({ error: 'The requested account role is invalid.' }, 400, headers);
  }
  if (role === 'admin' && Deno.env.get('ALLOW_ADMIN_INVITES') !== 'true') {
    return jsonResponse({ error: 'Administrator invitations are disabled by server policy.' }, 403, headers);
  }

  const { data: invitation, error: inviteError } = await adminClient.auth.admin
    .inviteUserByEmail(email, {
      redirectTo: portalRedirectUrl,
      data: { full_name: fullName },
    });

  if (inviteError || !invitation.user) {
    console.error('Invitation failed:', inviteError?.message ?? 'No user returned');
    const status = /already|registered|exists/i.test(inviteError?.message ?? '') ? 409 : 400;
    return jsonResponse(
      { error: status === 409 ? 'An account already exists for that email.' : 'The invitation could not be sent.' },
      status,
      headers,
    );
  }

  const invitedUserId = invitation.user.id;
  const { error: upsertError } = await adminClient.from('profiles').upsert(
    {
      id: invitedUserId,
      full_name: fullName,
      role,
      active: true,
      approved_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    { onConflict: 'id' },
  );

  if (upsertError) {
    console.error('Invited profile setup failed:', upsertError.message);
    // Avoid leaving a partially configured account if role assignment failed.
    await adminClient.auth.admin.deleteUser(invitedUserId).catch(() => undefined);
    return jsonResponse({ error: 'The account could not be configured.' }, 500, headers);
  }

  return jsonResponse(
    {
      ok: true,
      account: { id: invitedUserId, email, fullName, role },
    },
    201,
    headers,
  );
});
