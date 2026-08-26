import { createClient } from 'npm:@supabase/supabase-js@2.112.3';

type SelfServiceRole = 'parent' | 'student';
type RequestBody = {
  action?: unknown;
  userId?: unknown;
  role?: unknown;
};

const APPROVABLE_ROLES = new Set<SelfServiceRole>(['parent', 'student']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BODY_BYTES = 10_000;
const MAX_PENDING_ACCOUNTS = 500;

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

function safeName(value: unknown, fallback: string): string {
  const normalized = String(value ?? '').normalize('NFC').trim().replace(/\s+/g, ' ');
  return (normalized || fallback).slice(0, 120);
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
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: 'Request is too large.' }, 413, headers);
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
  const publicKey = Deno.env.get('SUPABASE_PUBLISHABLE_KEY')
    ?? Deno.env.get('SUPABASE_ANON_KEY')
    ?? '';
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    ?? Deno.env.get('SUPABASE_SECRET_KEY')
    ?? '';

  if (!supabaseUrl || !publicKey || !serviceRoleKey) {
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

  // Validate the token with Auth before trusting any JWT claim parsed below.
  const { data: userData, error: userError } = await userClient.auth.getUser(accessToken);
  const caller = userData.user;
  if (userError || !caller) {
    return jsonResponse({ error: 'Your session is invalid or expired.' }, 401, headers);
  }

  const claims = decodeVerifiedJwtPayload(accessToken);
  if (claims.aal !== 'aal2') {
    return jsonResponse({ error: 'Authenticator MFA is required for account management.' }, 403, headers);
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

  let body: RequestBody;
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
      return jsonResponse({ error: 'Request is too large.' }, 413, headers);
    }
    const parsed = JSON.parse(rawBody);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid body');
    body = parsed as RequestBody;
  } catch {
    return jsonResponse({ error: 'A valid JSON object is required.' }, 400, headers);
  }

  const action = String(body.action ?? '');

  if (action === 'list-pending') {
    const { data: pendingProfiles, error: pendingError } = await adminClient
      .from('profiles')
      .select('id,full_name,role,created_at,approved_at')
      .eq('active', false)
      .is('approved_at', null)
      .order('created_at', { ascending: true })
      .limit(MAX_PENDING_ACCOUNTS);

    if (pendingError) {
      console.error('Pending profile lookup failed:', pendingError.message);
      return jsonResponse({ error: 'Pending accounts could not be loaded.' }, 500, headers);
    }

    const profiles = pendingProfiles ?? [];
    if (!profiles.length) return jsonResponse({ ok: true, accounts: [] }, 200, headers);

    const profileIds = new Set(profiles.map((profile) => profile.id));
    const usersById = new Map<string, {
      id: string;
      email?: string;
      email_confirmed_at?: string | null;
      confirmed_at?: string | null;
      user_metadata?: Record<string, unknown>;
    }>();

    // A dojo should be far below this ceiling. Pagination avoids silently omitting
    // pending accounts if Auth contains more than one page of users.
    const perPage = 200;
    for (let page = 1; page <= 10 && usersById.size < profileIds.size; page += 1) {
      const { data: usersPage, error: usersError } = await adminClient.auth.admin.listUsers({ page, perPage });
      if (usersError) {
        console.error('Auth user lookup failed:', usersError.message);
        return jsonResponse({ error: 'Pending account identities could not be loaded.' }, 500, headers);
      }
      const users = usersPage.users ?? [];
      for (const user of users) {
        if (profileIds.has(user.id)) usersById.set(user.id, user);
      }
      if (users.length < perPage) break;
    }

    const accounts = profiles.flatMap((profile) => {
      const user = usersById.get(profile.id);
      const registrationSource = String(user?.user_metadata?.registration_source ?? '');
      const requestedRoleValue = String(user?.user_metadata?.requested_role ?? '').toLowerCase();
      if (registrationSource !== 'dojo_portal' || !APPROVABLE_ROLES.has(requestedRoleValue as SelfServiceRole)) {
        return [];
      }
      const fallbackName = user?.email?.split('@')[0] || 'Dojo member';
      const emailVerified = Boolean(user?.email_confirmed_at || user?.confirmed_at);
      return [{
        id: profile.id,
        fullName: safeName(profile.full_name ?? user?.user_metadata?.full_name, fallbackName),
        email: String(user?.email ?? '').slice(0, 254),
        requestedRole: requestedRoleValue as SelfServiceRole,
        createdAt: profile.created_at,
        emailVerified,
      }];
    });

    return jsonResponse({ ok: true, accounts }, 200, headers);
  }

  if (action === 'approve') {
    const userId = String(body.userId ?? '').trim();
    const role = String(body.role ?? '').toLowerCase() as SelfServiceRole;
    if (!UUID_PATTERN.test(userId) || !APPROVABLE_ROLES.has(role)) {
      return jsonResponse({ error: 'The approval request is invalid.' }, 400, headers);
    }

    const { data: userDataById, error: userLookupError } = await adminClient.auth.admin.getUserById(userId);
    const account = userDataById.user;
    if (userLookupError || !account) {
      return jsonResponse({ error: 'The requested account was not found.' }, 404, headers);
    }
    if (!account.email_confirmed_at && !account.confirmed_at) {
      return jsonResponse({ error: 'The user must verify the email address before approval.' }, 409, headers);
    }

    const requestedSource = String(account.user_metadata?.registration_source ?? '');
    const requestedRoleValue = String(account.user_metadata?.requested_role ?? '').toLowerCase();
    if (requestedSource !== 'dojo_portal' || !APPROVABLE_ROLES.has(requestedRoleValue as SelfServiceRole)) {
      return jsonResponse({ error: 'This account is not an eligible self-registration request.' }, 409, headers);
    }

    const approvalTime = new Date().toISOString();
    const { data: updatedProfiles, error: updateError } = await adminClient
      .from('profiles')
      .update({ role, active: true, approved_at: approvalTime, updated_at: approvalTime })
      .eq('id', userId)
      .eq('active', false)
      .is('approved_at', null)
      .select('id,full_name,role,active,approved_at');

    if (updateError) {
      console.error('Pending profile approval failed:', updateError.message);
      return jsonResponse({ error: 'The account could not be approved.' }, 500, headers);
    }
    const profile = updatedProfiles?.[0];
    if (!profile) {
      return jsonResponse({ error: 'The account is already active or cannot be approved.' }, 409, headers);
    }

    return jsonResponse({
      ok: true,
      account: {
        id: profile.id,
        fullName: profile.full_name,
        email: account.email ?? '',
        role: profile.role,
        active: profile.active,
      },
    }, 200, headers);
  }

  return jsonResponse({ error: 'The requested account action is not supported.' }, 400, headers);
});
