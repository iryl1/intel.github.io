const crypto = require('crypto');

const UPSTREAM_BASE = 'https://csint.pro/api';

// Base64url encoding helper
function base64url(input: string | Buffer): string {
  let str: string;
  if (typeof input === 'string') {
    str = Buffer.from(input, 'utf8').toString('base64');
  } else {
    str = input.toString('base64');
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Base64url decoding helper
function base64urlDecode(input: string): string {
  let str = input.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

// Create signed token: base64url(payload).base64url(hmacHex)
function createToken(payload: Record<string, unknown>, sessionSecret: string): string {
  const payloadStr = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', sessionSecret).update(payloadStr).digest('hex');
  return `${base64url(payloadStr)}.${base64url(signature)}`;
}

// Verify and decode token; returns payload or null
function verifyToken(token: string, sessionSecret: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  const payloadStr = base64urlDecode(payloadB64);
  const expectedSig = crypto.createHmac('sha256', sessionSecret).update(payloadStr).digest('hex');
  const expectedSigB64 = base64url(expectedSig);
  if (sigB64 !== expectedSigB64) return null;
  try {
    return JSON.parse(payloadStr);
  } catch {
    return null;
  }
}

// Helper: JSON response with CORS
function jsonResponse(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      ...extraHeaders,
    },
  });
}

export async function onRequest(context: { request: Request; env: Record<string, string> }) {
  const { request, env } = context;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  const url = new URL(request.url);
  const pathMatch = url.pathname.match(/^\/api\/(.*)$/);
  const upstreamPath = pathMatch ? pathMatch[1] : '';

  // ---------- AUTH ROUTES ----------

  // POST /api/auth/login
  if (upstreamPath === 'auth/login' && request.method === 'POST') {
    const sessionSecret = env.SESSION_SECRET;
    const subscriptionsJson = env.SUBSCRIPTIONS;

    if (!sessionSecret || !subscriptionsJson) {
      return jsonResponse({ error: 'Server configuration error: auth not configured' }, 500);
    }

    let body: { key?: string };
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'Invalid request body' }, 400);
    }

    const providedKey = body.key;
    if (!providedKey) {
      return jsonResponse({ error: 'Missing API key' }, 400);
    }

    let subscriptions: { keys: Array<{ key: string; tier: string; name: string; endpoints: string[]; requests_per_hour: number; expiry: string }> };
    try {
      subscriptions = JSON.parse(subscriptionsJson);
    } catch {
      return jsonResponse({ error: 'Server configuration error: invalid subscriptions' }, 500);
    }

    const keyEntry = subscriptions.keys.find((k) => k.key === providedKey);
    if (!keyEntry) {
      return jsonResponse({ error: 'Invalid API key' }, 401);
    }

    // Check expiry
    const now = new Date();
    const expiryDate = new Date(keyEntry.expiry);
    if (now > expiryDate) {
      return jsonResponse({ error: 'API key expired' }, 401);
    }

    // Create session token
    const kid = crypto.createHash('sha256').update(keyEntry.key.substring(0, 8)).digest('hex').substring(0, 16);
    const payload = {
      kid,
      tier: keyEntry.tier,
      name: keyEntry.name,
      endpoints: keyEntry.endpoints,
      requests_per_hour: keyEntry.requests_per_hour,
      exp: keyEntry.expiry,
    };

    const token = createToken(payload, sessionSecret);

    return jsonResponse({
      token,
      tier: keyEntry.tier,
      name: keyEntry.name,
      endpoints: keyEntry.endpoints,
      requests_per_hour: keyEntry.requests_per_hour,
      expiry: keyEntry.expiry,
    });
  }

  // POST /api/auth/verify
  if (upstreamPath === 'auth/verify' && request.method === 'POST') {
    const sessionSecret = env.SESSION_SECRET;
    if (!sessionSecret) {
      return jsonResponse({ error: 'Server configuration error: auth not configured' }, 500);
    }

    let body: { token?: string };
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'Invalid request body' }, 400);
    }

    const token = body.token;
    if (!token) {
      return jsonResponse({ error: 'Missing token' }, 400);
    }

    const payload = verifyToken(token, sessionSecret);
    if (!payload) {
      return jsonResponse({ error: 'Invalid session' }, 401);
    }

    return jsonResponse({
      tier: payload.tier,
      name: payload.name,
      endpoints: payload.endpoints,
      requests_per_hour: payload.requests_per_hour,
      expiry: payload.exp,
    });
  }

  // ---------- AUTHENTICATED PROXY ----------

  // All other /api/* requests require authentication
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: 'Authentication required' }, 401);
  }

  const token = authHeader.substring(7).trim();
  const sessionSecret = env.SESSION_SECRET;
  if (!sessionSecret) {
    return jsonResponse({ error: 'Server configuration error: auth not configured' }, 500);
  }

  const tokenPayload = verifyToken(token, sessionSecret);
  if (!tokenPayload) {
    return jsonResponse({ error: 'Authentication required' }, 401);
  }

  // Optional endpoint access check
  const endpoints = tokenPayload.endpoints as string[] | undefined;
  if (endpoints && !endpoints.includes('*')) {
    // Extract the base endpoint from the upstream path (e.g., "discord/lookup" -> "discord")
    const endpointSegment = upstreamPath.split('/')[0].toLowerCase();
    const hasAccess = endpoints.some((e) => e.toLowerCase() === endpointSegment);
    if (!hasAccess) {
      return jsonResponse({ error: `Endpoint not available in ${(tokenPayload.name as string) || 'current'} plan` }, 403);
    }
  }

  // ---------- EXISTING PROXY LOGIC ----------

  const apiKey = env.API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: 'Server configuration error: API_KEY not set' }, 500);
  }

  const upstreamUrl = `${UPSTREAM_BASE}/${upstreamPath}${url.search}`;

  // Build forwarded headers
  const headers = new Headers(request.headers);
  headers.set('X-API-Key', apiKey);
  headers.delete('host');
  headers.delete('Authorization'); // Don't forward client auth to upstream

  // Build fetch options
  const fetchOptions: RequestInit = {
    method: request.method,
    headers,
  };

  // Forward body for methods that have one
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      const body = await request.text();
      if (body) {
        fetchOptions.body = body;
      }
    } catch {
      // No body or unreadable – proceed without body
    }
  }

  try {
    const upstreamResponse = await fetch(upstreamUrl, fetchOptions);

    // Build response headers with CORS
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // If the request is for subscription info, inject server-side subscriptions
    const subscriptionsJson = env.SUBSCRIPTIONS;
    if (upstreamPath === 'subscriptions' && subscriptionsJson) {
      try {
        const subscriptions = JSON.parse(subscriptionsJson);
        return new Response(JSON.stringify({ subscriptions }), {
          status: 200,
          headers: responseHeaders,
        });
      } catch {
        // If SUBSCRIPTIONS env var is invalid JSON, fall through to upstream response
      }
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown upstream error';
    return jsonResponse({ error: 'Upstream request failed', details: message }, 502);
  }
}
