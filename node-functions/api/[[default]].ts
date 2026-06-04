const UPSTREAM_BASE = 'https://csint.pro/api';

export async function onRequest(context) {
  const { request, env } = context;

  // Read environment variables
  const apiKey = env.API_KEY;
  const subscriptionsJson = env.SUBSCRIPTIONS;

  if (!apiKey) {
    return new Response(JSON.stringify({ error: 'Server configuration error: API_KEY not set' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

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

  // Build the upstream URL from the catch-all path
  const url = new URL(request.url);
  const pathMatch = url.pathname.match(/^\/api\/(.*)$/);
  const upstreamPath = pathMatch ? pathMatch[1] : '';
  const upstreamUrl = `${UPSTREAM_BASE}/${upstreamPath}${url.search}`;

  // Build forwarded headers
  const headers = new Headers(request.headers);
  headers.set('X-API-Key', apiKey);
  headers.delete('host');

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
    return new Response(JSON.stringify({ error: 'Upstream request failed', details: message }), {
      status: 502,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
}
