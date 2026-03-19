/**
 * OAuth 2.0 Authorization Server for Fizzy MCP
 *
 * Implements a minimal OAuth 2.0 authorization server so that claude.ai
 * and other MCP clients can authenticate using their Fizzy Personal Access Token
 * through a standard OAuth flow.
 *
 * Endpoints:
 *   GET  /.well-known/oauth-protected-resource    RFC 9728 metadata
 *   GET  /.well-known/oauth-authorization-server  RFC 8414 metadata
 *   POST /register                                Dynamic client registration (RFC 7591)
 *   GET  /authorize                               Authorization page (shows PAT entry form)
 *   POST /authorize                               Process PAT submission
 *   POST /token                                   Token exchange
 *
 * Flow:
 *   1. claude.ai discovers auth server via .well-known endpoints
 *   2. Registers itself as a client via /register
 *   3. Redirects user to /authorize
 *   4. User enters their Fizzy PAT on the authorize page
 *   5. Server issues an auth code and redirects back
 *   6. claude.ai exchanges code for an opaque access token at /token
 *   7. claude.ai uses that access token on all /mcp requests
 *   8. Worker resolves opaque token → Fizzy PAT on each request
 */

import type { Env } from "./types.js";

// KV key prefixes (uses FIZZY_CACHE namespace, separate from fizzy: cache prefix)
const CLIENT_KEY = (id: string) => `oauth:client:${id}`;
const CODE_KEY = (code: string) => `oauth:code:${code}`;
const TOKEN_KEY = (token: string) => `oauth:token:${token}`;

const CODE_TTL_SECONDS = 600; // 10 minutes
const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

interface OAuthClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  client_name?: string;
}

interface OAuthCode {
  fizzy_pat: string;
  client_id: string;
  redirect_uri: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

interface OAuthToken {
  fizzy_pat: string;
}

/**
 * Get the base URL for this server from a request
 */
export function getServerBase(request: Request): string {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

/**
 * GET /.well-known/oauth-protected-resource
 * RFC 9728 — tells clients where to find the authorization server
 */
export function handleProtectedResourceMetadata(request: Request): Response {
  const base = getServerBase(request);
  return jsonResponse({
    resource: base,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
}

/**
 * GET /.well-known/oauth-authorization-server
 * RFC 8414 — authorization server metadata
 */
export function handleAuthorizationServerMetadata(request: Request): Response {
  const base = getServerBase(request);
  return jsonResponse({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["mcp"],
    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_basic",
      "client_secret_post",
    ],
  });
}

/**
 * POST /register
 * RFC 7591 — dynamic client registration
 */
export async function handleRegister(
  request: Request,
  env: Env
): Promise<Response> {
  if (!env.FIZZY_CACHE) {
    return oauthErrorResponse("server_error", "OAuth storage not configured");
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return oauthErrorResponse("invalid_request", "Invalid JSON body");
  }

  const redirect_uris = body.redirect_uris as string[] | undefined;
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return oauthErrorResponse("invalid_request", "redirect_uris is required");
  }

  const client: OAuthClient = {
    client_id: crypto.randomUUID(),
    client_secret: crypto.randomUUID(),
    redirect_uris,
    client_name: body.client_name as string | undefined,
  };

  await env.FIZZY_CACHE.put(
    CLIENT_KEY(client.client_id),
    JSON.stringify(client)
  );

  return jsonResponse(
    {
      client_id: client.client_id,
      client_secret: client.client_secret,
      redirect_uris: client.redirect_uris,
      client_name: client.client_name,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    },
    201
  );
}

/**
 * GET /authorize
 * Shows the Fizzy PAT entry page
 */
export function handleAuthorizeGet(request: Request): Response {
  const url = new URL(request.url);
  const p = url.searchParams;

  const client_id = p.get("client_id") ?? "";
  const redirect_uri = p.get("redirect_uri") ?? "";
  const state = p.get("state") ?? "";
  const code_challenge = p.get("code_challenge") ?? "";
  const code_challenge_method = p.get("code_challenge_method") ?? "S256";
  const scope = p.get("scope") ?? "mcp";

  if (!client_id || !redirect_uri) {
    return new Response("Missing required parameters: client_id, redirect_uri", {
      status: 400,
    });
  }

  return htmlResponse(
    buildAuthorizeHtml({
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      scope,
    })
  );
}

/**
 * POST /authorize
 * Processes the PAT form submission and issues an auth code
 */
export async function handleAuthorizePost(
  request: Request,
  env: Env
): Promise<Response> {
  if (!env.FIZZY_CACHE) {
    return new Response("OAuth storage not configured", { status: 503 });
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return new Response("Invalid form data", { status: 400 });
  }

  const fizzy_pat = (form.get("fizzy_pat") as string | null)?.trim() ?? "";
  const client_id = (form.get("client_id") as string | null) ?? "";
  const redirect_uri = (form.get("redirect_uri") as string | null) ?? "";
  const state = (form.get("state") as string | null) ?? "";
  const code_challenge = (form.get("code_challenge") as string | null) ?? "";
  const code_challenge_method =
    (form.get("code_challenge_method") as string | null) ?? "S256";
  const scope = (form.get("scope") as string | null) ?? "mcp";

  if (!fizzy_pat) {
    return htmlResponse(
      buildAuthorizeHtml({
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        scope,
        error: "Please enter your Fizzy Personal Access Token.",
      }),
      400
    );
  }

  // Validate the client exists
  const clientRaw = await env.FIZZY_CACHE.get(CLIENT_KEY(client_id));
  if (!clientRaw) {
    return new Response("Unknown client", { status: 400 });
  }

  // Issue auth code
  const code = generateToken();
  const authCode: OAuthCode = {
    fizzy_pat,
    client_id,
    redirect_uri,
    code_challenge: code_challenge || undefined,
    code_challenge_method: code_challenge_method || undefined,
  };

  await env.FIZZY_CACHE.put(CODE_KEY(code), JSON.stringify(authCode), {
    expirationTtl: CODE_TTL_SECONDS,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  return Response.redirect(redirectUrl.toString(), 302);
}

/**
 * POST /token
 * Exchanges an auth code for an opaque access token
 */
export async function handleToken(
  request: Request,
  env: Env
): Promise<Response> {
  if (!env.FIZZY_CACHE) {
    return oauthErrorResponse("server_error", "OAuth storage not configured");
  }

  // Accept both form-encoded and JSON bodies
  const contentType = request.headers.get("Content-Type") ?? "";
  let get: (key: string) => string | null;

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(await request.text());
    get = (k) => params.get(k);
  } else {
    let body: Record<string, string> = {};
    try {
      body = (await request.json()) as Record<string, string>;
    } catch {
      return oauthErrorResponse("invalid_request", "Invalid request body");
    }
    get = (k) => body[k] ?? null;
  }

  const grant_type = get("grant_type");
  const code = get("code");
  const redirect_uri = get("redirect_uri");
  const code_verifier = get("code_verifier");
  const client_id = get("client_id");

  if (grant_type !== "authorization_code") {
    return oauthErrorResponse(
      "unsupported_grant_type",
      "Only authorization_code is supported"
    );
  }
  if (!code) {
    return oauthErrorResponse("invalid_request", "Missing code");
  }

  const codeRaw = await env.FIZZY_CACHE.get(CODE_KEY(code));
  if (!codeRaw) {
    return oauthErrorResponse("invalid_grant", "Invalid or expired code");
  }

  const authCode: OAuthCode = JSON.parse(codeRaw);
  // Single-use: delete immediately
  await env.FIZZY_CACHE.delete(CODE_KEY(code));

  if (client_id && client_id !== authCode.client_id) {
    return oauthErrorResponse("invalid_client", "client_id mismatch");
  }
  if (redirect_uri && redirect_uri !== authCode.redirect_uri) {
    return oauthErrorResponse("invalid_grant", "redirect_uri mismatch");
  }

  // Validate PKCE if a challenge was stored
  if (authCode.code_challenge) {
    if (!code_verifier) {
      return oauthErrorResponse("invalid_request", "Missing code_verifier");
    }
    const valid = await verifyPkce(
      code_verifier,
      authCode.code_challenge,
      authCode.code_challenge_method ?? "S256"
    );
    if (!valid) {
      return oauthErrorResponse("invalid_grant", "Invalid code_verifier");
    }
  }

  const access_token = generateToken();
  const tokenData: OAuthToken = { fizzy_pat: authCode.fizzy_pat };

  await env.FIZZY_CACHE.put(
    TOKEN_KEY(access_token),
    JSON.stringify(tokenData),
    { expirationTtl: TOKEN_TTL_SECONDS }
  );

  return jsonResponse({
    access_token,
    token_type: "Bearer",
    expires_in: TOKEN_TTL_SECONDS,
    scope: "mcp",
  });
}

/**
 * Resolve an opaque OAuth access token to the underlying Fizzy PAT.
 * Returns null if the token is not a known OAuth token (falls back to
 * treating the bearer value as a raw Fizzy PAT for backwards compatibility).
 */
export async function resolveToken(
  token: string,
  env: Env
): Promise<string | null> {
  if (!env.FIZZY_CACHE) return null;
  const raw = await env.FIZZY_CACHE.get(TOKEN_KEY(token));
  if (!raw) return null;
  const data: OAuthToken = JSON.parse(raw);
  return data.fizzy_pat;
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

async function verifyPkce(
  verifier: string,
  challenge: string,
  method: string
): Promise<boolean> {
  if (method === "S256") {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier)
    );
    const base64url = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    return base64url === challenge;
  }
  // plain (fallback)
  return verifier === challenge;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateToken(): string {
  return (
    crypto.randomUUID().replace(/-/g, "") +
    crypto.randomUUID().replace(/-/g, "")
  );
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

function oauthErrorResponse(error: string, description?: string): Response {
  return new Response(
    JSON.stringify({ error, error_description: description }),
    { status: 400, headers: { "Content-Type": "application/json" } }
  );
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Authorize page HTML
// ---------------------------------------------------------------------------

interface AuthorizeHtmlParams {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  error?: string;
}

function buildAuthorizeHtml(p: AuthorizeHtmlParams): string {
  const errorBlock = p.error
    ? `<div class="error">${escapeHtml(p.error)}</div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connect Fizzy MCP</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f0f0f2;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      padding: 2rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
    }
    .brand { font-size: 1.4rem; font-weight: 700; color: #1a1a1a; margin-bottom: 0.2rem; }
    .tagline { font-size: 0.875rem; color: #666; margin-bottom: 1.75rem; }
    .error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #b91c1c;
      padding: 0.625rem 0.75rem;
      border-radius: 6px;
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }
    label { display: block; font-size: 0.85rem; font-weight: 500; color: #374151; margin-bottom: 0.35rem; }
    input[type="password"] {
      width: 100%;
      padding: 0.6rem 0.75rem;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      font-size: 0.9rem;
      color: #111;
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    input[type="password"]:focus {
      border-color: #6366f1;
      box-shadow: 0 0 0 3px rgba(99,102,241,0.15);
    }
    .hint { font-size: 0.78rem; color: #9ca3af; margin-top: 0.4rem; }
    .hint a { color: #6366f1; text-decoration: none; }
    .hint a:hover { text-decoration: underline; }
    button {
      width: 100%;
      margin-top: 1.25rem;
      padding: 0.65rem;
      background: #6366f1;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s;
    }
    button:hover { background: #4f46e5; }
    button:active { background: #4338ca; }
    .footer { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #f3f4f6; text-align: center; }
    .footer p { font-size: 0.78rem; color: #9ca3af; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">Fizzy MCP</div>
    <div class="tagline">Enter your Fizzy Personal Access Token to connect</div>
    ${errorBlock}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id"             value="${escapeHtml(p.client_id)}">
      <input type="hidden" name="redirect_uri"          value="${escapeHtml(p.redirect_uri)}">
      <input type="hidden" name="state"                 value="${escapeHtml(p.state)}">
      <input type="hidden" name="code_challenge"        value="${escapeHtml(p.code_challenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(p.code_challenge_method)}">
      <input type="hidden" name="scope"                 value="${escapeHtml(p.scope)}">
      <div>
        <label for="fizzy_pat">Personal Access Token</label>
        <input
          type="password"
          id="fizzy_pat"
          name="fizzy_pat"
          placeholder="fizzy_pat_..."
          required
          autofocus
          autocomplete="off"
        >
        <p class="hint">
          Get yours from
          <a href="https://app.fizzy.do/settings/tokens" target="_blank" rel="noopener noreferrer">
            Fizzy → Settings → API Tokens
          </a>
        </p>
      </div>
      <button type="submit">Connect Fizzy</button>
    </form>
    <div class="footer">
      <p>Your token is only used to call the Fizzy API on your behalf and is never shared.</p>
    </div>
  </div>
</body>
</html>`;
}
