/**
 * End-to-end test for the Streamable HTTP transport and its OAuth 2.1 server.
 *
 * Run with: node tests/integration/http-oauth.test.js
 *
 * This drives the complete authorization code + PKCE flow against a real
 * listening server — discovery, dynamic client registration, consent, code
 * exchange, an authenticated MCP initialize, refresh and revocation — and then
 * asserts the negative cases.
 *
 * The negative cases are the point. An auth layer that accepts valid
 * credentials proves very little; what matters is that it rejects a missing
 * token, a forged token, a replayed authorization code, a mismatched PKCE
 * verifier and a wrong password. Each of those is asserted below.
 *
 * No mailcow API key is configured, so the server starts in limited mode and
 * registers only its system tools. That is deliberate: this test is about the
 * transport and the auth gate, not about mailcow.
 */

const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const path = require('node:path');

const PORT = 39771;
const BASE = `http://127.0.0.1:${PORT}`;
const PASSWORD = 'correct-horse-battery-staple';

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function pkce() {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

async function waitForServer(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/healthz`);
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function main() {
  const entry = path.join(__dirname, '..', '..', 'dist', 'src', 'index.js');

  const server = spawn(process.execPath, [entry], {
    env: {
      ...process.env,
      MCP_TRANSPORT: 'http',
      MCP_HTTP_HOST: '127.0.0.1',
      MCP_HTTP_PORT: String(PORT),
      MCP_PUBLIC_URL: BASE,
      MCP_OAUTH_PASSWORD: PASSWORD,
      // A syntactically valid dummy key (the validator requires >= 32 chars).
      // It points at nothing reachable, which is fine: this test exercises the
      // transport and the auth gate, never the mailcow API itself.
      MAILCOW_API_KEY: 'TESTKEY-0000000000000000000000000000',
      MAILCOW_API_URL: 'http://127.0.0.1:9',
      LOG_LEVEL: 'warn',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let serverOutput = '';
  server.stdout.on('data', (d) => (serverOutput += d));
  server.stderr.on('data', (d) => (serverOutput += d));

  try {
    if (!(await waitForServer())) {
      console.error('Server failed to start. Output:\n' + serverOutput);
      process.exit(1);
    }

    // --- discovery -----------------------------------------------------
    const asMeta = await (await fetch(`${BASE}/.well-known/oauth-authorization-server`)).json();
    check('authorization server metadata is served', !!asMeta.authorization_endpoint);
    check(
      'metadata advertises PKCE S256',
      Array.isArray(asMeta.code_challenge_methods_supported) &&
        asMeta.code_challenge_methods_supported.includes('S256'),
      JSON.stringify(asMeta.code_challenge_methods_supported),
    );

    const prRes = await fetch(`${BASE}/.well-known/oauth-protected-resource`);
    check('protected resource metadata is served', prRes.ok, `status ${prRes.status}`);

    // --- the gate, before we hold any token -----------------------------
    const noAuth = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    check('unauthenticated /mcp is rejected', noAuth.status === 401, `status ${noAuth.status}`);
    check(
      'rejection carries WWW-Authenticate pointing at resource metadata',
      (noAuth.headers.get('www-authenticate') || '').includes('resource_metadata'),
      noAuth.headers.get('www-authenticate') || '(absent)',
    );

    const forged = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer not-a-real-token' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    check('forged bearer token is rejected', forged.status === 401, `status ${forged.status}`);

    // --- dynamic client registration ------------------------------------
    const reg = await fetch(`${BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'integration-test',
        redirect_uris: ['http://127.0.0.1:1/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    });
    const client = await reg.json();
    check('dynamic client registration succeeds', reg.ok && !!client.client_id, `status ${reg.status} ${JSON.stringify(client).slice(0, 200)}`);

    // --- consent --------------------------------------------------------
    const { verifier, challenge } = pkce();
    const authUrl =
      `${BASE}/authorize?response_type=code&client_id=${encodeURIComponent(client.client_id)}` +
      `&redirect_uri=${encodeURIComponent('http://127.0.0.1:1/callback')}` +
      `&code_challenge=${challenge}&code_challenge_method=S256&state=xyz`;

    const consent = await fetch(authUrl);
    const consentHtml = await consent.text();
    check('consent page is served', consent.ok && consentHtml.includes('name="pending"'), `status ${consent.status}`);

    const pending = /name="pending" value="([^"]+)"/.exec(consentHtml)?.[1];
    check('consent page carries a pending blob', !!pending);

    // Wrong password must not produce a code.
    const badPw = await fetch(`${BASE}/authorize/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ pending, password: 'wrong-password' }),
      redirect: 'manual',
    });
    check('wrong operator password is rejected', badPw.status === 401, `status ${badPw.status}`);

    const goodPw = await fetch(`${BASE}/authorize/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ pending, password: PASSWORD }),
      redirect: 'manual',
    });
    check('correct password redirects with a code', goodPw.status === 302, `status ${goodPw.status}`);
    const location = new URL(goodPw.headers.get('location'));
    const code = location.searchParams.get('code');
    check('authorization code is present', !!code);
    check('state is echoed back', location.searchParams.get('state') === 'xyz');

    // --- PKCE is actually enforced ---------------------------------------
    const wrongVerifier = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: client.client_id,
        redirect_uri: 'http://127.0.0.1:1/callback',
        code_verifier: b64url(randomBytes(32)),
      }),
    });
    check('token exchange with a wrong PKCE verifier fails', !wrongVerifier.ok, `status ${wrongVerifier.status}`);

    // --- real exchange ----------------------------------------------------
    const tokenRes = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: client.client_id,
        redirect_uri: 'http://127.0.0.1:1/callback',
        code_verifier: verifier,
      }),
    });
    const tokens = await tokenRes.json();
    check('authorization code exchanges for a token', tokenRes.ok && !!tokens.access_token, `status ${tokenRes.status} ${JSON.stringify(tokens).slice(0, 200)}`);
    check('a refresh token is issued', !!tokens.refresh_token);

    // --- replay -----------------------------------------------------------
    const replay = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: client.client_id,
        redirect_uri: 'http://127.0.0.1:1/callback',
        code_verifier: verifier,
      }),
    });
    check('authorization code cannot be replayed', !replay.ok, `status ${replay.status}`);

    // --- authenticated MCP -------------------------------------------------
    const init = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'integration-test', version: '0' },
        },
      }),
    });
    const initBody = await init.text();
    check('authenticated initialize succeeds', init.ok, `status ${init.status} ${initBody.slice(0, 200)}`);
    check('a session id is issued', !!init.headers.get('mcp-session-id'));

    // --- refresh ------------------------------------------------------------
    const refreshed = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
      }),
    });
    const refreshedTokens = await refreshed.json();
    check('refresh token yields a new access token', refreshed.ok && !!refreshedTokens.access_token, `status ${refreshed.status}`);
    check(
      'refresh token is rotated',
      refreshedTokens.refresh_token && refreshedTokens.refresh_token !== tokens.refresh_token,
    );

    const staleRefresh = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
      }),
    });
    check('the consumed refresh token no longer works', !staleRefresh.ok, `status ${staleRefresh.status}`);

    // --- unknown routes -------------------------------------------------------
    const notFound = await fetch(`${BASE}/../etc/passwd`);
    check('unknown routes 404 rather than leaking', notFound.status === 404 || notFound.status === 400, `status ${notFound.status}`);
  } finally {
    server.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 500));
    if (!server.killed) server.kill('SIGKILL');
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error('\nServer output:\n' + serverOutput.slice(-3000));
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
