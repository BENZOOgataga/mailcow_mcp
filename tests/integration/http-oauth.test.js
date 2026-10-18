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

const CALLBACK = 'http://127.0.0.1:1/callback';

/**
 * Streamable HTTP answers either as JSON or as an SSE stream, depending on the
 * request. Pull the JSON-RPC payload out of whichever one arrived.
 */
function extractJson(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return null;
    }
  }
  const lines = trimmed.split('\n').filter((l) => l.startsWith('data:'));
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i].slice(5).trim());
    } catch {
      /* keep looking */
    }
  }
  return null;
}

async function mcpPost(token, sessionId, payload) {
  const res = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return { status: res.status, ok: res.ok, text, json: extractJson(text), res };
}

/** Open an MCP session and return its id. */
async function mcpInitialize(token, clientName) {
  const out = await mcpPost(token, undefined, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: clientName, version: '0' },
    },
  });
  const sessionId = out.res.headers.get('mcp-session-id');
  if (sessionId) {
    // Completes the handshake, as a real client does.
    await mcpPost(token, sessionId, { jsonrpc: '2.0', method: 'notifications/initialized' });
  }
  return { ...out, sessionId };
}

/**
 * Run the whole authorization flow and return the token set.
 *
 * Each call is a separate grant, which is what the session-ownership and scope
 * cases need: two tokens that are both valid and must not be interchangeable.
 */
async function newGrant(clientId, scope) {
  const { verifier, challenge } = pkce();
  let url =
    `${BASE}/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK)}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=s`;
  if (scope) url += `&scope=${encodeURIComponent(scope)}`;

  const html = await (await fetch(url)).text();
  const pending = /name="pending" value="([^"]+)"/.exec(html)?.[1];
  if (!pending) throw new Error('no pending blob on the consent page');

  const consented = await fetch(`${BASE}/authorize/consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ pending, password: PASSWORD }),
    redirect: 'manual',
  });
  const location = consented.headers.get('location');
  if (!location) throw new Error(`consent did not redirect (status ${consented.status})`);
  const code = new URL(location).searchParams.get('code');

  const tokenRes = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    }),
  });
  return tokenRes.json();
}

/** Render a consent page and return only its pending blob. */
async function newGrantBlob(clientId) {
  const { challenge } = pkce();
  const url =
    `${BASE}/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK)}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=s`;
  const html = await (await fetch(url)).text();
  const pending = /name="pending" value="([^"]+)"/.exec(html)?.[1];
  if (!pending) throw new Error('no pending blob on the consent page');
  return pending;
}

/** Text that would mean an internal error leaked into a response body. */
function looksLikeAStackTrace(text) {
  return (
    /\bat\s+[\w$.<>]+\s+\(/.test(text) ||
    text.includes('node_modules') ||
    text.includes('SyntaxError') ||
    text.includes('node:internal')
  );
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

    // --- two clients at once ------------------------------------------------
    //
    // Why this test exists: a single `Server` instance can be connected to
    // exactly one transport, and the second `connect()` throws
    // `Already connected to a transport`. With one shared instance the server
    // served whichever client arrived first and failed every other, so Claude
    // and ChatGPT could not both be connected. Each session now gets its own
    // protocol object.
    const grantA = await newGrant(client.client_id);
    const grantB = await newGrant(client.client_id);

    const sessionA = await mcpInitialize(grantA.access_token, 'client-a');
    const sessionB = await mcpInitialize(grantB.access_token, 'client-b');

    check('a first client can initialize', sessionA.ok && !!sessionA.sessionId, `status ${sessionA.status} ${sessionA.text.slice(0, 200)}`);
    check('a second client can initialize at the same time', sessionB.ok && !!sessionB.sessionId, `status ${sessionB.status} ${sessionB.text.slice(0, 200)}`);
    check('the two sessions are distinct', !!sessionA.sessionId && sessionA.sessionId !== sessionB.sessionId);

    // Both sessions must be usable, not merely openable.
    const listA = await mcpPost(grantA.access_token, sessionA.sessionId, {
      jsonrpc: '2.0', id: 2, method: 'tools/list',
    });
    const listB = await mcpPost(grantB.access_token, sessionB.sessionId, {
      jsonrpc: '2.0', id: 2, method: 'tools/list',
    });
    check('the first session serves requests', listA.ok && !!listA.json?.result?.tools, `status ${listA.status} ${listA.text.slice(0, 200)}`);
    check('the second session serves requests concurrently', listB.ok && !!listB.json?.result?.tools, `status ${listB.status} ${listB.text.slice(0, 200)}`);

    // --- session ownership ---------------------------------------------------
    //
    // A session id travels in a plain header and is a capability on its own.
    // Without a binding check any valid token could drive any live session and
    // read its results.
    const crossSession = await mcpPost(grantB.access_token, sessionA.sessionId, {
      jsonrpc: '2.0', id: 3, method: 'tools/list',
    });
    check(
      'a token from another grant cannot drive this session',
      crossSession.status === 404,
      `status ${crossSession.status} ${crossSession.text.slice(0, 200)}`,
    );

    const crossGet = await fetch(`${BASE}/mcp`, {
      method: 'GET',
      headers: {
        Accept: 'text/event-stream',
        Authorization: `Bearer ${grantB.access_token}`,
        'mcp-session-id': sessionA.sessionId,
      },
    });
    check('the same binding applies to the event stream', crossGet.status === 404, `status ${crossGet.status}`);

    // The rightful owner is unaffected by those attempts.
    const stillMine = await mcpPost(grantA.access_token, sessionA.sessionId, {
      jsonrpc: '2.0', id: 4, method: 'tools/list',
    });
    check('the owning token still works afterwards', stillMine.ok, `status ${stillMine.status}`);

    // --- scope is enforced, not just advertised ------------------------------
    //
    // The metadata document advertises mailcow:read and mailcow:write, and the
    // operator approves one of them on the consent screen. Before this nothing
    // checked either at the point of use.
    const readOnly = await newGrant(client.client_id, 'mailcow:read');
    check('a read-only grant is issued with only that scope', readOnly.scope === 'mailcow:read', String(readOnly.scope));

    const readSession = await mcpInitialize(readOnly.access_token, 'read-only-client');
    check('a read-only client can still connect', readSession.ok && !!readSession.sessionId, `status ${readSession.status}`);

    const writeAttempt = await mcpPost(readOnly.access_token, readSession.sessionId, {
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'create_domain', arguments: { domain: 'scope-test.example' } },
    });
    const writeText = JSON.stringify(writeAttempt.json ?? writeAttempt.text);
    check(
      'a read-only token cannot call a write tool',
      writeText.includes('insufficient_scope'),
      writeText.slice(0, 300),
    );

    const readAttempt = await mcpPost(readOnly.access_token, readSession.sessionId, {
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'list_domains', arguments: {} },
    });
    const readText = JSON.stringify(readAttempt.json ?? readAttempt.text);
    // It will fail against the unreachable dummy API, and that is fine. What
    // matters is that it was not turned away for scope.
    check(
      'a read-only token is not blocked from a read tool',
      !readText.includes('insufficient_scope'),
      readText.slice(0, 300),
    );

    const widen = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: readOnly.refresh_token,
        client_id: client.client_id,
        scope: 'mailcow:read mailcow:write',
      }),
    });
    check('a refresh cannot widen its own scope', !widen.ok, `status ${widen.status}`);

    // --- revocation covers the grant ----------------------------------------
    //
    // With the pair unlinked, revoking the access token left the refresh token
    // live, the client minted a replacement, and the revocation was cosmetic.
    const doomed = await newGrant(client.client_id);
    const revoke = await fetch(`${BASE}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: doomed.access_token, client_id: client.client_id }),
    });
    check('revocation is accepted', revoke.ok, `status ${revoke.status}`);

    const revokedMcp = await mcpPost(doomed.access_token, undefined, {
      jsonrpc: '2.0', id: 7, method: 'tools/list',
    });
    check('the revoked access token is rejected', revokedMcp.status === 401, `status ${revokedMcp.status}`);

    const revokedRefresh = await fetch(`${BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: doomed.refresh_token,
        client_id: client.client_id,
      }),
    });
    check(
      'revoking the access token also kills its refresh token',
      !revokedRefresh.ok,
      `status ${revokedRefresh.status}`,
    );

    // --- errors do not leak internals ---------------------------------------
    //
    // Express's default handler prints the stack when NODE_ENV is unset. The
    // container sets it, which made the leak depend on how the process was
    // launched rather than on the code.
    const badJson = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"jsonrpc": "2.0", this is not json',
    });
    const badJsonText = await badJson.text();
    check('a malformed body is rejected', badJson.status >= 400 && badJson.status < 500, `status ${badJson.status}`);
    check('a malformed body leaks no stack trace', !looksLikeAStackTrace(badJsonText), badJsonText.slice(0, 300));

    const tooBig = await fetch(`${BASE}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { pad: 'x'.repeat(2000000) } }),
    });
    const tooBigText = await tooBig.text();
    check('an oversized body is rejected', tooBig.status >= 400 && tooBig.status < 500, `status ${tooBig.status}`);
    check('an oversized body leaks no stack trace', !looksLikeAStackTrace(tooBigText), tooBigText.slice(0, 300));

    // --- the consent gate cannot be used to lock the operator out -----------
    //
    // The SDK mounts its authorization handler at /authorize behind a 429 rate
    // limiter, and `router.use` matches sub-paths, so /authorize/consent
    // inherited it: an attacker who tripped the limit locked the operator out
    // of their own consent screen, and behind a proxy with trust proxy off
    // every request shared one counter. Guessing is slowed by delay now, so
    // there is nothing to trip.
    const lockoutProbe = await newGrantBlob(client.client_id);
    let sawTooManyRequests = false;
    for (let i = 0; i < 3; i++) {
      const attempt = await fetch(`${BASE}/authorize/consent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ pending: lockoutProbe, password: `wrong-${i}` }),
        redirect: 'manual',
      });
      if (attempt.status === 429) sawTooManyRequests = true;
    }
    check('repeated wrong passwords are never answered with 429', !sawTooManyRequests);

    const afterFailures = await fetch(`${BASE}/authorize/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ pending: lockoutProbe, password: PASSWORD }),
      redirect: 'manual',
    });
    check(
      'the correct password still works after repeated failures',
      afterFailures.status === 302,
      `status ${afterFailures.status}`,
    );

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
