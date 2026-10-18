/**
 * OAuth 2.1 Authorization Server
 *
 * Implements the MCP SDK's `OAuthServerProvider` so the HTTP transport can be
 * used as a remote MCP server by clients that require OAuth. Claude (web and
 * desktop) and ChatGPT both do. Neither client can send a static bearer header,
 * so a token endpoint is not optional for a remote deployment.
 *
 * Scope of this implementation, stated plainly:
 *
 * This authenticates *the operator* to *this server*. It is a single-operator
 * gate, not an identity provider. There is one credential, set in the
 * environment, and every issued token carries the same authority. If you need
 * several people with different permissions, put a real IdP in front and use
 * the SDK's ProxyOAuthServerProvider instead. The transport does not care which
 * provider it is handed.
 *
 * What it does implement, because the clients require it:
 *   - authorization code flow with PKCE (S256), per OAuth 2.1
 *   - dynamic client registration, so Claude can register itself
 *   - refresh tokens, so sessions survive access-token expiry
 *   - token revocation
 *
 * Tokens are held in memory. A restart invalidates them and the client
 * re-authorizes, which is the correct trade for a single-operator server: it
 * avoids persisting bearer tokens to disk, and re-auth is one click.
 *
 * Grants, not loose tokens
 * ------------------------
 * Every authorization produces a *grant*, and both the access token and the
 * refresh token belong to it. This matters for three things that are wrong if
 * tokens are tracked individually:
 *
 *   1. Revocation. RFC 7009 says revoking one token SHOULD invalidate the
 *      others issued with it. Tracked individually, revoking an access token
 *      leaves its refresh token live, so the client mints a replacement and
 *      the revocation achieves nothing.
 *   2. Lifetime. A rotating refresh token with no absolute expiry is a
 *      permanent credential: each use issues the next one, so a leaked token
 *      never ages out. The grant carries one absolute deadline that rotation
 *      cannot extend.
 *   3. Session binding. The transport binds an MCP session to the grant rather
 *      than to a token, so a refresh does not invalidate the session and
 *      another client's token cannot adopt it.
 */

import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  InvalidGrantError,
  InvalidScopeError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';

/**
 * Path the consent form submits to.
 *
 * Not `/authorize`: the SDK's authorization handler already accepts both GET
 * and POST there, so a form posting to it is parsed as an OAuth request and
 * rejected before this server's handler runs.
 */
export const CONSENT_SUBMIT_PATH = '/authorize/consent';

/** Scopes this server understands. */
export const SUPPORTED_SCOPES = ['mailcow:read', 'mailcow:write'] as const;
export type MailcowScope = (typeof SUPPORTED_SCOPES)[number];

/** Access token lifetime. Short, because refresh is free and silent. */
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
/** Authorization codes are single-use and must be redeemed promptly. */
const AUTH_CODE_TTL_MS = 60 * 1000;
/**
 * Absolute lifetime of a grant, counted from the authorization the operator
 * approved. Refresh rotation issues new tokens but never moves this deadline,
 * so a leaked refresh token expires rather than living until the next restart.
 */
const GRANT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/**
 * How long a rendered consent page stays submittable. A page left open in a
 * tab should not still authorize an hour later.
 */
const CONSENT_TTL_MS = 10 * 60 * 1000;

export interface MailcowOAuthOptions {
  /**
   * Shared secret the operator enters on the consent screen.
   *
   * Required. The server refuses to start without one rather than defaulting to
   * something guessable: a default password on an internet-reachable mail
   * admin endpoint is worse than no auth at all, because it looks protected.
   */
  operatorPassword: string;
  /** Public issuer URL, e.g. https://mcp-mail.example.com */
  issuerUrl: URL;
  /** Scopes this server understands. Defaults to SUPPORTED_SCOPES. */
  scopesSupported?: string[];
}

interface StoredAuthCode {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

/** A token's membership in a grant. The grant holds the authority. */
interface StoredToken {
  grantId: string;
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

interface Grant {
  clientId: string;
  scopes: string[];
  resource?: string;
  /** Absolute deadline. Rotation does not move it. */
  expiresAt: number;
  accessTokens: Set<string>;
  refreshTokens: Set<string>;
}

interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

/** Constant-time string comparison that tolerates differing lengths. */
function secretsMatch(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

function token(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * In-memory client store with dynamic registration.
 *
 * Claude registers itself through DCR on first connect; ChatGPT may be given a
 * client ID and secret manually. Both paths end up here.
 */
class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    this.clients.set(client.client_id, client);
    return client;
  }

  /** Pre-register a client for vendors that do not support DCR. */
  seed(client: OAuthClientInformationFull): void {
    this.clients.set(client.client_id, client);
  }

  list(): OAuthClientInformationFull[] {
    return [...this.clients.values()];
  }
}

export class MailcowOAuthProvider implements OAuthServerProvider {
  private readonly _clientsStore = new InMemoryClientsStore();
  private readonly codes = new Map<string, StoredAuthCode>();
  private readonly accessTokens = new Map<string, StoredToken>();
  private readonly refreshTokens = new Map<string, StoredToken>();
  private readonly grants = new Map<string, Grant>();
  private readonly scopes: string[];
  /**
   * Key for signing the pending-authorization blob. Per-process and never
   * leaves it, so a blob cannot be forged and does not survive a restart.
   */
  private readonly blobKey = randomBytes(32);

  constructor(private readonly options: MailcowOAuthOptions) {
    // The consent route can throttle how often a guess is checked, but it
    // cannot tell the operator from an attacker: /authorize needs no
    // authentication and registration is open. Entropy is therefore the
    // control that actually bounds guessing, so the floor is set where a
    // throttled online attack is hopeless rather than merely slow.
    if (!options.operatorPassword || options.operatorPassword.length < 24) {
      throw new Error(
        'MCP_OAUTH_PASSWORD must be set to at least 24 characters, and should be ' +
          'random rather than memorable. It is the only credential protecting ' +
          'write access to your mail server, on an endpoint that cannot tell you ' +
          'apart from anyone else who can reach it.',
      );
    }
    this.scopes = options.scopesSupported ?? [...SUPPORTED_SCOPES];
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /** Scopes advertised in metadata, and the ceiling on what can be granted. */
  get scopesSupported(): string[] {
    return [...this.scopes];
  }

  /** Pre-register a client ID/secret pair for clients without DCR. */
  seedClient(client: OAuthClientInformationFull): void {
    this._clientsStore.seed(client);
  }

  /**
   * Render the consent screen, or complete the flow when the operator submits
   * the correct password.
   *
   * The SDK routes GET /authorize here. We serve a minimal form on GET and
   * handle the submission on POST through `completeAuthorization` below, called
   * from the route the HTTP transport installs.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    // A client may not ask for authority this server does not define. Rejecting
    // here rather than silently narrowing means a client asking for something
    // unexpected is told so, instead of appearing to work with less access than
    // it believes it has.
    const requested = params.scopes ?? [];
    const unknown = requested.filter((s) => !this.scopes.includes(s));
    if (unknown.length > 0) {
      throw new InvalidScopeError(`Unsupported scope(s): ${unknown.join(', ')}`);
    }
    // Clients that request nothing get the full supported set, which is what
    // the metadata advertises and what Claude's registration asks for.
    const granted = requested.length > 0 ? requested : [...this.scopes];

    const pending = this.sealPending({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state ?? '',
      scopes: granted,
      resource: params.resource?.toString(),
      expiresAt: Date.now() + CONSENT_TTL_MS,
    });

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(consentPage(client, pending, params.redirectUri, granted));
  }

  /**
   * Validate the operator password and mint an authorization code.
   *
   * Returns the redirect URL the browser should be sent to, or null when the
   * password is wrong, the blob was tampered with, or the consent page has
   * expired. The caller is responsible for not revealing which.
   */
  completeAuthorization(pendingBlob: string, password: string): string | null {
    if (!secretsMatch(password, this.options.operatorPassword)) {
      return null;
    }

    const pending = this.openPending(pendingBlob);
    if (!pending) return null;

    const code = token();
    this.codes.set(code, {
      clientId: pending.clientId,
      codeChallenge: pending.codeChallenge,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes,
      resource: pending.resource,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });

    const target = new URL(pending.redirectUri);
    target.searchParams.set('code', code);
    if (pending.state) target.searchParams.set('state', pending.state);
    return target.toString();
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const stored = this.codes.get(authorizationCode);
    if (!stored || stored.expiresAt < Date.now()) {
      throw new InvalidGrantError('Authorization code is unknown or expired');
    }
    return stored.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<OAuthTokens> {
    const stored = this.codes.get(authorizationCode);
    if (!stored || stored.expiresAt < Date.now()) {
      throw new InvalidGrantError('Authorization code is unknown or expired');
    }
    if (stored.clientId !== client.client_id) {
      throw new InvalidGrantError('Authorization code was issued to another client');
    }

    // Single use. Delete before issuing so a replay cannot race.
    this.codes.delete(authorizationCode);

    return this.issueTokens(client.client_id, stored.scopes, stored.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const stored = this.refreshTokens.get(refreshToken);
    if (!stored) {
      throw new InvalidGrantError('Refresh token is unknown or revoked');
    }
    if (stored.clientId !== client.client_id) {
      throw new InvalidGrantError('Refresh token was issued to another client');
    }

    const grant = this.grants.get(stored.grantId);
    if (!grant || grant.expiresAt < Date.now()) {
      this.revokeGrant(stored.grantId);
      throw new InvalidGrantError('Grant has expired; re-authorization is required');
    }

    // A refresh may narrow a token's authority but never widen it. Without this
    // check a client granted read could ask for write on refresh and get it,
    // which makes the scope recorded on the grant decorative.
    if (scopes && scopes.length > 0) {
      const widened = scopes.filter((s) => !stored.scopes.includes(s));
      if (widened.length > 0) {
        throw new InvalidScopeError(
          `Refresh cannot widen scope; not granted: ${widened.join(', ')}`,
        );
      }
    }

    // Rotate: the presented refresh token is consumed.
    this.refreshTokens.delete(refreshToken);
    grant.refreshTokens.delete(refreshToken);

    const next = scopes && scopes.length > 0 ? scopes : stored.scopes;
    return this.issueTokens(client.client_id, next, stored.resource, stored.grantId);
  }

  async verifyAccessToken(accessToken: string): Promise<AuthInfo> {
    const stored = this.accessTokens.get(accessToken);
    if (!stored) {
      throw new InvalidTokenError('Access token is unknown or revoked');
    }
    if (stored.expiresAt < Date.now()) {
      this.forgetAccessToken(accessToken);
      throw new InvalidTokenError('Access token has expired');
    }

    // The grant is the authority. A token whose grant was revoked or has aged
    // out is not usable even while the token's own expiry is still in future.
    const grant = this.grants.get(stored.grantId);
    if (!grant) {
      this.forgetAccessToken(accessToken);
      throw new InvalidTokenError('Access token is unknown or revoked');
    }
    if (grant.expiresAt < Date.now()) {
      this.revokeGrant(stored.grantId);
      throw new InvalidTokenError('Grant has expired; re-authorization is required');
    }

    return {
      token: accessToken,
      clientId: stored.clientId,
      scopes: stored.scopes,
      expiresAt: Math.floor(stored.expiresAt / 1000),
      ...(stored.resource ? { resource: new URL(stored.resource) } : {}),
      extra: { grantId: stored.grantId },
    };
  }

  /**
   * Revoke the whole grant, not the single token presented.
   *
   * RFC 7009 section 2.1 says revoking a token SHOULD invalidate the others
   * issued from the same authorization, and here it is not merely tidy: with
   * the pair unlinked, revoking an access token leaves its refresh token live,
   * so the client immediately mints a replacement and the revocation is
   * cosmetic.
   */
  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    const stored =
      this.accessTokens.get(request.token) ?? this.refreshTokens.get(request.token);
    // RFC 7009 section 2.2: an unknown token is not an error.
    if (!stored) return;
    // A token issued to another client is not this caller's to revoke. The
    // token endpoint authenticates the client, but a public client
    // authenticates with nothing beyond its own client_id, so without this
    // check anyone holding a token value could cut off another client's
    // session. RFC 7009 section 2.1 permits ignoring such a request.
    if (stored.clientId !== client.client_id) return;
    this.revokeGrant(stored.grantId);
  }

  /** Drop a grant and every token issued under it. */
  private revokeGrant(grantId: string): void {
    const grant = this.grants.get(grantId);
    if (grant) {
      for (const t of grant.accessTokens) this.accessTokens.delete(t);
      for (const t of grant.refreshTokens) this.refreshTokens.delete(t);
      this.grants.delete(grantId);
      return;
    }
    // Defensive: a token pointing at a grant that is already gone.
    for (const [t, v] of this.accessTokens) if (v.grantId === grantId) this.accessTokens.delete(t);
    for (const [t, v] of this.refreshTokens) if (v.grantId === grantId) this.refreshTokens.delete(t);
  }

  private forgetAccessToken(accessToken: string): void {
    const stored = this.accessTokens.get(accessToken);
    this.accessTokens.delete(accessToken);
    if (stored) this.grants.get(stored.grantId)?.accessTokens.delete(accessToken);
  }

  private issueTokens(
    clientId: string,
    scopes: string[],
    resource?: string,
    existingGrantId?: string,
  ): OAuthTokens {
    this.sweep();

    let grantId = existingGrantId;
    let grant = grantId ? this.grants.get(grantId) : undefined;

    if (!grant) {
      grantId = token();
      grant = {
        clientId,
        scopes,
        resource,
        expiresAt: Date.now() + GRANT_TTL_MS,
        accessTokens: new Set<string>(),
        refreshTokens: new Set<string>(),
      };
      this.grants.set(grantId, grant);
    }

    const resolvedGrantId = grantId as string;
    const accessToken = token();
    const refreshToken = token();
    const accessExpiresAt = Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000;

    this.accessTokens.set(accessToken, {
      grantId: resolvedGrantId,
      clientId,
      scopes,
      expiresAt: accessExpiresAt,
      resource,
    });
    // The refresh token inherits the grant's absolute deadline rather than
    // getting a fresh one, so rotating cannot extend the chain indefinitely.
    this.refreshTokens.set(refreshToken, {
      grantId: resolvedGrantId,
      clientId,
      scopes,
      expiresAt: grant.expiresAt,
      resource,
    });
    grant.accessTokens.add(accessToken);
    grant.refreshTokens.add(refreshToken);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };
  }

  /** Drop expired codes, tokens and grants so the maps do not grow without bound. */
  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.codes) if (v.expiresAt < now) this.codes.delete(k);
    for (const [k, v] of this.accessTokens) if (v.expiresAt < now) this.forgetAccessToken(k);
    for (const [k, v] of this.refreshTokens) {
      if (v.expiresAt < now) {
        this.refreshTokens.delete(k);
        this.grants.get(v.grantId)?.refreshTokens.delete(k);
      }
    }
    for (const [id, g] of this.grants) if (g.expiresAt < now) this.revokeGrant(id);
  }

  /** Visible for tests: number of live grants. */
  get grantCount(): number {
    return this.grants.size;
  }

  // --- pending-authorization blob ------------------------------------------
  //
  // The blob carries the authorization parameters across the consent page, so
  // the server holds no state between rendering the form and the operator
  // submitting it. It travels through the operator's browser, which makes it
  // attacker-reachable, so it is signed with a per-process key: the parameters
  // that come back are the ones this server put in.

  private sealPending(payload: PendingAuthorization): string {
    const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const mac = createHmac('sha256', this.blobKey).update(body).digest('base64url');
    return `${body}.${mac}`;
  }

  private openPending(blob: string): PendingAuthorization | null {
    const dot = blob.lastIndexOf('.');
    if (dot <= 0) return null;
    const body = blob.slice(0, dot);
    const mac = blob.slice(dot + 1);

    // A sha256 digest is exactly 43 base64url characters. Checking the length
    // and the alphabet before decoding means a blob cannot be varied by
    // reshaping its signature, only by forging one.
    if (mac.length !== 43 || !/^[A-Za-z0-9_-]+$/.test(mac)) return null;

    const expected = createHmac('sha256', this.blobKey).update(body).digest();
    let presented: Buffer;
    try {
      presented = Buffer.from(mac, 'base64url');
    } catch {
      return null;
    }
    if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
      return null;
    }

    try {
      const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (typeof parsed?.expiresAt !== 'number' || parsed.expiresAt < Date.now()) return null;
      if (typeof parsed?.redirectUri !== 'string' || typeof parsed?.clientId !== 'string') return null;
      if (!Array.isArray(parsed?.scopes)) return null;
      return parsed as PendingAuthorization;
    } catch {
      return null;
    }
  }
}

/**
 * Minimal consent screen.
 *
 * Deliberately plain: no external assets, no inline scripts, nothing that a
 * CSP would have to allow. It states which client is asking and what it will be
 * able to do, because an operator approving mail-server access should see that
 * before typing a password.
 */
function consentPage(
  client: OAuthClientInformationFull,
  pending: string,
  redirectUri: string,
  scopes: string[],
): string {
  // client_name is chosen by whoever registered the client. With dynamic
  // registration open, that is anyone on the internet, so an attacker can
  // register a client called "Claude", point its redirect at a host they
  // control, and send the operator a genuine authorization URL on the right
  // domain with valid TLS. Nothing about the name can be trusted.
  //
  // The redirect target is the one field the attacker cannot disguise: it is
  // where the authorization code will actually be sent. Showing it, and
  // showing its origin separately and prominently, is what lets an operator
  // tell the real flow from the forged one.
  const name = escapeHtml(client.client_name ?? client.client_id);
  const target = escapeHtml(redirectUri);
  const scopeList = scopes.length > 0 ? escapeHtml(scopes.join(', ')) : '(none)';
  let origin: string;
  try {
    origin = escapeHtml(new URL(redirectUri).origin);
  } catch {
    origin = '(unparseable)';
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access to mailcow</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 4rem auto; padding: 0 1rem; }
  .client { font-weight: 600; }
  .warn { border-left: 3px solid #c2410c; padding: .5rem 0 .5rem .75rem; margin: 1.5rem 0; }
  .dest { border: 2px solid #c2410c; border-radius: 4px; padding: .75rem 1rem; margin: 1.5rem 0; }
  .dest-label { font-size: .85rem; text-transform: uppercase; letter-spacing: .04em; opacity: .75; }
  .dest-origin { font-size: 1.35rem; font-weight: 700; font-family: ui-monospace, monospace; word-break: break-all; margin: .25rem 0; }
  .dest-full { font-size: .8rem; opacity: .7; font-family: ui-monospace, monospace; word-break: break-all; }
  code { font-family: ui-monospace, monospace; }
  label { display: block; margin: 1.5rem 0 .25rem; font-weight: 600; }
  input[type=password] { width: 100%; padding: .6rem; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 1rem; padding: .6rem 1.2rem; font-size: 1rem; cursor: pointer; }
</style>
</head>
<body>
  <h1>Authorize access to mailcow</h1>
  <p>A client calling itself <span class="client">${name}</span> is requesting access
     to your mailcow server.</p>

  <div class="dest">
    <div class="dest-label">The authorization code will be sent to</div>
    <div class="dest-origin">${origin}</div>
    <div class="dest-full">${target}</div>
  </div>

  <div class="warn">
    <strong>Check that destination.</strong> The client name above is chosen by
    whoever registered the client and proves nothing. If that origin is not one
    you recognise as belonging to the service you are connecting, for example
    <code>claude.ai</code> or <code>chatgpt.com</code>, stop now: approving would
    hand control of this mail server to whoever owns it.
  </div>

  <div class="warn">
    Approving grants the tools this server has registered, which may include
    creating and modifying mailboxes, aliases and domains. Scope requested:
    <code>${scopeList}</code>. Only continue if you started this authorization
    yourself, just now.
  </div>
  <form method="POST" action="${CONSENT_SUBMIT_PATH}">
    <input type="hidden" name="pending" value="${pending}">
    <label for="password">Operator password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" autofocus required>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );
}
