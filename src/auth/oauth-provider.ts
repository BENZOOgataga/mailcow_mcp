/**
 * OAuth 2.1 Authorization Server
 *
 * Implements the MCP SDK's `OAuthServerProvider` so the HTTP transport can be
 * used as a remote MCP server by clients that require OAuth — Claude (web and
 * desktop) and ChatGPT both do. Neither client can send a static bearer header,
 * so a token endpoint is not optional for a remote deployment.
 *
 * Scope of this implementation, stated plainly:
 *
 * This authenticates *the operator* to *this server*. It is a single-operator
 * gate, not an identity provider. There is one credential, set in the
 * environment, and every issued token carries the same authority. If you need
 * several people with different permissions, put a real IdP in front and use
 * the SDK's ProxyOAuthServerProvider instead — the transport does not care
 * which provider it is handed.
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
 */

import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
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

/** Access token lifetime. Short, because refresh is free and silent. */
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
/** Authorization codes are single-use and must be redeemed promptly. */
const AUTH_CODE_TTL_MS = 60 * 1000;

export interface MailcowOAuthOptions {
  /**
   * Shared secret the operator enters on the consent screen.
   *
   * Required. The server refuses to start without one rather than defaulting to
   * something guessable — a default password on an internet-reachable mail
   * admin endpoint is worse than no auth at all, because it looks protected.
   */
  operatorPassword: string;
  /** Public issuer URL, e.g. https://mcp-mail.example.com */
  issuerUrl: URL;
  /** Scopes this server understands. */
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

interface StoredToken {
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
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

  constructor(private readonly options: MailcowOAuthOptions) {
    if (!options.operatorPassword || options.operatorPassword.length < 12) {
      throw new Error(
        'MCP_OAUTH_PASSWORD must be set to at least 12 characters. ' +
          'This is the only credential protecting write access to your mail server.',
      );
    }
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
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
    const pending = Buffer.from(
      JSON.stringify({
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state ?? '',
        scopes: params.scopes ?? [],
        resource: params.resource?.toString(),
      }),
    ).toString('base64url');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(consentPage(client, pending, params.redirectUri));
  }

  /**
   * Validate the operator password and mint an authorization code.
   *
   * Returns the redirect URL the browser should be sent to, or null when the
   * password is wrong. The caller is responsible for not revealing which.
   */
  completeAuthorization(pendingBlob: string, password: string): string | null {
    if (!secretsMatch(password, this.options.operatorPassword)) {
      return null;
    }

    let pending: {
      clientId: string;
      redirectUri: string;
      codeChallenge: string;
      state: string;
      scopes: string[];
      resource?: string;
    };
    try {
      pending = JSON.parse(Buffer.from(pendingBlob, 'base64url').toString('utf8'));
    } catch {
      return null;
    }

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
      throw new Error('invalid_grant: authorization code is unknown or expired');
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

    // Rotate: the presented refresh token is consumed.
    this.refreshTokens.delete(refreshToken);

    return this.issueTokens(client.client_id, scopes ?? stored.scopes, stored.resource);
  }

  async verifyAccessToken(accessToken: string): Promise<AuthInfo> {
    const stored = this.accessTokens.get(accessToken);
    if (!stored) {
      throw new InvalidTokenError('Access token is unknown or revoked');
    }
    if (stored.expiresAt < Date.now()) {
      this.accessTokens.delete(accessToken);
      throw new InvalidTokenError('Access token has expired');
    }

    return {
      token: accessToken,
      clientId: stored.clientId,
      scopes: stored.scopes,
      expiresAt: Math.floor(stored.expiresAt / 1000),
      ...(stored.resource ? { resource: new URL(stored.resource) } : {}),
    };
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    this.accessTokens.delete(request.token);
    this.refreshTokens.delete(request.token);
  }

  private issueTokens(clientId: string, scopes: string[], resource?: string): OAuthTokens {
    this.sweep();

    const accessToken = token();
    const refreshToken = token();
    const expiresAt = Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000;

    this.accessTokens.set(accessToken, { clientId, scopes, expiresAt, resource });
    // Refresh tokens do not expire on their own; they are rotated on use and
    // dropped on restart.
    this.refreshTokens.set(refreshToken, {
      clientId,
      scopes,
      expiresAt: Number.MAX_SAFE_INTEGER,
      resource,
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };
  }

  /** Drop expired codes and access tokens so the maps do not grow without bound. */
  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.codes) if (v.expiresAt < now) this.codes.delete(k);
    for (const [k, v] of this.accessTokens) if (v.expiresAt < now) this.accessTokens.delete(k);
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
): string {
  // client_name is chosen by whoever registered the client. With dynamic
  // registration open, that is anyone on the internet — so an attacker can
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
    you recognise as belonging to the service you are connecting — for example
    <code>claude.ai</code> or <code>chatgpt.com</code> — stop now: approving would
    hand control of this mail server to whoever owns it.
  </div>

  <div class="warn">
    Approving grants the tools this server has registered, which may include
    creating and modifying mailboxes, aliases and domains. Only continue if you
    started this authorization yourself, just now.
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
