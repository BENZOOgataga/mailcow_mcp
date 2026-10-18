/**
 * OAuth provider: grants, revocation, scope and the consent blob.
 *
 * Each test here corresponds to a specific way the first version of this
 * provider was wrong, found by reviewing it before deploying it. They are
 * written against the behaviour rather than the implementation, so a rewrite
 * that reintroduces any of these fails.
 *
 *   - revoking one token left the other half of the pair live, so the client
 *     minted a replacement and revocation did nothing
 *   - refresh tokens never expired, so a leaked one was a permanent
 *     credential until the process restarted
 *   - scopes were advertised and then never enforced, and a refresh could
 *     widen its own scope
 *   - the pending-authorization blob was unsigned, so the parameters that came
 *     back from the browser were not necessarily the ones the server sent
 */

import type { Response } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  InvalidGrantError,
  InvalidScopeError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { MailcowOAuthProvider, SUPPORTED_SCOPES } from '../../../src/auth/oauth-provider';

const PASSWORD = 'correct-horse-battery-staple';
const REDIRECT = 'https://client.example/callback';

const CLIENT: OAuthClientInformationFull = {
  client_id: 'test-client',
  redirect_uris: [REDIRECT],
};

const OTHER_CLIENT: OAuthClientInformationFull = {
  client_id: 'other-client',
  redirect_uris: [REDIRECT],
};

function makeProvider(): MailcowOAuthProvider {
  return new MailcowOAuthProvider({
    operatorPassword: PASSWORD,
    issuerUrl: new URL('https://mcp.example.com'),
  });
}

/** Minimal stand-in for the express Response the SDK hands `authorize`. */
function captureRes(): { res: Response; html: () => string } {
  let body = '';
  const res = {
    setHeader: () => undefined,
    send: (chunk: string) => {
      body = chunk;
      return res;
    },
  } as unknown as Response;
  return { res, html: () => body };
}

/** Render the consent page and pull the signed blob out of the form. */
async function consentBlob(
  provider: MailcowOAuthProvider,
  scopes?: string[],
  client: OAuthClientInformationFull = CLIENT,
): Promise<string> {
  const { res, html } = captureRes();
  await provider.authorize(
    client,
    {
      redirectUri: REDIRECT,
      codeChallenge: 'challenge-value',
      state: 'state-value',
      ...(scopes ? { scopes } : {}),
    } as never,
    res,
  );
  const match = /name="pending" value="([^"]+)"/.exec(html());
  if (!match) throw new Error('consent page carried no pending blob');
  return match[1];
}

/** Drive authorize -> consent -> code -> tokens, as the SDK's handlers would. */
async function issueGrant(
  provider: MailcowOAuthProvider,
  scopes?: string[],
  client: OAuthClientInformationFull = CLIENT,
) {
  const blob = await consentBlob(provider, scopes, client);
  const redirect = provider.completeAuthorization(blob, PASSWORD);
  if (!redirect) throw new Error('authorization was not completed');
  const code = new URL(redirect).searchParams.get('code');
  if (!code) throw new Error('no authorization code in the redirect');
  return provider.exchangeAuthorizationCode(client, code);
}

describe('MailcowOAuthProvider', () => {
  describe('revocation covers the grant, not one token', () => {
    it('kills the refresh token when the access token is revoked', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);

      await provider.revokeToken(CLIENT, { token: tokens.access_token });

      // The whole point: without this, the client simply refreshes and the
      // revocation is cosmetic.
      await expect(
        provider.exchangeRefreshToken(CLIENT, tokens.refresh_token as string),
      ).rejects.toThrow(InvalidGrantError);
      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(
        InvalidTokenError,
      );
      expect(provider.grantCount).toBe(0);
    });

    it('kills the access token when the refresh token is revoked', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);

      await provider.revokeToken(CLIENT, { token: tokens.refresh_token as string });

      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(
        InvalidTokenError,
      );
      expect(provider.grantCount).toBe(0);
    });

    it('still covers the grant after the refresh token has rotated', async () => {
      const provider = makeProvider();
      const first = await issueGrant(provider);
      const second = await provider.exchangeRefreshToken(
        CLIENT,
        first.refresh_token as string,
      );

      // Rotation must not start a new grant, or revocation after a refresh
      // would only reach the newest pair.
      expect(provider.grantCount).toBe(1);

      await provider.revokeToken(CLIENT, { token: second.access_token });
      await expect(
        provider.exchangeRefreshToken(CLIENT, second.refresh_token as string),
      ).rejects.toThrow(InvalidGrantError);
      expect(provider.grantCount).toBe(0);
    });

    it('treats an unknown token as a no-op, per RFC 7009 section 2.2', async () => {
      const provider = makeProvider();
      await issueGrant(provider);
      await expect(
        provider.revokeToken(CLIENT, { token: 'never-issued' }),
      ).resolves.toBeUndefined();
      expect(provider.grantCount).toBe(1);
    });

    it("ignores a request to revoke another client's token", async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);

      // A public client authenticates with nothing beyond its own client_id,
      // so without this check anyone holding a token value could cut off
      // another client's session. RFC 7009 section 2.1 permits ignoring it.
      await provider.revokeToken(OTHER_CLIENT, { token: tokens.access_token });

      expect(provider.grantCount).toBe(1);
      await expect(provider.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({
        clientId: CLIENT.client_id,
      });
    });

    it('still lets the owning client revoke it', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);
      await provider.revokeToken(CLIENT, { token: tokens.access_token });
      expect(provider.grantCount).toBe(0);
    });
  });

  describe('scope', () => {
    it('refuses a scope it does not define', async () => {
      const provider = makeProvider();
      const { res } = captureRes();
      await expect(
        provider.authorize(
          CLIENT,
          {
            redirectUri: REDIRECT,
            codeChallenge: 'challenge-value',
            scopes: ['mailcow:read', 'mailcow:root'],
          } as never,
          res,
        ),
      ).rejects.toThrow(InvalidScopeError);
    });

    it('grants the full supported set when the client asks for nothing', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);
      expect(tokens.scope).toBe([...SUPPORTED_SCOPES].join(' '));
    });

    it('refuses to widen scope on refresh', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider, ['mailcow:read']);
      expect(tokens.scope).toBe('mailcow:read');

      // A read-only client asking for write at refresh time. Allowing this is
      // what makes the scope on the original grant decorative.
      await expect(
        provider.exchangeRefreshToken(CLIENT, tokens.refresh_token as string, [
          'mailcow:read',
          'mailcow:write',
        ]),
      ).rejects.toThrow(InvalidScopeError);
    });

    it('allows narrowing scope on refresh', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);
      const narrowed = await provider.exchangeRefreshToken(
        CLIENT,
        tokens.refresh_token as string,
        ['mailcow:read'],
      );
      expect(narrowed.scope).toBe('mailcow:read');

      const info = await provider.verifyAccessToken(narrowed.access_token);
      expect(info.scopes).toEqual(['mailcow:read']);
    });

    it('advertises exactly the scopes it enforces', () => {
      expect(makeProvider().scopesSupported).toEqual([...SUPPORTED_SCOPES]);
    });
  });

  describe('grant identity', () => {
    it('exposes the grant id on the verified token', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);
      const info = await provider.verifyAccessToken(tokens.access_token);
      expect(typeof info.extra?.grantId).toBe('string');
      expect((info.extra?.grantId as string).length).toBeGreaterThan(20);
    });

    it('keeps the grant id stable across a refresh, and distinct between grants', async () => {
      const provider = makeProvider();

      const a1 = await issueGrant(provider);
      const a2 = await provider.exchangeRefreshToken(CLIENT, a1.refresh_token as string);
      const b1 = await issueGrant(provider);

      const idA1 = (await provider.verifyAccessToken(a1.access_token)).extra?.grantId;
      const idA2 = (await provider.verifyAccessToken(a2.access_token)).extra?.grantId;
      const idB1 = (await provider.verifyAccessToken(b1.access_token)).extra?.grantId;

      // Stable across refresh, so the transport can bind a session to it.
      expect(idA2).toBe(idA1);
      // Distinct between authorizations, so that binding means something.
      expect(idB1).not.toBe(idA1);
    });

    it('refuses a refresh token presented by a different client', async () => {
      const provider = makeProvider();
      const tokens = await issueGrant(provider);
      await expect(
        provider.exchangeRefreshToken(OTHER_CLIENT, tokens.refresh_token as string),
      ).rejects.toThrow(InvalidGrantError);
    });
  });

  describe('the pending-authorization blob', () => {
    it('rejects a tampered blob', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);

      // Flip a character in the signed payload. The signature no longer covers
      // it, so the parameters coming back are not the ones we sent.
      const body = blob.slice(0, blob.lastIndexOf('.'));
      const mac = blob.slice(blob.lastIndexOf('.'));
      const flipped = (body[0] === 'A' ? 'B' : 'A') + body.slice(1) + mac;

      expect(provider.completeAuthorization(flipped, PASSWORD)).toBeNull();
    });

    it('rejects a signature of the wrong length', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);
      const body = blob.slice(0, blob.lastIndexOf('.'));
      const mac = blob.slice(blob.lastIndexOf('.') + 1);

      // A sha256 digest is exactly 43 base64url characters. Padding or
      // truncating it must not produce a second blob that decodes the same
      // parameters, because anything downstream that treats a blob as an
      // identity would then see two.
      expect(provider.completeAuthorization(`${body}.${mac}A`, PASSWORD)).toBeNull();
      expect(provider.completeAuthorization(`${body}.${mac}==`, PASSWORD)).toBeNull();
      expect(provider.completeAuthorization(`${body}.${mac.slice(0, -1)}`, PASSWORD)).toBeNull();
    });

    it('rejects a signature outside the base64url alphabet', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);
      const body = blob.slice(0, blob.lastIndexOf('.'));
      const mac = blob.slice(blob.lastIndexOf('.') + 1);
      expect(provider.completeAuthorization(`${body}.${mac.slice(0, -1)}*`, PASSWORD)).toBeNull();
    });

    it('rejects a blob with the signature stripped', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);
      const body = blob.slice(0, blob.lastIndexOf('.'));
      expect(provider.completeAuthorization(body, PASSWORD)).toBeNull();
    });

    it('rejects a blob minted by another process', async () => {
      const mine = makeProvider();
      const theirs = makeProvider();
      const blob = await consentBlob(theirs);
      // The signing key is per-process, so a blob from elsewhere is not valid
      // here even though both instances share the operator password.
      expect(mine.completeAuthorization(blob, PASSWORD)).toBeNull();
    });

    it('rejects a valid blob with the wrong password', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);
      expect(provider.completeAuthorization(blob, 'not-the-password')).toBeNull();
    });

    it('accepts its own blob with the right password', async () => {
      const provider = makeProvider();
      const blob = await consentBlob(provider);
      const redirect = provider.completeAuthorization(blob, PASSWORD);
      expect(redirect).toContain(REDIRECT);
      expect(new URL(redirect as string).searchParams.get('state')).toBe('state-value');
    });
  });

  describe('construction', () => {
    it('refuses to start without a password', () => {
      expect(
        () =>
          new MailcowOAuthProvider({
            operatorPassword: '',
            issuerUrl: new URL('https://mcp.example.com'),
          }),
      ).toThrow(/MCP_OAUTH_PASSWORD/);
    });

    it('refuses a short password', () => {
      expect(
        () =>
          new MailcowOAuthProvider({
            operatorPassword: 'short',
            issuerUrl: new URL('https://mcp.example.com'),
          }),
      ).toThrow(/12 characters/);
    });
  });
});
