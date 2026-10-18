/**
 * Streamable HTTP transport
 *
 * Serves the MCP server over HTTP so it can be used as a remote MCP server by
 * Claude (web and desktop) and ChatGPT. Both require a public HTTPS endpoint
 * speaking Streamable HTTP, and neither can send a static bearer header, hence
 * the OAuth endpoints mounted alongside.
 *
 * This module deliberately does not terminate TLS. Run it behind a reverse
 * proxy that does, and bind it to loopback. A mail-administration endpoint
 * should not be the thing parsing TLS from the open internet.
 */

import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { CONSENT_SUBMIT_PATH, type MailcowOAuthProvider } from '../auth/oauth-provider.js';
import type { Logger } from '../utils/logger.js';

/**
 * Factory for the MCP protocol object.
 *
 * A `Server` instance can be connected to exactly one transport: the second
 * `connect()` throws `Already connected to a transport`. Since each MCP session
 * gets its own transport, each session needs its own `Server`, or the server
 * serves one client and rejects every other.
 *
 * Only the protocol object is per-session. The tool registry, API client and
 * configuration behind it are shared, which is what you want: the sessions are
 * separate conversations against the same mailcow.
 */
export type McpServerFactory = () => Server | Promise<Server>;

export interface HttpTransportOptions {
  host: string;
  port: number;
  /** Public origin this server is reached at, e.g. https://mail.example.com/mcp */
  publicUrl: URL;
  provider: MailcowOAuthProvider;
  logger: Logger;
  /** Trust X-Forwarded-* headers. Enable only when behind a known proxy. */
  trustProxy: boolean;
  /** Max JSON body size. Mail admin payloads are small. */
  maxBodyBytes?: number;
}

/** Minimum spacing between two password checks, doubling per failure. */
const CONSENT_BASE_INTERVAL_MS = 1000;
/** Ceiling on that spacing. */
const CONSENT_MAX_INTERVAL_MS = 30_000;
/** Failures stop counting towards the interval once the window has passed. */
const CONSENT_FAILURE_WINDOW_MS = 15 * 60 * 1000;
/**
 * How many submissions may be waiting for their turn to be checked.
 *
 * Past this the route sheds, and it sheds *before* looking at the password, so
 * the decision cannot depend on whether the password was right.
 */
const CONSENT_MAX_QUEUE = 8;

/**
 * Minimum interval between password checks, by failure count in the window.
 *
 * This gates how often a guess is *evaluated*, which is the only thing that
 * actually limits guessing. An earlier version used the same schedule to delay
 * the *reply* instead, and that is worth spelling out because it looked
 * equivalent and was not: an attacker does not need the reply, only the
 * verdict. They would saturate the route, every guess would still be evaluated
 * at full speed, a wrong one had its socket dropped at once and a right one
 * returned an immediate redirect. The delay slowed nobody and the saturation
 * path was a clean negative oracle.
 *
 * Exported for the unit test, which is where the schedule is checked: an
 * integration test can only observe it by waiting.
 */
export function consentIntervalFor(failures: number): number {
  const exponent = Math.min(Math.max(failures, 1) - 1, 10);
  return Math.min(CONSENT_BASE_INTERVAL_MS * 2 ** exponent, CONSENT_MAX_INTERVAL_MS);
}

interface McpSession {
  transport: StreamableHTTPServerTransport;
  /** This session's own protocol object. Closed with the session. */
  server: Server;
  /**
   * The grant that opened the session.
   *
   * Sessions are bound to the grant rather than to the access token, because
   * the token rotates hourly and the session should survive that. Binding to
   * something is the point: a session id is a bearer capability on its own, so
   * without this check any valid token could attach to any live session.
   */
  grantId?: string;
  clientId: string;
}

/** The SDK's bearer middleware attaches this. Not in Express's own types. */
type AuthedRequest = Request & { auth?: AuthInfo };

function authOf(req: Request): AuthInfo | undefined {
  return (req as AuthedRequest).auth;
}

function grantIdOf(auth: AuthInfo | undefined): string | undefined {
  const value = auth?.extra?.grantId;
  return typeof value === 'string' ? value : undefined;
}

/**
 * One transport, and one `Server`, per MCP session.
 *
 * Streamable HTTP is session-oriented: the client initializes once, receives a
 * session id, and sends subsequent requests with that id. Sessions are held in
 * memory and dropped when the transport closes.
 */
export class HttpTransportHost {
  private readonly app: Express;
  private readonly sessions = new Map<string, McpSession>();
  private httpServer?: ReturnType<Express['listen']>;
  /**
    * Failed authorizations in the current window, counted across every caller.
    *
    * Deliberately one number and not a map. An earlier version keyed the
    * backoff on a hash of the consent blob, reasoning that the operator should
    * not be slowed by somebody else's failures. That is resettable at will:
    * `/authorize` needs no authentication and registration is open, so an
    * attacker fetches a fresh consent page before every guess, every guess is
    * the first failure for its own key, and the backoff never leaves its first
    * step. A global count is the only version an attacker cannot reset.
    */
  private consentFailures = 0;
  private consentWindowStartedAt = 0;
  /** Submissions waiting for, or currently holding, the check slot. */
  private consentQueueDepth = 0;
  /** Earliest time the next password check may run. */
  private consentNextSlotAt = 0;

  constructor(
    private readonly createMcpServer: McpServerFactory,
    private readonly options: HttpTransportOptions,
  ) {
    this.app = express();
    this.configure();
  }

  private configure(): void {
    const { provider, publicUrl, logger, trustProxy } = this.options;

    // Behind a reverse proxy the client IP and protocol arrive in headers.
    // Trusting them unconditionally would let a direct caller spoof both, so
    // this is opt-in and should be paired with binding to loopback.
    this.app.set('trust proxy', trustProxy ? 1 : false);
    this.app.disable('x-powered-by');

    this.app.use(
      express.json({ limit: this.options.maxBodyBytes ?? 1_000_000 }),
    );
    this.app.use(express.urlencoded({ extended: false, limit: 64_000 }));

    this.app.use((_req, res, next) => {
      // This endpoint is machine-to-machine and serves one HTML page (consent).
      // Nothing here should ever be framed, sniffed or cached.
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Cache-Control', 'no-store');
      next();
    });

    // --- Consent submission ----------------------------------------------
    //
    // Registered BEFORE mcpAuthRouter, and that ordering is load-bearing.
    //
    // The SDK mounts its authorization handler with `router.use('/authorize',
    // ...)`, which matches sub-paths, so `/authorize/consent` would otherwise
    // inherit that handler's rate limiter: a fixed 100 requests per 15 minutes
    // keyed on the client IP. Two problems with inheriting it. It returns 429,
    // so an attacker who trips it locks the operator out of their own consent
    // screen; and with `trust proxy` off behind a proxy every request appears
    // to come from the proxy's address, which makes that one shared counter
    // and the lockout trivial to trigger.
    //
    // Password guessing is throttled here instead, with delay rather than
    // refusal: a wrong answer gets slower, but a correct one is never refused,
    // so there is nothing for an attacker to trip.
    this.app.post(CONSENT_SUBMIT_PATH, (req: Request, res: Response) => {
      void this.handleConsentSubmission(req, res);
    });

    // --- OAuth 2.1 -------------------------------------------------------
    // Mounts /authorize, /token, /register (DCR), /revoke and the
    // .well-known metadata documents the clients discover the server through.
    this.app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: publicUrl,
        resourceServerUrl: publicUrl,
        resourceName: 'mailcow MCP',
        scopesSupported: provider.scopesSupported,
      }),
    );

    // --- Liveness --------------------------------------------------------
    // Unauthenticated on purpose: it reveals nothing and the container
    // healthcheck needs it. It must never grow a body that says anything
    // about configuration.
    this.app.get('/healthz', (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    // --- MCP -------------------------------------------------------------
    //
    // No `requiredScopes` here on purpose. Scope is enforced per tool, where
    // the read/write distinction actually lives, so a client that holds only
    // one of the two scopes still connects and simply cannot call the tools it
    // was not granted. Requiring a scope at this boundary would reject such a
    // client at `initialize` with nothing useful to tell it.
    const auth = requireBearerAuth({
      verifier: provider,
      resourceMetadataUrl: new URL('/.well-known/oauth-protected-resource', publicUrl).toString(),
    });

    this.app.post('/mcp', auth, (req, res) => void this.handlePost(req, res));
    this.app.get('/mcp', auth, (req, res) => void this.handleSessionRequest(req, res));
    this.app.delete('/mcp', auth, (req, res) => void this.handleSessionRequest(req, res));

    // Anything else is not part of the contract.
    this.app.use((_req, res) => {
      res.status(404).type('text/plain').send('Not found');
    });

    // --- Errors ----------------------------------------------------------
    //
    // Last, so it catches everything above, including the body parsers: a
    // malformed JSON body or one over the size limit throws here rather than
    // reaching a route.
    //
    // Express's default handler prints the stack when NODE_ENV is unset. The
    // container sets it to production, which makes the leak conditional on
    // deployment rather than absent, so the stack is dropped unconditionally
    // instead of trusting an environment variable to be right.
    this.app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
      const error = err instanceof Error ? err : new Error(String(err));
      const status = statusOf(err);

      // Full detail server-side, where the operator can see it.
      logger.error('Request failed', error, { path: req.path, method: req.method, status });

      if (res.headersSent) {
        res.end();
        return;
      }
      // Nothing from the error object goes to the client, not the message and
      // not the stack. A caller learns the shape of its own mistake from the
      // status code.
      if (req.path === '/mcp') {
        res.status(status).json(jsonRpcError(-32700, 'Invalid request'));
      } else {
        res.status(status).type('text/plain').send('Invalid request');
      }
    });
  }

  /**
   * Handle a consent submission under a global check-rate limit.
   *
   * Three properties, each of which replaces a mistake made here before:
   *
   *   1. The throttle limits how often a password is *checked*, not how long
   *      the answer takes. Delaying the answer leaves the check running at
   *      full speed, and the verdict is what an attacker is after.
   *   2. Shedding happens before the check and on a condition that has nothing
   *      to do with the password, so a shed cannot be read as "wrong".
   *   3. A correct password waits its turn like any other. Letting it skip the
   *      queue is what turned saturation into a fast negative oracle: drops
   *      meant wrong, an immediate redirect meant right.
   *
   * The cost is that a sustained attack can delay, and past the queue bound
   * refuse, the operator's own submissions. There is no way to avoid that on an
   * endpoint that cannot tell the operator from anyone else: `/authorize` needs
   * no authentication and registration is open, so any token this route could
   * hand the operator, an attacker can request too. The controls that do
   * distinguish them live in front of this process (a source allowlist on the
   * proxy) and in the password's entropy, not here.
   */
  private async handleConsentSubmission(req: Request, res: Response): Promise<void> {
    const { provider, logger } = this.options;
    const { pending, password } = req.body ?? {};
    if (typeof pending !== 'string' || typeof password !== 'string') {
      res.status(400).type('text/plain').send('Malformed authorization request');
      return;
    }

    if (this.consentQueueDepth >= CONSENT_MAX_QUEUE) {
      logger.warn('Authorization submission shed; check queue is full', { ip: req.ip });
      res.status(503).type('text/plain').send('Try again shortly');
      return;
    }

    this.consentQueueDepth += 1;
    try {
      await this.awaitConsentSlot();

      const redirectTo = provider.completeAuthorization(pending, password);

      if (redirectTo) {
        // Only a correct password clears the throttle, and guessing cannot
        // produce one. Clearing the reserved-slot cursor as well as the count
        // matters: without it, slots already reserved by an attack keep
        // spacing out the operator's next submissions after they have proven
        // who they are.
        this.consentFailures = 0;
        this.consentNextSlotAt = 0;
        logger.info('Authorization granted', { ip: req.ip });
        if (!res.headersSent) res.redirect(302, redirectTo);
        return;
      }

      // Identical for a bad password, a tampered blob and an expired consent
      // page. The caller does not learn which.
      this.registerConsentFailure();
      logger.warn('Authorization attempt rejected', {
        ip: req.ip,
        failures: this.consentFailures,
      });
      if (!res.headersSent) {
        res.status(401).type('text/plain').send('Authorization failed');
      }
    } finally {
      this.consentQueueDepth -= 1;
    }
  }

  /**
   * Wait until this submission's turn to be checked.
   *
   * Reserves the next slot before waiting, so concurrent submissions queue
   * behind one another instead of all being checked at once. The spacing is
   * taken from the failure count, which is global for the window because any
   * per-caller key is resettable: `/authorize` is unauthenticated and
   * registration is open, so a fresh consent page per guess resets anything
   * keyed to the page.
   */
  private async awaitConsentSlot(): Promise<void> {
    const now = Date.now();
    if (now - this.consentWindowStartedAt > CONSENT_FAILURE_WINDOW_MS) {
      this.consentWindowStartedAt = now;
      this.consentFailures = 0;
      this.consentNextSlotAt = 0;
    }

    const slot = Math.max(now, this.consentNextSlotAt);
    this.consentNextSlotAt = slot + consentIntervalFor(this.consentFailures + 1);

    const wait = slot - now;
    if (wait > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, wait));
    }
  }

  private registerConsentFailure(): void {
    const now = Date.now();
    if (now - this.consentWindowStartedAt > CONSENT_FAILURE_WINDOW_MS) {
      this.consentWindowStartedAt = now;
      this.consentFailures = 0;
    }
    this.consentFailures += 1;
  }

  /** Exposed for tests: failed authorizations counted in the current window. */
  get consentFailureCount(): number {
    return this.consentFailures;
  }

  /**
   * Check that the caller owns the session it names.
   *
   * A session id travels in a plain header and is a capability by itself, so
   * without this any authenticated caller could drive any live session: one
   * tenant of the same deployment, or an attacker holding a token from a
   * separate authorization, resuming someone else's conversation and reading
   * its results.
   */
  private ownsSession(session: McpSession, auth: AuthInfo | undefined): boolean {
    const grantId = grantIdOf(auth);
    if (session.grantId && grantId) return session.grantId === grantId;
    // No grant id on one side or the other (a provider that does not supply
    // one). Fall back to the client, which is weaker but not nothing.
    return !!auth && session.clientId === auth.clientId;
  }

  private async handlePost(req: Request, res: Response): Promise<void> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const auth = authOf(req);

    try {
      const existing = sessionId ? this.sessions.get(sessionId) : undefined;

      if (existing) {
        if (!this.ownsSession(existing, auth)) {
          this.options.logger.warn('Rejected cross-grant session access', {
            sessionId,
            clientId: auth?.clientId,
          });
          // 404 rather than 403: a caller that does not own the session should
          // not learn that it exists.
          res.status(404).json(jsonRpcError(-32001, 'Unknown session'));
          return;
        }
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }

      if (sessionId) {
        res.status(404).json(jsonRpcError(-32001, 'Unknown session'));
        return;
      }
      if (!isInitializeRequest(req.body)) {
        res.status(400).json(jsonRpcError(-32000, 'First request must be initialize'));
        return;
      }

      // New session: its own protocol object, its own transport.
      const server = await this.createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id): void => {
          this.sessions.set(id, {
            transport,
            server,
            grantId: grantIdOf(auth),
            clientId: auth?.clientId ?? 'unknown',
          });
          this.options.logger.info('MCP session initialized', {
            sessionId: id,
            clientId: auth?.clientId,
            sessions: this.sessions.size,
          });
        },
      });

      transport.onclose = (): void => {
        const id = transport.sessionId;
        if (id) this.sessions.delete(id);
        // The per-session Server goes with it. Left open, each closed session
        // would leak a protocol object and its handlers.
        void server.close().catch(() => {
          /* best effort */
        });
        if (id) {
          this.options.logger.info('MCP session closed', {
            sessionId: id,
            sessions: this.sessions.size,
          });
        }
      };

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      this.options.logger.error('MCP request failed', error as Error);
      if (!res.headersSent) {
        res.status(500).json(jsonRpcError(-32603, 'Internal error'));
      }
    }
  }

  private async handleSessionRequest(req: Request, res: Response): Promise<void> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const session = sessionId ? this.sessions.get(sessionId) : undefined;

    if (!session || !this.ownsSession(session, authOf(req))) {
      if (session) {
        this.options.logger.warn('Rejected cross-grant session access', {
          sessionId,
          clientId: authOf(req)?.clientId,
        });
      }
      res.status(404).type('text/plain').send('Unknown session');
      return;
    }

    try {
      await session.transport.handleRequest(req, res);
    } catch (error) {
      this.options.logger.error('MCP session request failed', error as Error);
      if (!res.headersSent) res.status(500).end();
    }
  }

  async start(): Promise<void> {
    const { host, port, logger, publicUrl } = this.options;

    await new Promise<void>((resolve, reject) => {
      this.httpServer = this.app.listen(port, host, () => resolve());
      this.httpServer.on('error', reject);
    });

    logger.info('MCP HTTP transport listening', {
      bind: `${host}:${port}`,
      publicUrl: publicUrl.toString(),
    });

    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      logger.warn(
        `HTTP transport is bound to ${host}, not loopback. This server does not ` +
          'terminate TLS and should sit behind a reverse proxy that does.',
      );
    }
  }

  async stop(): Promise<void> {
    for (const session of this.sessions.values()) {
      try {
        await session.transport.close();
      } catch {
        /* best effort on shutdown */
      }
      try {
        await session.server.close();
      } catch {
        /* best effort on shutdown */
      }
    }
    this.sessions.clear();

    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer!.close(() => resolve()));
    }
  }

  /** Exposed for tests. */
  get expressApp(): Express {
    return this.app;
  }

  /** Exposed for tests: number of live MCP sessions. */
  get sessionCount(): number {
    return this.sessions.size;
  }
}

/** Map a thrown error to a status without echoing anything from it. */
function statusOf(err: unknown): number {
  const status = (err as { status?: number; statusCode?: number } | null)?.status
    ?? (err as { statusCode?: number } | null)?.statusCode;
  return typeof status === 'number' && status >= 400 && status <= 599 ? status : 400;
}

interface JsonRpcErrorBody {
  jsonrpc: '2.0';
  error: { code: number; message: string };
  id: null;
}

function jsonRpcError(code: number, message: string): JsonRpcErrorBody {
  return { jsonrpc: '2.0' as const, error: { code, message }, id: null };
}
