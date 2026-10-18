/**
 * Streamable HTTP transport
 *
 * Serves the MCP server over HTTP so it can be used as a remote MCP server by
 * Claude (web and desktop) and ChatGPT. Both require a public HTTPS endpoint
 * speaking Streamable HTTP, and neither can send a static bearer header — hence
 * the OAuth endpoints mounted alongside.
 *
 * This module deliberately does not terminate TLS. Run it behind a reverse
 * proxy that does, and bind it to loopback. A mail-administration endpoint
 * should not be the thing parsing TLS from the open internet.
 */

import express, { type Express, type Request, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { CONSENT_SUBMIT_PATH, type MailcowOAuthProvider } from '../auth/oauth-provider.js';
import type { Logger } from '../utils/logger.js';

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

/**
 * One transport per MCP session.
 *
 * Streamable HTTP is session-oriented: the client initializes once, receives a
 * session id, and sends subsequent requests with that id. Sessions are held in
 * memory and dropped when the transport closes.
 */
export class HttpTransportHost {
  private readonly app: Express;
  private readonly transports = new Map<string, StreamableHTTPServerTransport>();
  private httpServer?: ReturnType<Express['listen']>;

  constructor(
    private readonly mcpServer: Server,
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

    // --- OAuth 2.1 -------------------------------------------------------
    // Mounts /authorize, /token, /register (DCR), /revoke and the
    // .well-known metadata documents the clients discover the server through.
    this.app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: publicUrl,
        resourceServerUrl: publicUrl,
        resourceName: 'mailcow MCP',
        scopesSupported: ['mailcow:read', 'mailcow:write'],
      }),
    );

    // The consent form posts back here.
    //
    // Note the path: the SDK's authorization handler accepts both GET and POST
    // on /authorize, so a form posting there is parsed as an OAuth request and
    // rejected with a 400 before this handler ever runs. The submission needs
    // its own route.
    this.app.post(CONSENT_SUBMIT_PATH, (req: Request, res: Response) => {
      const { pending, password } = req.body ?? {};
      if (typeof pending !== 'string' || typeof password !== 'string') {
        res.status(400).type('text/plain').send('Malformed authorization request');
        return;
      }

      const redirectTo = provider.completeAuthorization(pending, password);
      if (!redirectTo) {
        // Deliberately identical for a bad password and a malformed blob, and
        // deliberately slow enough to make online guessing unattractive.
        logger.warn('Authorization attempt rejected', { ip: req.ip });
        setTimeout(() => {
          res.status(401).type('text/plain').send('Authorization failed');
        }, 1000);
        return;
      }

      logger.info('Authorization granted', { ip: req.ip });
      res.redirect(302, redirectTo);
    });

    // --- Liveness --------------------------------------------------------
    // Unauthenticated on purpose: it reveals nothing and the container
    // healthcheck needs it. It must never grow a body that says anything
    // about configuration.
    this.app.get('/healthz', (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    // --- MCP -------------------------------------------------------------
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
  }

  private async handlePost(req: Request, res: Response): Promise<void> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    try {
      let transport = sessionId ? this.transports.get(sessionId) : undefined;

      if (!transport) {
        if (sessionId) {
          res.status(404).json(jsonRpcError(-32001, 'Unknown session'));
          return;
        }
        if (!isInitializeRequest(req.body)) {
          res.status(400).json(jsonRpcError(-32000, 'First request must be initialize'));
          return;
        }

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            this.transports.set(id, transport!);
            this.options.logger.info('MCP session initialized', { sessionId: id });
          },
        });

        transport.onclose = () => {
          const id = transport!.sessionId;
          if (id) {
            this.transports.delete(id);
            this.options.logger.info('MCP session closed', { sessionId: id });
          }
        };

        await this.mcpServer.connect(transport);
      }

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
    const transport = sessionId ? this.transports.get(sessionId) : undefined;

    if (!transport) {
      res.status(404).type('text/plain').send('Unknown session');
      return;
    }

    try {
      await transport.handleRequest(req, res);
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
    for (const transport of this.transports.values()) {
      try {
        await transport.close();
      } catch {
        /* best effort on shutdown */
      }
    }
    this.transports.clear();

    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer!.close(() => resolve()));
    }
  }

  /** Exposed for tests. */
  get expressApp(): Express {
    return this.app;
  }
}

function jsonRpcError(code: number, message: string) {
  return { jsonrpc: '2.0' as const, error: { code, message }, id: null };
}
