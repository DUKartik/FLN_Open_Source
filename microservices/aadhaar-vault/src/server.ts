/**
 * Fastify bootstrap.
 *
 * Responsibilities:
 *  - Parse + validate env (refuses to boot on misconfig).
 *  - Build the Pino logger with PII redaction.
 *  - Register a JSON body parser with a hard size cap.
 *  - Register the health routes.
 *  - Wire the Postgres pool + repositories on the Fastify instance as
 *    `app.db`. Health probes use this to ping the database.
 *  - Wire the auth plugin (HS256 JWT verifier + scopes) when config
 *    supplies an HMAC secret. Public routes (health) carry a route
 *    config flag `{ public: true }` and bypass the verifier.
 *  - Wire graceful SIGINT/SIGTERM shutdown (closes both Fastify and DB).
 *
 * Session 2 wires the DB. Session 3 wires the key manager. Session 4
 * wires the auth plugin. The wiring seam is the same: an instance
 * decorator + a register call before routes.
 */
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type RawServerDefault,
} from 'fastify';

import { loadConfig, type Config } from './config.js';
import {
  createDatabase,
  createMemoryDatabase,
  pingPool,
  type Database,
} from './db/index.js';
import { createLogger, type Logger } from './logger.js';
import { healthRoutes } from './routes/health.routes.js';
import { tokenizeRoutes } from './routes/tokenize.routes.js';
import { detokenizeRoutes } from './routes/detokenize.routes.js';
import { auditRoutes } from './routes/audit.routes.js';

import { createKeyManager } from './infrastructure/key-providers/index.js';
import type { KeyManager } from './application/ports/key-manager.js';
import type { CryptoService } from './application/ports/crypto.service.js';
import type { EventPublisher } from './application/ports/event-publisher.js';
import type { TransactionalVaultWriter } from './application/ports/transactional-vault-writer.js';
import type { JwtVerifier } from './application/ports/jwt-verifier.js';
import type { TotpVerifier } from './application/ports/totp-verifier.js';
import { NodeCryptoService } from './infrastructure/crypto/node-crypto.service.js';
import { InProcessEventPublisher } from './infrastructure/events/in-process-event-publisher.js';
import { OtpAuthTotpVerifier } from './infrastructure/mfa/totp-verifier.js';
import { createJwtVerifierFromConfig } from './auth/factory.js';
import authPlugin from './auth/plugin.js';

export interface BuildServerOptions {
  config?: Config;
  logger?: Logger;
  /**
   * Optional DB override. If supplied, used verbatim (e.g. a test
   * passes a pg-mem-backed `Database`). When omitted, the server
   * derives the DB from `config`:
   *   - `VAULT_DB_URI` set → real Postgres pool.
   *   - `NODE_ENV === 'test'` with no URI → pg-mem (in-process).
   *   - otherwise → undefined; routes that need the DB will fail loudly.
   */
  db?: Database;
  /** Disable DB check in /health/ready (debug/diagnostic use only). */
  disableDbCheck?: boolean;
  /**
   * Optional KeyManager override. When omitted, the server constructs
   * one via the factory; the factory fires the production-safety guard
   * (refuses `KEY_PROVIDER=local-dev` in production without override).
   * Tests can pass a fully-built KeyManager to bypass the factory.
   */
  keyManager?: KeyManager;
  /**
   * Optional CryptoService override. Defaults to `NodeCryptoService`,
   * which only uses Node's built-in `crypto` module and is safe to
   * instantiate unconditionally.
   */
  crypto?: CryptoService;
  /**
   * Optional EventPublisher override. Defaults to the in-process
   * adapter (a no-op aside from a debug log line) so the boot path is
   * a single constructor. A future Redis Streams adapter lands here.
   */
  events?: EventPublisher;
  /**
   * Optional JwtVerifier override. When omitted, the server attempts to
   * construct one via the factory (`createJwtVerifierFromConfig`). If the
   * factory returns `undefined` (e.g. test config without
   * `SERVICE_JWT_HMAC_SECRET`), the server boots WITHOUT an auth plugin
   * — health probes remain public, but every other route is wired to a
   * 503-by-default handler via the auth plugin's requireScope guard.
   * Tests that exercise authenticated routes must pass a fully-built
   * verifier here.
   */
  jwtVerifier?: JwtVerifier;
  /**
   * Optional TotpVerifier override. When omitted, the server instantiates
   * {@link OtpAuthTotpVerifier} unconditionally — it has no required
   * configuration and is safe to wire on every boot. Tests can pass a
   * stub here to assert against specific clock values.
   */
  totpVerifier?: TotpVerifier;
}

declare module 'fastify' {
  interface FastifyInstance {
    db?: Database;
    keyManager?: KeyManager;
    crypto?: CryptoService;
    events?: EventPublisher;
    /**
     * Convenience reference to `db?.vaultWriter`. Set iff `db` is set.
     * Surfaced so the route module can address it through the same
     * `app.*` fastify-decoration seam as everything else.
     */
    vaultWriter?: TransactionalVaultWriter;
    /**
     * Set iff a JwtVerifier was wired at boot. Used by the auth plugin
     * to verify bearer tokens, and by individual routes to enforce
     * scopes. When undefined the auth plugin is not registered — see
     * `BuildServerOptions.jwtVerifier` for the rationale.
     */
    jwtVerifier?: JwtVerifier;
    /**
     * Always set after boot. Wired by `buildServer` (override-able for
     * tests). Routes that need TOTP enrollment / verification read this
     * from the Fastify instance the same way they read every other
     * cross-cutting port.
     */
    totpVerifier?: TotpVerifier;
  }
}

export async function buildServer(
  options: BuildServerOptions = {},
): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();
  const logger = options.logger ?? createLogger(config);

  // Pin the Logger generic to FastifyBaseLogger so the instance type matches
  // the FastifyInstance<...FastifyBaseLogger...> declared by the public API.
  const app = Fastify<
    RawServerDefault,
    import('http').IncomingMessage,
    import('http').ServerResponse,
    FastifyBaseLogger
  >({
    logger,
    bodyLimit: 1024 * 64, // 64 KiB hard cap; the largest body is the tokenize request.
    trustProxy: true,
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'reqId',
    disableRequestLogging: false,
  });

  // Wire the DB. Explicit override wins, then VAULT_DB_URI, then test
  // fallback. If none apply (e.g. production misconfig that the loader
  // already rejected) we leave `app.db` undefined and the readiness
  // probe reports it as `null` — that's a defence-in-depth signal, not
  // the primary guard.
  if (options.db !== undefined) {
    app.db = options.db;
  } else if (config.VAULT_DB_URI) {
    app.db = await createDatabase({ uri: config.VAULT_DB_URI, logger });
  } else if (config.NODE_ENV === 'test') {
    app.db = await createMemoryDatabase();
  }

  // Wire the KeyManager. Explicit override wins; otherwise the factory
  // dispatches on `KEY_PROVIDER` (default `local-dev`). The factory is
  // the single place that enforces the production-safety guard, so
  // every KeyManager that lives on a Fastify instance has already been
  // vetted. If construction throws we DO NOT swallow it — the server
  // refuses to boot, which is the only safe behaviour.
  if (options.keyManager !== undefined) {
    app.keyManager = options.keyManager;
  } else {
    app.keyManager = createKeyManager({ config, logger });
  }

  // Wire the CryptoService. NodeCryptoService is dependency-free (just
  // uses node's built-in crypto module), so it is safe to instantiate
  // unconditionally. A real KMS-backed CryptoService adapter would
  // gate construction on config the same way the KeyManager does.
  app.crypto = options.crypto ?? new NodeCryptoService();

  // Wire the EventPublisher. In-process adapter is fine for v0.1 —
  // events never leave the process. A future Redis Streams adapter
  // swaps in here via `options.events`.
  app.events =
    options.events ??
    new InProcessEventPublisher({
      logger: { info: (obj, msg) => logger.info(obj, msg) },
    });

  // Surface the transactional vault writer for the tokenize route.
  // The writer always travels with the Database; the alias is purely
  // a convenience so the route can read `app.vaultWriter` instead of
  // reaching through `app.db.vaultWriter` (and tripping nulls on a
  // hypothetical DB-less boot).
  app.vaultWriter = app.db?.vaultWriter;

  // Wire the JWT verifier. Explicit override wins; otherwise the
  // factory inspects config (algorithm + secret). If the factory
  // returns undefined (e.g. test config without SERVICE_JWT_HMAC_SECRET),
  // we leave `app.jwtVerifier` undefined — the auth plugin registration
  // below then becomes a no-op. This is intentional: a unit test that
  // boots in `NODE_ENV=test` and only exercises public health probes
  // does not need to mint bearer tokens.
  //
  // Production safety: `loadConfig` already aborts boot if
  // NODE_ENV !== 'test' && !SERVICE_JWT_HMAC_SECRET, so the factory
  // never returns undefined in production.
  app.jwtVerifier =
    options.jwtVerifier ?? createJwtVerifierFromConfig(config, logger);

  // Wire the TOTP verifier. OtpAuthTotpVerifier has no required
  // configuration (it constructs its own CSPRNG secrets) so the default
  // boot path is unconditional. Tests pass a stub via `totpVerifier` to
  // assert against fixed clock values without monkey-patching Date.now.
  app.totpVerifier = options.totpVerifier ?? new OtpAuthTotpVerifier();

  // Central error handler.
  //
  // Honours an explicit `err.statusCode` in the 400-499 range so that
  // auth-plugin rejections (`requireScope` throws with statusCode 403)
  // surface to the caller as 403, not as a generic 500. Anything else —
  // a thrown TypeError, a Postgres connection failure, an unexpected
  // null deref — is collapsed to 500 with a generic envelope. We never
  // echo `err.message` to the client on 5xx because some messages may
  // contain identifiers (e.g. PII scrubbing lag).
  app.setErrorHandler((err, _req, reply) => {
    const rawStatus =
      typeof (err as { statusCode?: unknown }).statusCode === 'number'
        ? (err as { statusCode: number }).statusCode
        : 500;
    const status =
      rawStatus >= 400 && rawStatus < 500 ? rawStatus : 500;

    if (status >= 500) {
      logger.error({ err }, 'aadhaar-vault request failed');
      reply.code(500).send({
        error: 'internal_error',
        message: 'An unexpected error occurred.',
      });
      return;
    }

    // 4xx: log at info (not error), and pick a stable error envelope.
    logger.info(
      { err, status },
      'aadhaar-vault request rejected with client error',
    );
    const envelopeError =
      status === 401
        ? 'unauthorized'
        : status === 403
          ? 'forbidden'
          : status === 404
            ? 'not_found'
            : status === 409
              ? 'conflict'
              : status === 429
                ? 'rate_limited'
                : 'request_failed';
    reply.code(status).send({
      error: envelopeError,
      message:
        typeof err.message === 'string' && err.message.length > 0
          ? err.message
          : 'Request could not be processed.',
    });
  });

  // Defensive: a 404 should still be a JSON response, not Fastify's default HTML.
  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({
      error: 'not_found',
      message: 'The requested resource does not exist.',
    });
  });

  // Register the auth plugin first so the `onRequest` hook it installs
  // is in place before any route runs. The plugin is a no-op when
  // `app.jwtVerifier` is undefined (test config without HMAC secret);
  // every authenticated route guards itself with `req.requireScope()`
  // which throws 503 if invoked without a verifier.
  if (app.jwtVerifier) {
    await app.register(authPlugin, { verifier: app.jwtVerifier });
  } else {
    logger.warn(
      'aadhaar-vault booting WITHOUT a JwtVerifier; authenticated routes will reject every request. ' +
        'This is expected only when NODE_ENV=test without SERVICE_JWT_HMAC_SECRET.',
    );
  }

  await app.register(healthRoutes, {
    deps: {
      version: '0.1.0',
      keyManager: () => app.keyManager,
      isReady: async () => {
        if (options.disableDbCheck) return true;
        if (!app.db) return false;
        try {
          await pingPool(app.db.pool);
          return true;
        } catch (err) {
          app.log.error({ err }, 'aadhaar-vault readiness probe failed');
          return false;
        }
      },
    },
  });

  // Register the tokenize route. It depends on every cross-cutting
  // port having been wired onto the Fastify instance. If the DB is
  // absent, the route will simply return 503 on the first hit rather
  // than crashing the boot — the readiness probe already reports the
  // DB as unreachable.
  await app.register(tokenizeRoutes, {
    deps: {
      version: '0.1.0',
      keyManager: () => app.keyManager,
      crypto: () => app.crypto,
      vaultWriter: () => app.vaultWriter,
      events: () => app.events,
      db: () => app.db,
      logger,
    },
  });
  // Register the detokenize route. Same dependency shape as the
  // tokenize route, but the route does not need the vault writer
  // (detokenize is a read + audit-append, not a multi-row write).
  await app.register(detokenizeRoutes, {
    deps: {
      version: '0.1.0',
      keyManager: () => app.keyManager,
      crypto: () => app.crypto,
      events: () => app.events,
      db: () => app.db,
      logger,
    },
  });

  // Register the audit history route. Read-only: depends on the
  // `db.audit` port and a logger; no key manager, no crypto, no
  // vault writer, no event publisher. The route is gated by the
  // `vault:audit` JWT scope; the principal is the JWT subject.
  await app.register(auditRoutes, {
    deps: {
      version: '0.1.0',
      db: () => app.db,
      logger,
    },
  });


  // On close, drain the DB pool too. We only close pools that this
  // builder created — if the caller passed their own db, they're
  // responsible for closing it.
  app.addHook('onClose', async () => {
    if (app.db && options.db === undefined) {
      await app.db.close();
    }
  });

  return app;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger(config);

  const app = await buildServer({ config, logger });

  const shutdown = async (signal: string): Promise<void> => {
    logger.warn({ signal }, 'received shutdown signal, draining Fastify');
    try {
      await app.close();
      logger.info('aadhaar-vault shut down cleanly');
      process.exit(0);
    } catch (err) {
      logger.error({ err }, 'aadhaar-vault shutdown failed');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });

  try {
    await app.listen({ host: config.HOST, port: config.PORT });
    logger.info(
      { host: config.HOST, port: config.PORT },
      'aadhaar-vault listening',
    );
  } catch (err) {
    logger.fatal({ err }, 'aadhaar-vault failed to start');
    process.exit(1);
  }
}

// Run only when executed directly, not when imported by tests.
const isEntrypoint =
  import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`;
if (isEntrypoint) {
  void main();
}