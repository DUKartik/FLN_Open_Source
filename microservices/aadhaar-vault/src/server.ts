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
 *  - Wire graceful SIGINT/SIGTERM shutdown (closes both Fastify and DB).
 *
 * Session 2 wires the DB. Sessions 3–5 (crypto, auth, OpenAPI) plug in
 * the same way: an instance decorator + a graceful shutdown hook.
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
import {
  createKeyManager,
} from './infrastructure/key-providers/index.js';
import type { KeyManager } from './application/ports/key-manager.js';
import type { CryptoService } from './application/ports/crypto.service.js';
import type { EventPublisher } from './application/ports/event-publisher.js';
import type { TransactionalVaultWriter } from './application/ports/transactional-vault-writer.js';
import { NodeCryptoService } from './infrastructure/crypto/node-crypto.service.js';
import { InProcessEventPublisher } from './infrastructure/events/in-process-event-publisher.js';

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

  app.setErrorHandler((err, _req, reply) => {
    // Log the error with the request context. The response shape is intentionally
    // minimal — the vault never echoes internal error messages to the caller
    // because some of them may contain identifiers.
    logger.error({ err }, 'aadhaar-vault request failed');
    reply.code(500).send({
      error: 'internal_error',
      message: 'An unexpected error occurred.',
    });
  });

  // Defensive: a 404 should still be a JSON response, not Fastify's default HTML.
  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({
      error: 'not_found',
      message: 'The requested resource does not exist.',
    });
  });

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