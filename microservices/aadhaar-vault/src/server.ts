/**
 * Fastify bootstrap.
 *
 * Responsibilities:
 *  - Parse + validate env (refuses to boot on misconfig).
 *  - Build the Pino logger with PII redaction.
 *  - Register a JSON body parser with a hard size cap.
 *  - Register the health routes.
 *  - Wire graceful SIGINT/SIGTERM shutdown.
 *
 * Session 1 does NOT yet wire:
 *  - Database pool (Session 2)
 *  - Crypto module (Session 3)
 *  - JWT/MFA auth (Session 4)
 *  - Swagger UI / OpenAPI (Session 5)
 */
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type RawServerDefault,
} from 'fastify';
import { loadConfig, type Config } from './config.js';
import { createLogger, type Logger } from './logger.js';
import { healthRoutes } from './routes/health.routes.js';

export interface BuildServerOptions {
  config?: Config;
  logger?: Logger;
}

export async function buildServer(
  options: BuildServerOptions = {},
): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();
  const logger = options.logger ?? createLogger(config);

  // Pin the Logger generic to FastifyBaseLogger so the instance type matches
  // the FastifyInstance<...FastifyBaseLogger...> declared by the public API.
  // Pino's richer `Logger` type is structurally a super-set; we keep it for
  // runtime use but erase it at the boundary.
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

  await app.register(healthRoutes, { deps: { version: '0.1.0' } });

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