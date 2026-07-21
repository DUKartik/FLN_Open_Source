/**
 * Health routes.
 *
 * Architecture doc §6 mandates three probes with distinct semantics:
 *   - GET /health       — generic liveness payload, never fails.
 *   - GET /health/live  — Kubernetes-style liveness; returns 200 always.
 *   - GET /health/ready — Kubernetes-style readiness; reports dependency status.
 *
 * Session 2 wires a real Postgres ping via the `isReady` dep. Session 3
 * will add a key-provider reachability check alongside it.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';

export interface HealthDeps {
  version: string;
  /**
   * Used by `/health/ready` to decide whether to return 200 or 503.
   * Should resolve `true` only when every dependency it owns is healthy.
   * The plugin **does not** throw on `false` — the route returns 503
   * with the reason inline.
   */
  isReady: () => Promise<boolean>;
}

export const healthRoutes: FastifyPluginAsync<{ deps: HealthDeps }> = async (
  app: FastifyInstance,
  { deps },
) => {
  app.get('/health', async () => ({
    status: 'ok',
    service: 'aadhaar-vault',
    version: deps.version,
    timestamp: new Date().toISOString(),
  }));

  app.get('/health/live', async () => ({ status: 'alive' }));

  app.get('/health/ready', async (_req, reply) => {
    const ok = await deps.isReady();
    if (!ok) {
      reply.code(503);
      return {
        status: 'not_ready',
        checks: {
          postgres: 'unreachable',
          keyProvider: 'deferred-session-3',
        },
      };
    }
    return {
      status: 'ready',
      checks: {
        postgres: 'ok',
        keyProvider: 'deferred-session-3',
      },
    };
  });
};

export default healthRoutes;