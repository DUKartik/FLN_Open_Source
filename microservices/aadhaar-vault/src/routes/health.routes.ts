/**
 * Health routes.
 *
 * Architecture doc §6 mandates three probes with distinct semantics:
 *   - GET /health       — generic liveness payload, never fails.
 *   - GET /health/live  — Kubernetes-style liveness; returns 200 always.
 *   - GET /health/ready — Kubernetes-style readiness; reports dependency status.
 *
 * Session 1 only wires the routes. The actual dependency checks (Postgres
 * ping, key provider reachability) are added in Sessions 2 and 3.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';

export interface HealthDeps {
  version: string;
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

  app.get('/health/ready', async () => ({
    status: 'ready',
    checks: {
      postgres: 'deferred-session-2',
      keyProvider: 'deferred-session-3',
    },
  }));
};

export default healthRoutes;