// ==========================================
// VAULT MODULE — REGISTRATION ENTRY (Phase 1 stub)
// ==========================================
// Sole public surface of the in-process vault module.
//
// In Phase 1 this is a no-op: the function exists so the module can be
// wired into backend/src/index.ts behind a feature flag, the import chain
// is exercised by the build, and subsequent phases have a stable home for
// their route registrations.
//
// The full lifecycle (Phase 2 → Phase 7) progressively adds:
//   - Phase 2: tokenize (POST /v1/tokenize) + 3 Mongo repos
//   - Phase 3: detokenize (POST /v1/detokenize) + audit (GET /v1/audit)
//   - Phase 4: step-up request/approve + MFA enroll/verify
//   - Phase 5: console static mount at /console/
//   - Phase 6: graceful shutdown hook (no-op here, lives in backend/src/index.ts)
//   - Phase 7: drop the VAULT_MODULE_ENABLED flag entirely
import type { Express } from 'express';

export interface VaultModuleOptions {
  // Reserved for Phase 2+ — the wired deps (db, keyManager, crypto, etc.)
  // arrive here. Phase 1 has nothing to inject, so the param is empty.
}

export function registerVaultRoutes(app: Express, _opts: VaultModuleOptions = {}): void {
  // Phase 1: no routes registered. The module's existence is enough to
  // verify the import chain works. Health check at GET /health is added
  // in Phase 2 alongside the tokenize route.
  void app;
}
