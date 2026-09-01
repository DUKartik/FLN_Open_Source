/**
 * Vault module wiring.
 *
 * `buildVaultContext` is the single place that turns a `Db` +
 * `MongoClient` into the fully-wired `VaultContext` the route handlers
 * consume. It is invoked once at boot by `registerVaultRoutes` and
 * the result is stashed on `app.locals.vault` (or returned to the
 * caller) for the route layer to use.
 *
 * Why not export a `VaultModule` class and inject its instance via
 * `app.use((req, res, next) => res.locals.vault = ...)`: because
 * `app.locals` is typed as `any` and the production route layer is
 * plain Express handlers (not class-based controllers). A
 * `Record<string, VaultContext>` map keyed by a string tag is
 * closer to how the rest of the FLN backend wires state.
 *
 * If `db` is `null` (the test file-fallback path or a misconfigured
 * dev box) the builder returns `null` and the route layer is told
 * to refuse calls with 503. The in-process command wired onto
 * `aadhaarVault.ts` is skipped — that lets the existing 6 hardening
 * tests stub the function directly without standing up Mongo.
 */
import type { Db, MongoClient } from 'mongodb';

import { NodeCryptoService } from './infrastructure/crypto/node-crypto.service';
import { createKeyManager } from './infrastructure/key-providers';
import { InProcessEventPublisher } from './infrastructure/events/in-process-event-publisher';
import { MongoTransactionalVaultWriter } from './infrastructure/db/mongo-transactional-vault-writer';
import { ensureVaultIndexes } from './schema/indexes';
import { makeTokenizeAadhaar } from './application/commands/tokenize-aadhaar';
import { __setTokenizeAadhaarImpl } from '../../aadhaarVault';

export interface VaultContext {
  tokenize: ReturnType<typeof makeTokenizeAadhaar>;
  keyManagerInfo: { provider: string; currentVersion: string; algorithm: string };
}

export interface BuildVaultContextInput {
  db: Db | null;
  client: MongoClient | null;
  /** Optional logger for the event publisher. */
  logger?: { info: (obj: unknown, msg?: string) => void; warn: (obj: unknown, msg?: string) => void };
}

export interface BuildVaultContextResult {
  /** The wired context, or `null` if the build failed. */
  ctx: VaultContext | null;
  /** When `ctx` is `null`, a stable reason tag for logging / health
   *  probes. `undefined` when the build succeeded. */
  failureReason?: 'no-mongo' | 'key-manager-init-failed';
  /** The underlying error when `failureReason` is set. */
  failureError?: Error;
}

/**
 * Build the wired vault context. Idempotent — safe to call from
 * `registerVaultRoutes` at every boot, since the underlying repos
 * are stateless and the key manager holds only an immutable config.
 *
 * Side effects:
 *   - Calls `ensureVaultIndexes(db)` to create the collections +
 *     indexes (idempotent; safe to re-run).
 *   - Installs the in-process tokenize implementation on
 *     `aadhaarVault.ts` via `__setTokenizeAadhaarImpl` so the existing
 *     `tokenizeAadhaar()` callers (student registration, bulk import)
 *     transparently route through the module.
 */
export async function buildVaultContext(
  input: BuildVaultContextInput,
): Promise<BuildVaultContextResult> {
  if (!input.db || !input.client) {
    return { ctx: null, failureReason: 'no-mongo' };
  }

  // Ensure schema before anything reads/writes.
  await ensureVaultIndexes(input.db);

  // Build deps.
  let keyManager;
  try {
    keyManager = createKeyManager({ logger: input.logger });
  } catch (err) {
    return {
      ctx: null,
      failureReason: 'key-manager-init-failed',
      failureError: err instanceof Error ? err : new Error(String(err)),
    };
  }
  const crypto = new NodeCryptoService();
  const events = new InProcessEventPublisher({ logger: input.logger });
  const vaultWriter = new MongoTransactionalVaultWriter(input.db, input.client);

  const tokenize = makeTokenizeAadhaar({
    keyManager,
    crypto,
    vaultWriter,
    events,
  });

  const ctx: VaultContext = {
    tokenize,
    keyManagerInfo: keyManager.info(),
  };

  // Install the in-process implementation on the legacy shim. After
  // this returns, calls to `tokenizeAadhaar(rawAadhar, ctx)` from
  // student registration / bulk import go through the module, not
  // HTTP. The HTTP fallback (default impl) is no longer consulted.
  __setTokenizeAadhaarImpl(async (rawAadhar, aadhaarCtx) => {
    // Map the FLN shim's context shape to the command's caller context.
    const result = await tokenize({
      raw: rawAadhar,
      type: 'AADHAAR',
      context: {
        actorId: aadhaarCtx.email || 'fln-backend-service',
        actorRole: 'SERVICE',
        reason: `Aadhaar tokenization for student registration by ${aadhaarCtx.email || 'unknown user'}`,
        requestId: aadhaarCtx.requestId,
        sourceIp: aadhaarCtx.sourceIp,
        userAgent: aadhaarCtx.userAgent,
      },
    });
    return result;
  });

  return { ctx };
}
