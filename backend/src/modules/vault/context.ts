/**
 * Vault module wiring.
 *
 * `buildVaultContext` is the single place that turns a `Db` +
 * `MongoClient` into the fully-wired `VaultContext` the route handlers
 * consume. It is invoked once at boot by `registerVaultRoutes` and
 * the result is stashed on `app.vaultContext` (Express
 * `Application` augmentation) for the route layer to use.
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
 * to refuse calls with 503. The in-process commands wired onto
 * `aadhaarVault.ts` are skipped — that lets the existing hardening
 * tests stub the functions directly without standing up Mongo.
 */
import type { Db, MongoClient } from 'mongodb';

import { NodeCryptoService } from './infrastructure/crypto/node-crypto.service';
import { createKeyManager } from './infrastructure/key-providers';
import { InProcessEventPublisher } from './infrastructure/events/in-process-event-publisher';
import { MongoTransactionalVaultWriter } from './infrastructure/db/mongo-transactional-vault-writer';
import { MongoIdentityRepository } from './infrastructure/db/mongo-identity.repository';
import { MongoTokenRepository } from './infrastructure/db/mongo-token.repository';
import { MongoStepUpChallengeRepository } from './infrastructure/db/mongo-step-up-challenge.repository';
import { MongoMfaFactorRepository } from './infrastructure/db/mongo-mfa-factor.repository';
import { ensureVaultIndexes } from './schema/indexes';
import { makeTokenizeAadhaar } from './application/commands/tokenize-aadhaar';
import { makeDetokenizeAadhaar } from './application/commands/detokenize-aadhaar';
import { makeReadAuditHistory } from './application/commands/read-audit-history';
import { makeEnrollMfa } from './application/commands/enroll-mfa';
import { makeRequestDetokenization } from './application/commands/request-detokenization';
import { makeApproveStepUpChallenge } from './application/commands/approve-step-up-challenge';
import { OtpAuthTotpVerifier } from './infrastructure/mfa/totp-verifier';
import {
  __setTokenizeAadhaarImpl,
  __setDetokenizeAadhaarImpl,
  __setEnrollMfaImpl,
  __setRequestDetokenizationImpl,
  __setApproveStepUpChallengeImpl,
} from '../../aadhaarVault';

export interface VaultContext {
  tokenize: ReturnType<typeof makeTokenizeAadhaar>;
  detokenize: ReturnType<typeof makeDetokenizeAadhaar>;
  readAuditHistory: ReturnType<typeof makeReadAuditHistory>;
  enrollMfa: ReturnType<typeof makeEnrollMfa>;
  requestDetokenization: ReturnType<typeof makeRequestDetokenization>;
  approveStepUpChallenge: ReturnType<typeof makeApproveStepUpChallenge>;
  keyManagerInfo: { provider: string; currentVersion: string; algorithm: string };
}

export interface BuildVaultContextInput {
  db: Db | null;
  client: MongoClient | null;
  /** Optional logger for the event publisher + key manager. */
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
 *   - Installs the in-process tokenize + detokenize implementations
 *     on `aadhaarVault.ts` via `__setTokenizeAadhaarImpl` and
 *     `__setDetokenizeAadhaarImpl` so the existing call sites
 *     (student registration, admin reveal) transparently route
 *     through the module.
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

  // Repositories (all read-side; writes go through vaultWriter
  // for the tokenize path). Identity + token + challenge + mfa
  // are the four collections the detokenize + step-up paths walk.
  // The audit chain is the FLN `logbook` collection, written
  // by the commands themselves via `dbStore.addLog` /
  // `dbStore.addLogInSession` — there is no `audit` repo
  // anymore (issue #406).
  const identities = new MongoIdentityRepository(input.db);
  const tokens = new MongoTokenRepository(input.db);
  const challenges = new MongoStepUpChallengeRepository(input.db);
  const mfa = new MongoMfaFactorRepository(input.db);

  // RFC 6238 TOTP verifier. The application-layer
  // `TotpVerifier` port keeps `otpauth` confined to a single
  // adapter so the commands never import it directly.
  const totp = new OtpAuthTotpVerifier();

  // Commands. The detokenize command needs the read-side repos
  // directly; the tokenize command needs the transactional
  // writer (so identity + token + logbook audit land
  // atomically). The audit chain is the FLN `logbook`
  // collection, written by the commands themselves.
  const tokenize = makeTokenizeAadhaar({
    keyManager,
    crypto,
    vaultWriter,
    events,
  });
  const detokenize = makeDetokenizeAadhaar({
    keyManager,
    crypto,
    tokens,
    identities,
    events,
    challenges,
  });
  const readAuditHistory = makeReadAuditHistory({});
  const enrollMfa = makeEnrollMfa({
    keyManager,
    totp,
    mfa,
    events,
  });
  const requestDetokenization = makeRequestDetokenization({
    tokens,
    identities,
    mfa,
    challenges,
    events,
  });
  const approveStepUpChallenge = makeApproveStepUpChallenge({
    keyManager,
    totp,
    mfa,
    challenges,
    events,
  });

  const ctx: VaultContext = {
    tokenize,
    detokenize,
    readAuditHistory,
    enrollMfa,
    requestDetokenization,
    approveStepUpChallenge,
    keyManagerInfo: keyManager.info(),
  };

  // Install the in-process tokenize implementation on the legacy
  // shim. After this returns, calls to `tokenizeAadhaar(rawAadhar,
  // ctx)` from student registration / bulk import go through the
  // module, not HTTP. The HTTP fallback (default impl) is no
  // longer consulted.
  __setTokenizeAadhaarImpl(async (rawAadhar, aadhaarCtx) => {
    // Map the FLN shim's context shape to the command's caller
    // context. The shim has `email`; the command wants `actorId`.
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

  // Install the in-process detokenize implementation on the
  // legacy shim. After this returns, calls to
  // `detokenizeAadhaar({challengeId, context})` from the admin
  // reveal flow go through the module, not HTTP.
  __setDetokenizeAadhaarImpl(async (params) => {
    // The shim's AadhaarActorContext uses `email`; the command
    // wants `actorId`. The actorRole enum is identical across
    // both surfaces, so it's passed through unchanged.
    const result = await detokenize({
      challengeId: params.challengeId,
      context: {
        actorId: params.context.email || 'fln-backend-service',
        actorRole: params.context.actorRole,
        reason: `Detokenization for admin reveal — ${params.context.email || 'fln admin'}`,
        requestId: params.context.requestId,
        sourceIp: params.context.sourceIp,
        userAgent: params.context.userAgent,
      },
    });
    // The command's result shape is identical to the legacy
    // shim's `DetokenizeResult` — same field set and types — so
    // it's safe to pass through without reshaping.
    return result;
  });

  // Install the in-process enrollMfa implementation on the
  // legacy shim. After this returns, calls to
  // `enrollMfa({actor, label, context, ...})` from the admin
  // step-up flow go through the module, not HTTP.
  __setEnrollMfaImpl(async (params) => {
    const result = await enrollMfa({
      actor: params.actor,
      context: {
        actorId: params.actor,
        actorRole: params.context.actorRole,
        reason: `MFA enrollment for ${params.actor} — ${params.context.email || 'fln admin'}`,
        requestId: params.context.requestId,
        sourceIp: params.context.sourceIp,
        userAgent: params.context.userAgent,
      },
      ...(params.label !== undefined ? { label: params.label } : {}),
      ...(params.algorithm !== undefined ? { algorithm: params.algorithm } : {}),
      ...(params.digits !== undefined ? { digits: params.digits } : {}),
      ...(params.period !== undefined ? { period: params.period } : {}),
    });
    // The command's `factor` is a typed `MfaFactor`; the shim's
    // contract is `Record<string, unknown>` (it forwards the
    // response as-is). Convert via a deliberate object spread
    // so the call-site shape is stable.
    const factorObj: Record<string, unknown> = {
      factorId: result.factor.factorId,
      actor: result.factor.actor,
      factorType: result.factor.factorType,
      status: result.factor.status,
      label: result.factor.label,
      algorithm: result.factor.algorithm,
      digits: result.factor.digits,
      period: result.factor.period,
      lastUsedAt: result.factor.lastUsedAt,
      expiresAt: result.factor.expiresAt,
      createdAt: result.factor.createdAt,
    };
    return {
      factorId: result.factorId,
      otpauthUri: result.otpauthUri,
      factor: factorObj,
    };
  });

  // Install the in-process requestDetokenization implementation
  // on the legacy shim. After this returns, calls to
  // `requestDetokenization({tokenId, factorId, context})` from
  // the admin step-up flow go through the module, not HTTP.
  __setRequestDetokenizationImpl(async (params) => {
    const result = await requestDetokenization({
      tokenId: params.tokenId,
      factorId: params.factorId,
      context: {
        actorId: params.context.email || 'fln-backend-service',
        actorRole: params.context.actorRole,
        reason: `Step-up challenge for admin detokenization — ${params.context.email || 'fln admin'}`,
        requestId: params.context.requestId,
        sourceIp: params.context.sourceIp,
        userAgent: params.context.userAgent,
      },
    });
    // The command returns a `Date` for `expiresAt`; the shim
    // contract is an ISO string. Convert here.
    return {
      challengeId: result.challengeId,
      expiresAt: result.expiresAt.toISOString(),
      requiredFactor: result.requiredFactor as unknown as Record<string, unknown>,
    };
  });

  // Install the in-process approveStepUpChallenge implementation
  // on the legacy shim. After this returns, calls to
  // `approveStepUpChallenge({challengeId, code, context})` from
  // the admin step-up flow go through the module, not HTTP.
  __setApproveStepUpChallengeImpl(async (params) => {
    const result = await approveStepUpChallenge({
      challengeId: params.challengeId,
      code: params.code,
      context: {
        actorId: params.context.email || 'fln-backend-service',
        actorRole: params.context.actorRole,
        reason: `Step-up approval for admin detokenization — ${params.context.email || 'fln admin'}`,
        requestId: params.context.requestId,
        sourceIp: params.context.sourceIp,
        userAgent: params.context.userAgent,
      },
    });
    // The command returns a `Date` for `approvedAt`; the shim
    // contract is an ISO string.
    return {
      challengeId: result.challengeId,
      status: result.status,
      approvedAt: result.approvedAt.toISOString(),
      verifiedFactorId: result.verifiedFactorId,
    };
  });

  return { ctx };
}
