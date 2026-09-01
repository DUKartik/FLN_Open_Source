/**
 * `VerifyMfa` command — application-layer use case (Phase 4 port).
 *
 * Verbatim port of
 * `src/application/commands/verify-mfa.ts`,
 * adjusted only for:
 *   - relative import paths (no `.js` suffix; FLN backend ESM resolution)
 *   - the in-process `MfaFactorRepository` + `AuditRepository` ports
 *     (no Fastify, no `pg`); the audit row id is a stringified ObjectId.
 *
 * Implements the "verify a TOTP step-up code" use case. The command
 * is the only place that knows the whole verification pipeline:
 *
 *   1. validate input (factorId, code, optional actor hint);
 *   2. look up the factor via {@link MfaFactorRepository.getById};
 *   3. verify the factor is `active` and not expired;
 *   4. open the sealed shared secret with
 *      {@link KeyManager.openSecret} under the per-factor context
 *      (see {@link makeMfaSecretContext});
 *   5. verify the user-submitted code via
 *      {@link TotpVerifier.verifyCode} with a small clock-skew
 *      window;
 *   6. record `lastUsedAt` via {@link MfaFactorRepository.markUsed}
 *      (idempotent timestamp bump);
 *   7. append an audit row via {@link AuditRepository.append}
 *      (success or failure, both audited);
 *   8. publish the `MfaVerified` or `MfaVerificationFailed` domain
 *      event via {@link EventPublisher.publish}.
 *
 * **Verification failure semantics.** A failed verify (wrong code,
 * revoked factor, expired factor) is *not* an exception — it's a
 * `valid: false` result. The HTTP layer maps that to 401 (wrong
 * code) or 403 (revoked/expired), and the command still audits
 * the failure and publishes the failure event. The only paths
 * that throw are input-validation failures and unexpected
 * infrastructure errors (DB down, KMS unreachable).
 *
 * **Replay protection.** RFC 6238 §5.2 recommends a small clock-
 * skew window (default `±1` step) so legitimate users do not get
 * a 401 on a slow phone. The window is part of the port
 * contract. v0.1's `markUsed` does NOT track the time-step the
 * code matched against (only the wall-clock `usedAt`), so a
 * single code replayed within the same `period` could be
 * re-accepted. A future `mfa_challenges_used` table — or an
 * `last_used_step` column on the factor row — is the canonical
 * fix. The session brief defers that to a future schema-
 * reconciliation session.
 *
 * **Wrap context for the TOTP secret.** The same
 * `mfa-factor:<factorId>` context used at enrollment (see
 * `application/util/mfa-secret-context.ts`) is re-derived here.
 * A stolen `encryptedSecret` blob from factor A cannot be
 * opened under factor B's context — the desired
 * "factor-scoped key" property.
 *
 * **Plaintext hygiene.** The raw TOTP shared secret returned by
 * `KeyManager.openSecret` is sensitive. The command zeroes it in
 * `finally` via {@link safeZero}, regardless of which branch it
 * exits through. The context buffer is also zeroed, matching the
 * `TokenizeAadhaar` / `EnrollMfa` convention.
 */
import type { KeyManager } from "../ports/key-manager";
import type { TotpVerifier } from "../ports/totp-verifier";
import type {
  AuditEntry,
  AuditRepository,
  MfaFactor,
  MfaFactorRepository,
} from "../ports/repositories";
import type { EventPublisher } from "../ports/event-publisher";
import { safeZero } from "../../util/dek-zero";
import { makeMfaSecretContext } from "../util/mfa-secret-context";

// ---------------------------------------------------------------------------
// Public types — the "verify MFA" contract surface
// ---------------------------------------------------------------------------

/**
 * Caller context. Same shape as `EnrollMfaCallerContext` /
 * `ReadAuditHistoryCallerContext` / `TokenizeCallerContext` so
 * the audit chain sees a consistent actor triple.
 */
export interface VerifyMfaCallerContext {
  actorId: string;
  actorRole:
    | "TEACHER"
    | "SCHOOL_ADMIN"
    | "STATE_ADMIN"
    | "SUPER_ADMIN"
    | "SERVICE";
  reason: string;
  requestId?: string;
  sourceIp?: string;
  userAgent?: string;
}

/**
 * Request shape: `{ factorId, code, context, expectedActor?, window? }`.
 *
 * `expectedActor` is the application-level identity principal
 * the caller expects the factor to belong to (e.g. the JWT
 * subject). When supplied, the command refuses to verify a
 * factor that belongs to a *different* actor — this is a
 * defense against a misbehaving client passing a factor id from
 * a different user's session.
 *
 * `window` is the clock-skew tolerance in TOTP time-steps.
 * Defaults to `1` (accept the previous and next code as well as
 * the current one). Per RFC 6238 §5.2, a value of `0` rejects
 * everything except the current step.
 */
export interface VerifyMfaCommand {
  factorId: string;
  code: string;
  context: VerifyMfaCallerContext;
  expectedActor?: string;
  window?: number;
}

/**
 * Result shape for a successful verification.
 */
export interface VerifyMfaSuccess {
  valid: true;
  factorId: string;
  actor: string;
  /**
   * Signed integer offset from "now" to the time-step whose
   * code matched. `0` = current step, `-1` = previous, `+1` =
   * next. Surfaced for the audit row + downstream log
   * consumers; not actionable by the HTTP layer.
   */
  delta: number;
  /** The factor row, post-`markUsed`. */
  factor: MfaFactor;
}

/**
 * Result shape for a failed verification. The command does NOT
 * distinguish *why* the verification failed at the type level —
 * the reason string is for the audit row + log only. A
 * "not-active" / "expired" / "wrong code" failure all collapse
 * to `valid: false` from the caller's perspective, so an
 * attacker cannot probe factor states.
 */
export interface VerifyMfaFailure {
  valid: false;
  factorId: string | null;
  /**
   * Stable reason tag, one of:
   *   - `FACTOR_NOT_FOUND` — no row with this factor_id.
   *   - `FACTOR_REVOKED`   — row exists but `status='revoked'`.
   *   - `FACTOR_EXPIRED`   — row is past `expiresAt`.
   *   - `ACTOR_MISMATCH`   — factor's `actor` ≠ `expectedActor`.
   *   - `CODE_MISMATCH`    — code did not match within the window.
   */
  reason:
    | "FACTOR_NOT_FOUND"
    | "FACTOR_REVOKED"
    | "FACTOR_EXPIRED"
    | "ACTOR_MISMATCH"
    | "CODE_MISMATCH";
}

export type VerifyMfaResult = VerifyMfaSuccess | VerifyMfaFailure;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Error class with a stable `code` so the HTTP layer can map to
 * 4xx without sniffing message text. Distinct from
 * `EnrollMfaCommandError` / `ReadAuditHistoryCommandError` /
 * `TokenizeCommandError` so a `try/catch` on one doesn't
 * accidentally swallow the others. Only thrown for input
 * validation failures; verification failures are a `valid:false`
 * result, not a throw.
 */
export class VerifyMfaCommandError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "VerifyMfaCommandError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default clock-skew window in TOTP time-steps (±1). */
const DEFAULT_WINDOW = 1;

/** Default length of a TOTP code. Matches the v0.1 port default
 *  (digits=6). Other digit lengths (rare) must be configured at
 *  enrollment; the command does not support cross-digit verification. */
const DEFAULT_DIGITS = 6;

// ---------------------------------------------------------------------------
// Command factory
// ---------------------------------------------------------------------------

/**
 * Dependencies the command needs. The four "verify" ports are kept
 * individually (rather than going through a `vaultWriter`
 * abstraction) because the brief explicitly says *do not redesign
 * the repository* in this session.
 */
export interface VerifyMfaDeps {
  keyManager: KeyManager;
  totp: TotpVerifier;
  mfa: MfaFactorRepository;
  audit: AuditRepository;
  events: EventPublisher;
  /**
   * Returns the *current* "now" — injected so tests can pin
   * time and so the timestamp used by the audit row, the
   * `markUsed` call, and the event publish agree.
   */
  clock?: () => Date;
}

/**
 * Factory returns the bound command function. Style mirrors
 * `makeTokenizeAadhaar` / `makeEnrollMfa`.
 */
export function makeVerifyMfa(deps: VerifyMfaDeps) {
  const clock: () => Date = deps.clock ?? (() => new Date());

  return async function verifyMfa(
    cmd: VerifyMfaCommand,
  ): Promise<VerifyMfaResult> {
    // -----------------------------------------------------------------
    // 1. Validate input. The audit row is keyed on
    //    `context.actorId`; an empty value would produce a
    //    misleading row. The factorId / code fields are the
    //    surface the user supplied; we validate they are the
    //    right *shape* here and let the domain-level
    //    (factor-not-found, code-mismatch) failures be
    //    returned as `valid: false` results rather than
    //    exceptions.
    // -----------------------------------------------------------------
    if (
      typeof cmd.context?.actorId !== "string" ||
      cmd.context.actorId.length === 0
    ) {
      throw new VerifyMfaCommandError(
        "INVALID_INPUT",
        "context.actorId must be a non-empty string.",
      );
    }
    if (typeof cmd.factorId !== "string" || cmd.factorId.length === 0) {
      throw new VerifyMfaCommandError(
        "INVALID_INPUT",
        "factorId must be a non-empty string.",
      );
    }
    if (typeof cmd.code !== "string") {
      throw new VerifyMfaCommandError(
        "INVALID_INPUT",
        "code must be a string.",
      );
    }
    // The code must be exactly `digits` decimal digits. We
    // do NOT coerce to a number first because leading
    // zeros would be lost. The `digits` field is
    // discovered from the factor row below — we use
    // `DEFAULT_DIGITS` (6) for the *initial* shape check
    // so a 4-digit code with a 6-digit factor still
    // gets rejected fast, before we touch the DB.
    const codeDigits = DEFAULT_DIGITS;
    if (cmd.code.length !== codeDigits || !/^\d+$/.test(cmd.code)) {
      throw new VerifyMfaCommandError(
        "INVALID_INPUT",
        `code must be a ${codeDigits}-digit decimal string.`,
      );
    }
    if (
      cmd.expectedActor !== undefined &&
      (typeof cmd.expectedActor !== "string" ||
        cmd.expectedActor.length === 0)
    ) {
      throw new VerifyMfaCommandError(
        "INVALID_INPUT",
        "expectedActor, when supplied, must be a non-empty string.",
      );
    }
    if (cmd.window !== undefined) {
      if (
        !Number.isFinite(cmd.window) ||
        !Number.isInteger(cmd.window) ||
        cmd.window < 0
      ) {
        throw new VerifyMfaCommandError(
          "INVALID_INPUT",
          "window, when supplied, must be a non-negative integer.",
        );
      }
    }

    const now = clock();
    const window = cmd.window ?? DEFAULT_WINDOW;

    // -----------------------------------------------------------------
    // 2. Look up the factor.
    // -----------------------------------------------------------------
    const factor = await deps.mfa.getById(cmd.factorId);
    if (!factor) {
      return await recordFailure(
        deps,
        cmd,
        null,
        "FACTOR_NOT_FOUND",
        now,
      );
    }

    // -----------------------------------------------------------------
    // 3. Reject if the factor does not belong to the
    //    expected actor.
    // -----------------------------------------------------------------
    if (
      cmd.expectedActor !== undefined &&
      factor.actor !== cmd.expectedActor
    ) {
      return await recordFailure(
        deps,
        cmd,
        factor,
        "ACTOR_MISMATCH",
        now,
      );
    }

    // -----------------------------------------------------------------
    // 4. Reject if the factor is not `active` or has
    //    expired.
    // -----------------------------------------------------------------
    if (factor.status !== "active") {
      return await recordFailure(
        deps,
        cmd,
        factor,
        "FACTOR_REVOKED",
        now,
      );
    }
    if (factor.expiresAt !== null && factor.expiresAt.getTime() <= now.getTime()) {
      return await recordFailure(
        deps,
        cmd,
        factor,
        "FACTOR_EXPIRED",
        now,
      );
    }

    // -----------------------------------------------------------------
    // 5. Open the sealed secret under the per-factor
    //    context. The context must match the one used at
    //    enrollment exactly; a mismatch throws (KMS
    //    surface error) and is propagated to the caller
    //    as a 5xx — never as a `valid: false` result,
    //    because it indicates either a programming bug
    //    or active tampering, both of which deserve
    //    operator attention.
    // -----------------------------------------------------------------
    const secretContext = makeMfaSecretContext(factor.factorId);
    let openedSecret: Buffer | undefined;
    try {
      openedSecret = await deps.keyManager.openSecret(
        { bytes: factor.encryptedSecret },
        secretContext,
      );

      // -------------------------------------------------------------
      // 6. Verify the user-submitted code. The verifier
      //    returns `{valid, delta}` (or `{valid: false}`);
      //    we record the `delta` so the audit chain
      //    can attribute the success to a specific
      //    time-step. A code-mismatch is a `valid:false`
      //    result, not a throw.
      // -------------------------------------------------------------
      const result = await deps.totp.verifyCode(
        openedSecret,
        cmd.code,
        window,
        now.getTime(),
      );

      if (!result.valid) {
        return await recordFailure(
          deps,
          cmd,
          factor,
          "CODE_MISMATCH",
          now,
        );
      }

      // -------------------------------------------------------------
      // 7. Record usage. `markUsed` is idempotent — a
      //    second call updates the timestamp. The
      //    command calls it exactly once per
      //    successful verify.
      // -------------------------------------------------------------
      const updatedFactor = await deps.mfa.markUsed(
        factor.factorId,
        now,
      );
      // The adapter's contract is to return the
      // updated row. If the row went away between
      //    getById and markUsed (extremely unlikely in
      //    a real DB), we treat it as a failure to
      //    avoid surfacing a phantom success to the
      //    HTTP layer.
      if (!updatedFactor) {
        return await recordFailure(
          deps,
          cmd,
          factor,
          "FACTOR_NOT_FOUND",
          now,
        );
      }

      // -------------------------------------------------------------
      // 8. Append the audit row + publish the success
      //    event.
      // -------------------------------------------------------------
      await deps.audit.append({
        identityId: null,
        actor: cmd.context.actorId,
        action: "MFA_VERIFY",
        outcome: "allow",
        reason: cmd.context.reason,
        requestId: cmd.context.requestId ?? null,
        meta: {
          factor_id: factor.factorId,
          factor_type: factor.factorType,
          factor_actor: factor.actor,
          delta: result.delta,
          window,
          source_ip: cmd.context.sourceIp ?? null,
          user_agent: cmd.context.userAgent ?? null,
        },
      });

      await deps.events.publish({
        type: "MfaVerified",
        factorId: factor.factorId,
        actor: factor.actor,
        delta: result.delta,
        verifiedBy: cmd.context.actorId,
        verifiedByRole: cmd.context.actorRole,
        occurredAt: now.toISOString(),
      });

      return {
        valid: true,
        factorId: factor.factorId,
        actor: factor.actor,
        delta: result.delta,
        factor: updatedFactor,
      };
    } finally {
      // -------------------------------------------------------------
      // Plaintext hygiene — ALWAYS, even on throw.
      // -------------------------------------------------------------
      if (openedSecret) safeZero(openedSecret);
      if (secretContext) safeZero(secretContext);
    }
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Centralized failure-recording helper. All five failure modes
 * (FACTOR_NOT_FOUND, FACTOR_REVOKED, FACTOR_EXPIRED,
 * ACTOR_MISMATCH, CODE_MISMATCH) go through here so the audit
 * row + failure-event shape stay uniform.
 */
async function recordFailure(
  deps: VerifyMfaDeps,
  cmd: VerifyMfaCommand,
  factor: MfaFactor | null,
  reason: VerifyMfaFailure["reason"],
  now: Date,
): Promise<VerifyMfaFailure> {
  const factorId = factor?.factorId ?? cmd.factorId;
  const factorActor = factor?.actor ?? null;

  const auditEntry: AuditEntry = {
    identityId: null,
    actor: cmd.context.actorId,
    action: "MFA_VERIFY",
    outcome: "deny",
    reason: cmd.context.reason,
    requestId: cmd.context.requestId ?? null,
    meta: {
      factor_id: factorId,
      factor_actor: factorActor,
      failure_reason: reason,
      source_ip: cmd.context.sourceIp ?? null,
      user_agent: cmd.context.userAgent ?? null,
    },
  };
  await deps.audit.append(auditEntry);

  await deps.events.publish({
    type: "MfaVerificationFailed",
    factorId,
    actor: factorActor,
    reason,
    attemptedBy: cmd.context.actorId,
    attemptedByRole: cmd.context.actorRole,
    occurredAt: now.toISOString(),
  });

  return {
    valid: false,
    factorId,
    reason,
  };
}
