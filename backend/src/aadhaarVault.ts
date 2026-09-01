// Aadhaar Vault client — shared by the backend's route modules.
//
// Moves raw Aadhaar out of the primary request path: on student registration
// the backend calls the vault's POST /v1/tokenize and persists only a mask,
// an opaque token, and a deterministic identity id. This module is the single
// integration point for the Aadhaar Vault microservice
// (microservices/aadhaar-vault/), so route modules can call it without
// creating a circular dependency on index.ts.
//
// Phase 2 hardening (this revision):
//   - Request timeout via AbortSignal.timeout(...) — a hung vault can no
//     longer hang registration (or serially stall every row of a bulk import).
//     Tunable via AADHAAR_VAULT_TIMEOUT_MS (default 10000ms).
//   - Typed VaultError carrying { code, status } so internal callers can
//     distinguish configuration problems, network failures, timeouts,
//     malformed responses and the vault's own stable error codes.
//   - Clear fail-closed configuration error when the service JWT secret is
//     missing. Registration still fails; nothing is ever written.
//
// Step-up workflow (Session 7E — full end-to-end admin detokenization):
//   The vault's step-up flow has four additional endpoints the backend
//   needs to drive from an admin request:
//     - POST /v1/mfa/enroll                               — `enrollMfa`
//     - POST /v1/detokenize/request                       — `requestDetokenization`
//     - POST /v1/detokenize/step-up/:challengeId/approve  — `approveStepUpChallenge`
//     - POST /v1/detokenize                               — `detokenizeAadhaar`
//   These reuse the same service-JWT / timeout / error mapping infra as
//   `tokenizeAadhaar`. They MUST NOT be invoked from the browser — the
//   Vault never issues user-scoped JWTs, only service-scoped HS256 tokens
//   minted here.
//
// Logging hygiene: no message produced here ever contains the raw Aadhaar,
// the minted service JWT, the TOTP code, the otpauth URI (which encodes the
// shared secret), or any secret — only stable error codes, HTTP statuses
// and transport-level descriptions.
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const AADHAAR_VAULT_URL = (process.env.AADHAAR_VAULT_URL || 'http://127.0.0.1:4101').replace(/\/+$/, '');
const AADHAAR_VAULT_SERVICE_JWT_SECRET = process.env.AADHAAR_VAULT_SERVICE_JWT_SECRET;
const AADHAAR_VAULT_SERVICE_JWT_ISSUER = process.env.AADHAAR_VAULT_SERVICE_JWT_ISSUER;
const AADHAAR_VAULT_SERVICE_JWT_AUDIENCE = process.env.AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;
const AADHAAR_VAULT_SERVICE_JWT_SUBJECT = process.env.AADHAAR_VAULT_SERVICE_JWT_SUBJECT || 'fln-backend-service';

// Conservative service-to-service timeout: the vault is a small local
// Postgres-backed service and tokenization is one transaction.
const DEFAULT_TIMEOUT_MS = 10000;

export type AadhaarVaultTokenizeResult = {
  token: string;
  last4: string;
  tokenType: string;
  identityId: string;
  auditId: string;
  keyVersion: string | number;
};

/** XXXX-XXXX-<last4> — the only Aadhaar representation allowed at rest. */
export function formatAadhaarMask(rawAadhar: string): string {
  const digits = rawAadhar.replace(/[^0-9]/g, '');
  return 'XXXX-XXXX-' + digits.slice(-4);
}

// ---------------------------------------------------------------------------
// Typed error surface (Phase 2 hardening)
// ---------------------------------------------------------------------------

/** Stable failure codes raised by this client. */
export type VaultErrorCode =
  // Local configuration problem — fail-closed before any network call.
  | 'NOT_CONFIGURED'
  // Connection/DNS/socket failure — vault could not be reached at all.
  | 'UNREACHABLE'
  // Request aborted because the vault did not answer in time.
  | 'TIMEOUT'
  // Vault answered successfully but the body was unusable / contract-breaking.
  | 'MALFORMED_RESPONSE'
  // The vault's own stable error codes (tokenize / detokenize / mfa / step-up).
  | 'INVALID_INPUT'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'PEPPER_MISMATCH'
  | 'RATE_LIMIT'
  | 'INTERNAL'
  // Step-up lifecycle codes (mirrored 1:1 from the vault routes).
  | 'TOKEN_NOT_FOUND'
  | 'IDENTITY_NOT_FOUND'
  | 'FACTOR_NOT_FOUND'
  | 'FACTOR_NOT_ACTIVE'
  | 'FACTOR_EXPIRED'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_NOT_PENDING'
  | 'CHALLENGE_NOT_APPROVED'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_CONSUMED'
  | 'CHALLENGE_OPERATION_MISMATCH'
  | 'ACTOR_MISMATCH'
  | 'CODE_MISMATCH'
  | 'CODE_REPLAYED'
  | 'UNWRAP_FAILED'
  | 'DECRYPTION_FAILED'
  | 'INVALID_PAYLOAD'
  // Any other non-OK status whose body does not carry a known code.
  | 'UNKNOWN_VAULT_ERROR';

/**
 * Typed failure thrown by every method on this module.
 *
 * `status` mirrors the closest HTTP status so internal handlers can reason
 * about retryability (4xx vs 5xx vs transport) WITHOUT parsing messages.
 * Messages are safe to log: they never contain raw Aadhaar, bearer tokens,
 * TOTP secrets, or vault secrets — only stable codes and transport descriptions.
 */
export class VaultError extends Error {
  readonly code: VaultErrorCode;
  readonly status: number;

  constructor(code: VaultErrorCode, status: number, message: string) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Service JWT — used by every method below. The vault routes partition
// authorization by the `scope` claim (see each route file in the vault repo):
//   - vault:tokenize        — POST /v1/tokenize
//   - vault:mfa:enroll      — POST /v1/mfa/enroll
//   - vault:detokenize      — POST /v1/detokenize/request
//                             POST /v1/detokenize/step-up/:challengeId/approve
//                             POST /v1/detokenize
// We mint a fresh token per request to keep the token's lifetime narrow and
// prevent replay across method boundaries.
// ---------------------------------------------------------------------------

function buildVaultServiceJwt(scope: 'vault:tokenize' | 'vault:mfa:enroll' | 'vault:detokenize'): string {
  if (!AADHAAR_VAULT_SERVICE_JWT_SECRET) {
    // Fail closed BEFORE any network call, with an actionable message that
    // names the exact variables an operator must set (values never logged).
    throw new VaultError(
      'NOT_CONFIGURED',
      500,
      'AADHAAR_VAULT_SERVICE_JWT_SECRET is not configured. Set AADHAAR_VAULT_URL and '
        + 'AADHAAR_VAULT_SERVICE_JWT_SECRET (plus optionally AADHAAR_VAULT_SERVICE_JWT_ISSUER / '
        + '_AUDIENCE / _SUBJECT) to match the vault deployment. The requested Vault operation cannot proceed '
        + 'safely until this is fixed.',
    );
  }

  const signingOptions: jwt.SignOptions = {
    algorithm: 'HS256',
    expiresIn: '5m',
  };
  if (AADHAAR_VAULT_SERVICE_JWT_ISSUER) signingOptions.issuer = AADHAAR_VAULT_SERVICE_JWT_ISSUER;
  if (AADHAAR_VAULT_SERVICE_JWT_AUDIENCE) signingOptions.audience = AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;

  return jwt.sign(
    {
      sub: AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
      scope,
    },
    AADHAAR_VAULT_SERVICE_JWT_SECRET,
    signingOptions,
  );
}

export type AadhaarTokenizeContext = {
  email?: string;
  sourceIp?: string;
  userAgent?: string;
  requestId?: string;
};

/** Caller context for the step-up + MFA endpoints. Distinct from
 *  `AadhaarTokenizeContext` because the vault requires an `actorRole`
 *  drawn from a fixed enum (see vault route schemas).
 */
export type AadhaarActorContext = AadhaarTokenizeContext & {
  /** Vault-side role. Maps FLN role → Vault role. Required. */
  actorRole: 'TEACHER' | 'SCHOOL_ADMIN' | 'STATE_ADMIN' | 'SUPER_ADMIN' | 'SERVICE';
};

/** Resolved per call so ops can tune it via env without touching code. */
function resolveTimeoutMs(): number {
  const parsed = Number(process.env.AADHAAR_VAULT_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TIMEOUT_MS;
}

/**
 * Internal: a single fetch wrapper that all methods share. Maps transport
 * errors to VaultError with stable codes, parses JSON bodies (best-effort),
 * and lets the caller decide success criteria.
 */
async function callVault(
  path: string,
  scope: 'vault:tokenize' | 'vault:mfa:enroll' | 'vault:detokenize',
  body: Record<string, unknown>,
  timeoutMs: number,
): Promise<{ status: number; data: any }> {
  const serviceJwt = buildVaultServiceJwt(scope);

  let response: Response;
  try {
    response = await fetch(`${AADHAAR_VAULT_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${serviceJwt}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err: any) {
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError' || err?.code === 'ABORT_ERR') {
      throw new VaultError('TIMEOUT', 504, `Aadhaar Vault did not respond within ${timeoutMs}ms.`);
    }
    throw new VaultError(
      'UNREACHABLE',
      503,
      `Could not reach the Aadhaar Vault at ${AADHAAR_VAULT_URL}: ${err?.message || 'network failure'}.`,
    );
  }

  // Body parse is best-effort: error responses are JSON today, but a proxy
  // or 5xx page may not be. Body contents are never echoed on parse failure.
  const data: any = await response.json().catch(() => null);
  return { status: response.status, data };
}

/** Maps a vault `error` field (string) to a known VaultErrorCode. The set
 *  below covers every code listed in the vault route ERROR_STATUS tables.
 */
const KNOWN_VAULT_CODES: readonly VaultErrorCode[] = [
  'INVALID_INPUT', 'UNAUTHORIZED', 'FORBIDDEN', 'PEPPER_MISMATCH', 'RATE_LIMIT', 'INTERNAL',
  'TOKEN_NOT_FOUND', 'IDENTITY_NOT_FOUND',
  'FACTOR_NOT_FOUND', 'FACTOR_NOT_ACTIVE', 'FACTOR_EXPIRED',
  'CHALLENGE_NOT_FOUND', 'CHALLENGE_NOT_PENDING', 'CHALLENGE_NOT_APPROVED',
  'CHALLENGE_EXPIRED', 'CHALLENGE_CONSUMED', 'CHALLENGE_OPERATION_MISMATCH',
  'ACTOR_MISMATCH', 'CODE_MISMATCH', 'CODE_REPLAYED',
  'UNWRAP_FAILED', 'DECRYPTION_FAILED', 'INVALID_PAYLOAD',
];

function mapVaultErrorResponse(status: number, data: any): VaultError {
  const vaultCode: string = typeof data?.error === 'string' ? data.error : '';
  const code: VaultErrorCode = KNOWN_VAULT_CODES.find(c => c === vaultCode) ?? 'UNKNOWN_VAULT_ERROR';
  // The vault returns stable, generic messages (it never echoes input),
  // so surfacing data.message internally is safe; fall back to status alone.
  const message: string =
    typeof data?.message === 'string' && data.message.length > 0
      ? data.message
      : `Aadhaar Vault returned HTTP ${status}.`;
  return new VaultError(code, status, message);
}

// ===========================================================================
// POST /v1/tokenize
// ===========================================================================

/**
 * Tokenize a raw 12-digit Aadhaar.
 *
 * The implementation is swappable so the in-process vault module
 * (backend/src/modules/vault/) can install its own command-bound
 * function at boot, and so the integration tests can inject a
 * deterministic stub without standing up a fake HTTP server. The
 * default implementation is the legacy HTTP path; the vault module
 * overrides it via {@link __setTokenizeAadhaarImpl} when the
 * `VAULT_MODULE_ENABLED` flag is on.
 *
 * Throws {@link VaultError} on ANY failure — callers must fail the
 * registration; there is no plaintext fallback path by design.
 */
export type TokenizeAadhaarFn = (
  rawAadhar: string,
  context: AadhaarTokenizeContext,
) => Promise<AadhaarVaultTokenizeResult>;

let tokenizeAadhaarImpl: TokenizeAadhaarFn = async (rawAadhar, context) => {
  // Legacy HTTP path — the default. Kept working until the vault
  // module is the only caller. The vault module installs a new impl
  // at boot (see modules/vault/index.ts) and the HTTP env-vars are
  // no longer consulted.
  const timeoutMs = resolveTimeoutMs();
  const { status, data } = await callVault('/v1/tokenize', 'vault:tokenize', {
    raw: rawAadhar,
    type: 'AADHAAR',
    context: {
      actorId: AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
      actorRole: 'SERVICE',
      reason: `Aadhaar tokenization for student registration by ${context.email || 'unknown user'}`,
      requestId: context.requestId || `fln-${randomUUID()}`,
      sourceIp: context.sourceIp,
      userAgent: context.userAgent,
    },
  }, timeoutMs);

  if (!status.toString().startsWith('2')) {
    throw mapVaultErrorResponse(status, data);
  }

  // Success-contract check (POST /v1/tokenize → 201 with these fields).
  if (
    !data ||
    typeof data.token !== 'string' || data.token.length === 0 ||
    typeof data.identityId !== 'string' || data.identityId.length === 0
  ) {
    throw new VaultError(
      'MALFORMED_RESPONSE',
      502,
      'Aadhaar Vault returned a success status without the required token/identityId fields.',
    );
  }

  return data as AadhaarVaultTokenizeResult;
};

/**
 * Install a replacement implementation. Called by the in-process vault
 * module at boot, and by integration tests via `__setTokenizeAadhaarForTest`
 * (which is the same function but exported under a test-only name so the
 * production code never has a public setter).
 */
export function __setTokenizeAadhaarImpl(fn: TokenizeAadhaarFn | null): void {
  if (fn === null) {
    // Reset to the default HTTP path. Useful for test teardown.
    tokenizeAadhaarImpl = tokenizeAadhaarImplDefault;
    return;
  }
  tokenizeAadhaarImpl = fn;
}

/** Internal: the default HTTP-backed implementation. Stored as a const
 *  reference so {@link __setTokenizeAadhaarImpl} can reset to it. */
const tokenizeAadhaarImplDefault = tokenizeAadhaarImpl;

export async function tokenizeAadhaar(
  rawAadhar: string,
  context: AadhaarTokenizeContext = {},
): Promise<AadhaarVaultTokenizeResult> {
  return tokenizeAadhaarImpl(rawAadhar, context);
}

// ===========================================================================
// POST /v1/mfa/enroll
// ===========================================================================

export type EnrollMfaParams = {
  /** The principal whose TOTP factor is being enrolled. FLN maps the
   *  admin's email here so a single SUPERADMIN/ADMIN has their own factor. */
  actor: string;
  label?: string;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
  context: AadhaarActorContext;
};

export type EnrollMfaResult = {
  factorId: string;
  otpauthUri: string;
  factor: Record<string, unknown>;
};

/**
 * Enroll a TOTP MFA factor for a given actor (admin). Returns the
 * `otpauth://` URI for the QR code and the factor envelope.
 *
 * The implementation is swappable so the in-process vault module
 * (`backend/src/modules/vault/`) can install its own command-bound
 * function at boot, and so integration tests can inject a
 * deterministic stub without standing up the full Mongo replica
 * set. The default implementation is the legacy HTTP path; the
 * vault module overrides it via {@link __setEnrollMfaImpl} when the
 * `VAULT_MODULE_ENABLED` flag is on.
 *
 * The returned `otpauthUri` embeds the TOTP secret — the frontend MUST
 * treat it as a secret (only render the QR / copy-to-clipboard inside the
 * admin's session, never persist it on the FLN side, never log it).
 *
 * Throws {@link VaultError} on any failure.
 */
export type EnrollMfaFn = (params: EnrollMfaParams) => Promise<EnrollMfaResult>;

let enrollMfaImpl: EnrollMfaFn = async (params) => {
  // Legacy HTTP path — the default. Kept working until the vault
  // module is the only caller. The vault module installs a new impl
  // at boot (see modules/vault/index.ts) and the HTTP env-vars are
  // no longer consulted.
  const timeoutMs = resolveTimeoutMs();
  const body: Record<string, unknown> = {
    actor: params.actor,
    context: {
      actorId: params.actor,
      actorRole: params.context.actorRole,
      reason: `MFA enrollment for ${params.actor} — ${params.context.email || 'fln admin'}`,
      requestId: params.context.requestId || `fln-${randomUUID()}`,
      sourceIp: params.context.sourceIp,
      userAgent: params.context.userAgent,
    },
  };
  if (params.label !== undefined) body.label = params.label;
  if (params.algorithm !== undefined) body.algorithm = params.algorithm;
  if (params.digits !== undefined) body.digits = params.digits;
  if (params.period !== undefined) body.period = params.period;

  const { status, data } = await callVault('/v1/mfa/enroll', 'vault:mfa:enroll', body, timeoutMs);

  if (!status.toString().startsWith('2')) {
    throw mapVaultErrorResponse(status, data);
  }

  if (
    !data ||
    typeof data.factorId !== 'string' || data.factorId.length === 0 ||
    typeof data.otpauthUri !== 'string' || data.otpauthUri.length === 0
  ) {
    throw new VaultError(
      'MALFORMED_RESPONSE',
      502,
      'Aadhaar Vault returned a success status without the required MFA factorId/otpauthUri fields.',
    );
  }

  return {
    factorId: data.factorId,
    otpauthUri: data.otpauthUri,
    factor: data.factor ?? {},
  };
};

/**
 * Install a replacement implementation. Called by the in-process
 * vault module at boot, and by integration tests via the test-
 * only name. Pass `null` to reset to the default HTTP path.
 */
export function __setEnrollMfaImpl(fn: EnrollMfaFn | null): void {
  if (fn === null) {
    enrollMfaImpl = enrollMfaImplDefault;
    return;
  }
  enrollMfaImpl = fn;
}

/** Internal: the default HTTP-backed implementation. Stored as a
 *  const reference so {@link __setEnrollMfaImpl} can reset to it. */
const enrollMfaImplDefault = enrollMfaImpl;

export async function enrollMfa(params: EnrollMfaParams): Promise<EnrollMfaResult> {
  return enrollMfaImpl(params);
}

// ===========================================================================
// POST /v1/detokenize/request
// ===========================================================================

export type RequestDetokenizationParams = {
  /** Resolved by the FLN backend from the authorized student record. */
  tokenId: string;
  /** The admin's factor id (returned by `enrollMfa`). */
  factorId: string;
  context: AadhaarActorContext;
};

export type RequestDetokenizationResult = {
  challengeId: string;
  expiresAt: string;
  requiredFactor: Record<string, unknown>;
};

/**
 * Mint a step-up challenge bound to a specific token and admin MFA factor.
 * Returns the challenge id the admin must approve with a TOTP code.
 *
 * The implementation is swappable so the in-process vault module
 * (`backend/src/modules/vault/`) can install its own command-bound
 * function at boot, and so integration tests can inject a
 * deterministic stub. The default implementation is the legacy
 * HTTP path; the vault module overrides it via
 * {@link __setRequestDetokenizationImpl} when the
 * `VAULT_MODULE_ENABLED` flag is on.
 *
 * Throws {@link VaultError} on any failure.
 */
export type RequestDetokenizationFn = (
  params: RequestDetokenizationParams,
) => Promise<RequestDetokenizationResult>;

let requestDetokenizationImpl: RequestDetokenizationFn = async (params) => {
  // Legacy HTTP path — the default. Kept working until the vault
  // module is the only caller.
  const timeoutMs = resolveTimeoutMs();
  const { status, data } = await callVault('/v1/detokenize/request', 'vault:detokenize', {
    tokenId: params.tokenId,
    factorId: params.factorId,
    context: {
      actorId: params.context.email || AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
      actorRole: params.context.actorRole,
      reason: `Step-up challenge for admin detokenization — ${params.context.email || 'fln admin'}`,
      requestId: params.context.requestId || `fln-${randomUUID()}`,
      sourceIp: params.context.sourceIp,
      userAgent: params.context.userAgent,
    },
  }, timeoutMs);

  if (!status.toString().startsWith('2')) {
    throw mapVaultErrorResponse(status, data);
  }

  if (
    !data ||
    typeof data.challengeId !== 'string' || data.challengeId.length === 0 ||
    typeof data.expiresAt !== 'string' && !(data.expiresAt instanceof Date)
  ) {
    throw new VaultError(
      'MALFORMED_RESPONSE',
      502,
      'Aadhaar Vault returned a success status without the required challengeId/expiresAt fields.',
    );
  }

  return {
    challengeId: data.challengeId,
    expiresAt: data.expiresAt instanceof Date ? data.expiresAt.toISOString() : data.expiresAt,
    requiredFactor: data.requiredFactor ?? {},
  };
};

/**
 * Install a replacement implementation. Pass `null` to reset to
 * the default HTTP path.
 */
export function __setRequestDetokenizationImpl(fn: RequestDetokenizationFn | null): void {
  if (fn === null) {
    requestDetokenizationImpl = requestDetokenizationImplDefault;
    return;
  }
  requestDetokenizationImpl = fn;
}

/** Internal: the default HTTP-backed implementation. Stored as a
 *  const reference so {@link __setRequestDetokenizationImpl} can
 *  reset to it. */
const requestDetokenizationImplDefault = requestDetokenizationImpl;

export async function requestDetokenization(
  params: RequestDetokenizationParams,
): Promise<RequestDetokenizationResult> {
  return requestDetokenizationImpl(params);
}

// ===========================================================================
// POST /v1/detokenize/step-up/:challengeId/approve
// ===========================================================================

export type ApproveStepUpParams = {
  challengeId: string;
  /** 6-digit TOTP code from the admin's authenticator app. NEVER logged. */
  code: string;
  context: AadhaarActorContext;
};

export type ApproveStepUpResult = {
  challengeId: string;
  status: 'approved';
  approvedAt: string;
  verifiedFactorId: string;
};

/**
 * Approve a step-up challenge by submitting the admin's TOTP code.
 *
 * The implementation is swappable so the in-process vault module
 * (`backend/src/modules/vault/`) can install its own command-bound
 * function at boot. The default implementation is the legacy HTTP
 * path; the vault module overrides it via
 * {@link __setApproveStepUpChallengeImpl} when the
 * `VAULT_MODULE_ENABLED` flag is on.
 *
 * Throws {@link VaultError} on any failure — including CODE_MISMATCH
 * (mapped to 403) and CHALLENGE_EXPIRED (mapped to 410).
 */
export type ApproveStepUpChallengeFn = (
  params: ApproveStepUpParams,
) => Promise<ApproveStepUpResult>;

let approveStepUpChallengeImpl: ApproveStepUpChallengeFn = async (params) => {
  // Legacy HTTP path — the default. Kept working until the vault
  // module is the only caller.
  const timeoutMs = resolveTimeoutMs();
  const { status, data } = await callVault(
    `/v1/detokenize/step-up/${encodeURIComponent(params.challengeId)}/approve`,
    'vault:detokenize',
    {
      code: params.code,
      context: {
        actorId: params.context.email || AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
        actorRole: params.context.actorRole,
        reason: `Step-up approval for admin detokenization — ${params.context.email || 'fln admin'}`,
        requestId: params.context.requestId || `fln-${randomUUID()}`,
        sourceIp: params.context.sourceIp,
        userAgent: params.context.userAgent,
      },
    },
    timeoutMs,
  );

  if (!status.toString().startsWith('2')) {
    throw mapVaultErrorResponse(status, data);
  }

  if (
    !data ||
    typeof data.challengeId !== 'string' || data.challengeId.length === 0 ||
    data.status !== 'approved'
  ) {
    throw new VaultError(
      'MALFORMED_RESPONSE',
      502,
      'Aadhaar Vault returned a success status without a confirmed approved challenge.',
    );
  }

  return {
    challengeId: data.challengeId,
    status: 'approved',
    approvedAt: data.approvedAt,
    verifiedFactorId: data.verifiedFactorId,
  };
};

/**
 * Install a replacement implementation. Pass `null` to reset to
 * the default HTTP path.
 */
export function __setApproveStepUpChallengeImpl(fn: ApproveStepUpChallengeFn | null): void {
  if (fn === null) {
    approveStepUpChallengeImpl = approveStepUpChallengeImplDefault;
    return;
  }
  approveStepUpChallengeImpl = fn;
}

/** Internal: the default HTTP-backed implementation. Stored as a
 *  const reference so {@link __setApproveStepUpChallengeImpl} can
 *  reset to it. */
const approveStepUpChallengeImplDefault = approveStepUpChallengeImpl;

export async function approveStepUpChallenge(
  params: ApproveStepUpParams,
): Promise<ApproveStepUpResult> {
  return approveStepUpChallengeImpl(params);
}

// ===========================================================================
// POST /v1/detokenize
// ===========================================================================

export type DetokenizeParams = {
  challengeId: string;
  context: AadhaarActorContext;
};

export type DetokenizeResult = {
  token: string;
  identityId: string;
  /** Plaintext 12-digit Aadhaar — TEMPORARY. Must not be persisted / cached
   *  beyond the lifetime of the admin's reveal step. The frontend clears it
   *  on dialog close and after a short auto-clear timer. */
  aadhaar: string;
  last4: string;
  auditId: string;
};

/**
 * Detokenize — thin wrapper around a swappable implementation.
 *
 * The implementation is swappable so the in-process vault module
 * (`backend/src/modules/vault/`) can install its own command-bound
 * function at boot, and so the integration tests can inject a
 * deterministic stub without standing up the full Mongo replica
 * set. The default implementation is the legacy HTTP path; the
 * vault module overrides it via {@link __setDetokenizeAadhaarImpl}
 * when the `VAULT_MODULE_ENABLED` flag is on.
 *
 * Throws {@link VaultError} on ANY failure — callers must fail the
 * reveal; there is no plaintext fallback path by design.
 */
export type DetokenizeAadhaarFn = (
  params: DetokenizeParams,
) => Promise<DetokenizeResult>;

let detokenizeAadhaarImpl: DetokenizeAadhaarFn = async (params) => {
  // Legacy HTTP path — the default. Kept working until the vault
  // module is the only caller. The vault module installs a new
  // impl at boot (see modules/vault/index.ts) and the HTTP env-
  // vars are no longer consulted.
  const timeoutMs = resolveTimeoutMs();
  const { status, data } = await callVault('/v1/detokenize', 'vault:detokenize', {
    challengeId: params.challengeId,
    context: {
      actorId: params.context.email || AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
      actorRole: params.context.actorRole,
      reason: `Detokenization for admin reveal — ${params.context.email || 'fln admin'}`,
      requestId: params.context.requestId || `fln-${randomUUID()}`,
      sourceIp: params.context.sourceIp,
      userAgent: params.context.userAgent,
    },
  }, timeoutMs);

  if (!status.toString().startsWith('2')) {
    throw mapVaultErrorResponse(status, data);
  }

  if (
    !data ||
    typeof data.token !== 'string' || data.token.length === 0 ||
    typeof data.aadhaar !== 'string' || data.aadhaar.length === 0 ||
    typeof data.identityId !== 'string' || data.identityId.length === 0
  ) {
    throw new VaultError(
      'MALFORMED_RESPONSE',
      502,
      'Aadhaar Vault returned a success status without the required detokenize fields.',
    );
  }

  return {
    token: data.token,
    identityId: data.identityId,
    aadhaar: data.aadhaar,
    last4: data.last4,
    auditId: data.auditId,
  };
};

/**
 * Install a replacement implementation. Called by the in-process
 * vault module at boot, and by integration tests via the test-
 * only name (the production code never has a public setter).
 */
export function __setDetokenizeAadhaarImpl(fn: DetokenizeAadhaarFn | null): void {
  if (fn === null) {
    detokenizeAadhaarImpl = detokenizeAadhaarImplDefault;
    return;
  }
  detokenizeAadhaarImpl = fn;
}

/** Internal: the default HTTP-backed implementation. Stored as a
 *  const reference so {@link __setDetokenizeAadhaarImpl} can reset
 *  to it. */
const detokenizeAadhaarImplDefault = detokenizeAadhaarImpl;

export async function detokenizeAadhaar(
  params: DetokenizeParams,
): Promise<DetokenizeResult> {
  return detokenizeAadhaarImpl(params);
}