/**
 * Repository port interfaces (consolidated from
 * src/db/ports/*.ts).
 *
 * In the original microservice each repository lived in its own file.
 * Here we consolidate the three needed for Phase 2 (tokenize) into one
 * file so the port surface is co-located. Phases 3 (mfa, step-up) and
 * 4 will add more types here or in sibling files.
 */
import type { Buffer } from 'node:buffer';

// ---------------------------------------------------------------------------
// Identity repository
// ---------------------------------------------------------------------------
export interface IdentityRecord {
  identityId: string;
  ciphertext: Buffer;
  aad: Buffer;
  pepperVersion: number;
  keyVersion: number;
  createdAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
}

export type NewIdentityRecord = Omit<
  IdentityRecord,
  'createdAt' | 'rotatedAt' | 'revokedAt'
>;

export interface IdentityRepository {
  insert(rec: NewIdentityRecord): Promise<IdentityRecord>;
  getById(identityId: string): Promise<IdentityRecord | null>;
  revoke(identityId: string): Promise<void>;
  rotate(identityId: string, keyVersion: number): Promise<void>;
}

// ---------------------------------------------------------------------------
// Token repository
// ---------------------------------------------------------------------------
export interface NewToken {
  /** Opaque token id. Application layer mints a UUIDv4. */
  id: string;
  identityId: string;
  algorithm: string;
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  wrappedDek: Buffer;
}

export interface TokenRow {
  id: string;
  identityId: string;
  algorithm: string;
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  wrappedDek: Buffer;
  /** Unix millis; matches the date semantics of `vault_identities.created_at`. */
  createdAt: number;
}

export interface TokenRepository {
  insert(token: NewToken): Promise<TokenRow>;
  findById(id: string): Promise<TokenRow | null>;
}

// ---------------------------------------------------------------------------
// Audit repository
// ---------------------------------------------------------------------------
export type AuditOutcome = 'allow' | 'deny' | 'error';

export interface AuditEntry {
  identityId: string | null;
  actor: string;
  action: string;
  outcome: AuditOutcome;
  reason?: string | null;
  requestId?: string | null;
  meta?: Record<string, unknown>;
}

export interface AuditRecord extends AuditEntry {
  auditId: string;
  occurredAt: Date;
}

export interface AuditRepository {
  /**
   * Append an audit row. Returns the assigned `auditId` (a stringified
   * ObjectId) so the caller can link related rows. Throws on DB failure;
   * never returns `null` / `undefined`.
   */
  append(entry: AuditEntry): Promise<string>;
  listByIdentity(
    identityId: string,
    opts?: { limit?: number },
  ): Promise<AuditRecord[]>;
}

// ---------------------------------------------------------------------------
// Step-up challenge repository (Phase 3)
// ---------------------------------------------------------------------------
// Lifecycle: pending → approved → consumed, or pending → expired/failed.
// The four state transitions are all implemented as `findOneAndUpdate` with
// a status guard so two concurrent consume() calls collapse to one winner.

export type StepUpChallengeStatus =
  | 'pending'
  | 'approved'
  | 'consumed'
  | 'expired'
  | 'failed';

export type StepUpOperation = 'detokenize';

export interface StepUpChallenge {
  challengeId: string;
  operation: StepUpOperation;
  identityId: string;
  tokenId: string | null;
  requestedBy: string;
  requestedAt: Date;
  expiresAt: Date;
  approvedAt: Date | null;
  consumedAt: Date | null;
  status: StepUpChallengeStatus;
  requiredFactorId: string;
  verifiedFactorId: string | null;
  auditId: string | null;
  metadata: string | null;
}

export interface CreateStepUpChallengeInput {
  challengeId: string;
  operation: StepUpOperation;
  identityId: string;
  tokenId: string | null;
  requestedBy: string;
  requestedAt: Date;
  expiresAt: Date;
  requiredFactorId: string;
  metadata: string | null;
}

export interface ApproveStepUpChallengeInput {
  challengeId: string;
  verifiedFactorId: string;
  approvedAt: Date;
  auditId: string | null;
}

export interface StepUpChallengeRepository {
  /** Persist a new challenge in `pending` state. */
  create(input: CreateStepUpChallengeInput): Promise<StepUpChallenge>;
  /** Look up a challenge by id. Returns `null` for unknown ids. */
  findById(challengeId: string): Promise<StepUpChallenge | null>;
  /**
   * Transition `pending → approved`. Returns the updated row, or
   * `null` if the row was missing or already past `pending`.
   */
  approve(input: ApproveStepUpChallengeInput): Promise<StepUpChallenge | null>;
  /**
   * Atomic `approved → consumed` transition. Returns the row, or
   * `null` if the row was missing, not `approved`, or already
   * `consumed`. This is the single replay-prevention gate.
   */
  consume(challengeId: string, consumedAt: Date): Promise<StepUpChallenge | null>;
  /** Transition `pending → expired`. Returns `null` if missing or not pending. */
  expire(challengeId: string, expiredAt: Date): Promise<StepUpChallenge | null>;
  /** Transition `pending → failed`. Returns `null` if missing or not pending. */
  fail(challengeId: string, failedAt: Date): Promise<StepUpChallenge | null>;
}

// ---------------------------------------------------------------------------
// MFA factor repository (Phase 4)
// ---------------------------------------------------------------------------
// Persistent step-up factor model. Each row is a TOTP factor that lives
// until revoked.
//
//   - `actor`           — the user / service principal that enrolled it.
//   - `factorType`      — currently 'totp'; future: 'webauthn', 'email-otp'.
//   - `status`          — 'active' or 'revoked'.
//   - `encryptedSecret` — the TOTP shared secret sealed via
//                         KeyManager.sealSecret; never stored in plaintext.
//   - `algorithm`       — 'SHA1' | 'SHA256' | 'SHA512'.
//   - `digits`          — code length, typically 6.
//   - `period`          — time-step in seconds, typically 30.
//   - `lastUsedAt`      — wall-clock time the most recent successful
//                         verification happened (for replay protection
//                         and audit).
//   - `expiresAt`       — optional deadline; TOTP factors do not expire,
//                         future factor types (e.g. email-OTP) may set it.
//   - `createdAt`       — enrollment time.

export type MfaFactorType = "totp";

export type MfaFactorStatus = "active" | "revoked";

export interface MfaFactor {
  factorId: string;
  actor: string;
  factorType: MfaFactorType;
  status: MfaFactorStatus;
  label: string;
  /** AES-GCM envelope of the TOTP shared secret. Persisted as the
   *  output of KeyManager.sealSecret. */
  encryptedSecret: Buffer;
  algorithm: string;
  digits: number;
  period: number;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
}

export interface InsertMfaFactorInput {
  factorId: string;
  actor: string;
  factorType: MfaFactorType;
  label: string;
  encryptedSecret: Buffer;
  algorithm: string;
  digits: number;
  period: number;
  expiresAt?: Date | null;
}

export interface MfaFactorRepository {
  /**
   * Persist a newly enrolled factor. The adapter supplies `createdAt`
   * (the application's wall clock) and `status='active'`. The caller
   * supplies the factor_id (UUIDv7, same shape as `vault_tokens.id`).
   */
  insert(rec: InsertMfaFactorInput): Promise<MfaFactor>;

  /** Mark the factor as having been used at `usedAt`. Idempotent:
   *  a second call updates the timestamp. Returns null when the
   *  factor_id is unknown. */
  markUsed(factorId: string, usedAt: Date): Promise<MfaFactor | null>;

  /** Revoke the factor. After this call the factor still exists
   *  (audit) but {@link listActiveByActor} will skip it. Idempotent:
   *  revoking an already-revoked row is a no-op that still returns
   *  the row. */
  revoke(factorId: string): Promise<MfaFactor | null>;

  /** Look up by id. Returns null when unknown. */
  getById(factorId: string): Promise<MfaFactor | null>;

  /** All factors enrolled by an actor, newest first. */
  listByActor(actor: string): Promise<MfaFactor[]>;

  /** Active (non-revoked) factors only. The detokenize hot path. */
  listActiveByActor(actor: string): Promise<MfaFactor[]>;
}
