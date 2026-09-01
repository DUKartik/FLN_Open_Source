/**
 * Repository port interfaces (consolidated from
 * microservices/aadhaar-vault/src/db/ports/*.ts).
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
