/**
 * MongoMfaFactorRepository — implements the `MfaFactorRepository` port
 * (Phase 4, MFA + step-up). One row per enrolled TOTP factor. A
 * factor lives until it is revoked; revoking is idempotent and
 * `markUsed` is idempotent.
 *
 * Schema (collection `vault_mfa_factors`):
 *   _id:            string    (the opaque factor id, UUID minted by the
 *                             application at enrollment time)
 *   actor:          string    (the user / service principal — JWT subject)
 *   factorType:     'totp'    (extensible to 'webauthn' / 'email-otp')
 *   status:         'active' | 'revoked'
 *   label:          string    (human-readable; surfaced in otpauth URI)
 *   encryptedSecret: Buffer   (KeyManager.sealSecret output)
 *   algorithm:      'SHA1' | 'SHA256' | 'SHA512'
 *   digits:         number
 *   period:         number
 *   lastUsedAt:     Date | null
 *   expiresAt:      Date | null
 *   createdAt:      Date
 *
 * Plaintext hygiene: the `encryptedSecret` field is the AES-GCM
 * envelope from `KeyManager.sealSecret`. The plaintext TOTP secret
 * is never persisted, never logged, never returned by the read API.
 */
import type { Collection, Db } from 'mongodb';
import { VAULT_COLLECTIONS } from '../../schema/collections';
import type {
  InsertMfaFactorInput,
  MfaFactor,
  MfaFactorRepository,
  MfaFactorStatus,
  MfaFactorType,
} from '../../application/ports/repositories';
import { toBuffer } from './binary';

interface FactorDoc {
  _id: string;
  actor: string;
  factorType: string;
  status: string;
  label: string;
  encryptedSecret: Buffer;
  algorithm: string;
  digits: number;
  period: number;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
}

function toFactor(doc: FactorDoc): MfaFactor {
  return {
    factorId: doc._id,
    actor: doc.actor,
    factorType: doc.factorType as MfaFactorType,
    status: doc.status as MfaFactorStatus,
    label: doc.label,
    encryptedSecret: toBuffer(doc.encryptedSecret),
    algorithm: doc.algorithm,
    digits: doc.digits,
    period: doc.period,
    lastUsedAt: doc.lastUsedAt,
    expiresAt: doc.expiresAt,
    createdAt: doc.createdAt,
  };
}

export class MongoMfaFactorRepository implements MfaFactorRepository {
  constructor(private readonly db: Db) {}

  private col(): Collection<FactorDoc> {
    return this.db.collection<FactorDoc>(VAULT_COLLECTIONS.mfaFactors);
  }

  async insert(rec: InsertMfaFactorInput): Promise<MfaFactor> {
    const doc: FactorDoc = {
      _id: rec.factorId,
      actor: rec.actor,
      factorType: rec.factorType,
      status: 'active',
      label: rec.label,
      encryptedSecret: rec.encryptedSecret,
      algorithm: rec.algorithm,
      digits: rec.digits,
      period: rec.period,
      lastUsedAt: null,
      expiresAt: rec.expiresAt ?? null,
      createdAt: new Date(),
    };
    await this.col().insertOne(doc);
    return toFactor(doc);
  }

  async markUsed(factorId: string, usedAt: Date): Promise<MfaFactor | null> {
    // Idempotent — a second call updates the timestamp. Returns the
    // updated row, or `null` if the factor_id is unknown.
    const result = await this.col().findOneAndUpdate(
      { _id: factorId },
      { $set: { lastUsedAt: usedAt } },
      { returnDocument: 'after' },
    );
    return result ? toFactor(result as FactorDoc) : null;
  }

  async revoke(factorId: string): Promise<MfaFactor | null> {
    // Idempotent — revoking an already-revoked row is a no-op that
    // still returns the row. Returns `null` only when the factor_id
    // is unknown.
    const result = await this.col().findOneAndUpdate(
      { _id: factorId },
      { $set: { status: 'revoked' } },
      { returnDocument: 'after' },
    );
    return result ? toFactor(result as FactorDoc) : null;
  }

  async getById(factorId: string): Promise<MfaFactor | null> {
    const doc = await this.col().findOne({ _id: factorId });
    return doc ? toFactor(doc) : null;
  }

  async listByActor(actor: string): Promise<MfaFactor[]> {
    const docs = await this.col()
      .find({ actor })
      .sort({ createdAt: -1 })
      .toArray();
    return docs.map(toFactor);
  }

  async listActiveByActor(actor: string): Promise<MfaFactor[]> {
    const docs = await this.col()
      .find({ actor, status: 'active' })
      .sort({ createdAt: -1 })
      .toArray();
    return docs.map(toFactor);
  }
}
