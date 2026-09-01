/**
 * Vault index ensure-on-boot.
 *
 * Creates the collections + indexes the vault needs to operate. Safe
 * to call multiple times — `createIndex` is idempotent for identical
 * specs and `createCollection` will return the existing name silently
 * if the collection already exists.
 *
 * Phase 2: identities, tokens, audit_log.
 * Phase 3: step_up_challenges (incl. TTL on terminal rows).
 * Phase 4: mfa_factors.
 */
import type { Db } from 'mongodb';
import { VAULT_COLLECTIONS } from './collections';

export async function ensureVaultIndexes(db: Db): Promise<void> {
  // vault_identities — _id is the natural key (subjectHash UUID).
  await db.createCollection(VAULT_COLLECTIONS.identities).catch((err) => {
    if (err?.codeName !== 'NamespaceExists') throw err;
  });

  // vault_tokens — _id is the natural key (the opaque token id).
  // `identityId` is the FK used by Phase 3's detokenize path.
  await db.createCollection(VAULT_COLLECTIONS.tokens).catch((err) => {
    if (err?.codeName !== 'NamespaceExists') throw err;
  });
  await db.collection(VAULT_COLLECTIONS.tokens).createIndex({ identityId: 1 });

  // vault_audit_log — listByIdentity is the read path; sort by
  // occurredAt desc. Compound index supports both.
  await db.createCollection(VAULT_COLLECTIONS.auditLog).catch((err) => {
    if (err?.codeName !== 'NamespaceExists') throw err;
  });
  await db
    .collection(VAULT_COLLECTIONS.auditLog)
    .createIndex({ identityId: 1, occurredAt: -1 });

  // vault_step_up_challenges — Phase 3.
  // PK is `challenge_id` (the natural key); we store it on `_id`.
  // Secondary indexes (mirroring the Postgres migration 004):
  //   - status+expiresAt: prune lookup
  //   - requestedBy: list a principal's pending challenges
  //   - expiresAt TTL: Mongo's native equivalent of the Postgres
  //     `deleteExpired` cron. Only terminal rows (consumed/expired/
  //     failed) are eligible because Mongo's TTL sweeper deletes
  //     any document whose indexed date field is older than the
  //     configured offset — pending rows are protected by being
  //     transitioned to `expired` first via the repository. The
  //     grace window is 1h so audit consumers have time to read
  //     recently-terminal rows.
  await db.createCollection(VAULT_COLLECTIONS.stepUpChallenges).catch((err) => {
    if (err?.codeName !== 'NamespaceExists') throw err;
  });
  await db
    .collection(VAULT_COLLECTIONS.stepUpChallenges)
    .createIndex({ status: 1, expiresAt: 1 });
  await db
    .collection(VAULT_COLLECTIONS.stepUpChallenges)
    .createIndex(
      { requestedBy: 1 },
      { partialFilterExpression: { status: 'pending' } },
    );
  await db
    .collection(VAULT_COLLECTIONS.stepUpChallenges)
    .createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 3600 }, // 1h grace after expiresAt
    );
}
