/**
 * Vault index ensure-on-boot.
 *
 * Creates the collections + indexes the vault needs to operate. Safe
 * to call multiple times — `createIndex` is idempotent for identical
 * specs and `createCollection` will return the existing name silently
 * if the collection already exists.
 *
 * Phase 2 only needs the tokenize + audit-write path. Step-up and MFA
 * indexes land in Phase 3 / Phase 4.
 */
import type { Db } from 'mongodb';
import { VAULT_COLLECTIONS } from './collections';

export async function ensureVaultIndexes(db: Db): Promise<void> {
  // vault_identities — _id is the natural key (subjectHash UUID).
  // No secondary indexes needed for Phase 2 reads; the writes are
  // upserts on _id which is the primary index.
  await db.createCollection(VAULT_COLLECTIONS.identities).catch((err) => {
    // NamespaceExists (48) is fine — collection already present.
    if (err?.codeName !== 'NamespaceExists') throw err;
  });

  // vault_tokens — _id is the natural key (the opaque token id).
  // `identityId` is the FK used by Phase 3's detokenize path to walk
  // from identity -> tokens, so a secondary index pays off there.
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
}
