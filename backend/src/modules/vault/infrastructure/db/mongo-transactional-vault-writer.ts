/**
 * MongoTransactionalVaultWriter — wraps a unit of work in a single
 * MongoDB multi-document transaction.
 *
 * Replica-set requirement:
 *   The Mongo driver's `session.withTransaction(...)` is only
 *   supported on a replica set or a sharded cluster. A standalone
 *   `mongod` (the default for local dev) cannot do cross-document
 *   transactions and the driver throws `Transaction numbers are only
 *   allowed on a replica set member or mongos`. We translate that
 *   error (and its siblings) to a typed `VaultError` with code
 *   `VAULT_DB_REQUIRES_REPLICA_SET` (HTTP 503) so callers see a
 *   stable contract — the JSON-file fallback path is intentionally
 *   NOT used for vault writes (the threat model assumes a single
 *   encrypted-at-rest primary store).
 *
 * Connection scope:
 *   The session is created from `client.startSession()` and is always
 *   ended in `finally`. The repos handed to `work` are bound to that
 *   session so their writes participate in the transaction.
 */
import type { ClientSession, Db, MongoClient } from 'mongodb';
import { VaultError } from '../../errors';
import type {
  TransactionalVaultWriter,
  VaultWriteConnection,
} from '../../application/ports/transactional-vault-writer';
import { MongoIdentityRepository } from './mongo-identity.repository';
import { MongoTokenRepository } from './mongo-token.repository';
import { MongoAuditRepository } from './mongo-audit.repository';

// Driver error messages that mean "this MongoDB deployment cannot
// service multi-document transactions". Used to translate a driver-
// level exception into the typed VaultError the route layer maps to
// HTTP 503.
const REPLICA_SET_ERROR_PATTERNS = [
  /Transaction numbers are only allowed on a replica set member or mongos/i,
  /not supported in standalone/i,
  /IllegalOperation.*transaction/i,
];

function isReplicaSetRequiredError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return REPLICA_SET_ERROR_PATTERNS.some(p => p.test(msg));
}

export class MongoTransactionalVaultWriter implements TransactionalVaultWriter {
  constructor(
    private readonly db: Db,
    private readonly client: MongoClient,
  ) {}

  async runWrite<T>(work: (conn: VaultWriteConnection) => Promise<T>): Promise<T> {
    const session: ClientSession = this.client.startSession();
    let result: T;
    try {
      try {
        await session.withTransaction(async () => {
          const conn: VaultWriteConnection = {
            insertIdentity: (rec) =>
              new MongoIdentityRepository(this.db, session).insert(rec).then(() => undefined),
            insertToken: (token) =>
              new MongoTokenRepository(this.db, session).insert(token),
            appendAudit: (entry) =>
              new MongoAuditRepository(this.db, session).append(entry).then(() => undefined),
          };
          result = await work(conn);
        });
      } catch (err) {
        if (isReplicaSetRequiredError(err)) {
          throw new VaultError(
            'VAULT_DB_REQUIRES_REPLICA_SET',
            'The vault requires a MongoDB replica set (or sharded cluster) for atomic ' +
              'multi-document writes. A standalone `mongod` cannot service transactions. ' +
              'See MIGRATION_PLAN.md Phase 2 / Phase 7 deployment notes.',
            503,
          );
        }
        throw err;
      }
    } finally {
      await session.endSession().catch(() => undefined);
    }
    return result!;
  }
}
