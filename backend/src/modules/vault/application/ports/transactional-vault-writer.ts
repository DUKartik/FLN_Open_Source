/**
 * Transactional write unit-of-work (ported verbatim from
 * src/application/ports/transactional-vault-writer.ts).
 *
 * The command writes to three collections — `vault_identities`, `vault_tokens`,
 * `vault_audit_log` — and these three writes must succeed **or fail
 * together**. If `vault_tokens.insert(...)` succeeds but
 * `vault_audit_log.append(...)` fails (e.g. disk full, deadlock, broken
 * connection) the vault would end up holding an unwrapped ciphertext row
 * with no audit trail of *who* tokenized it. That is unacceptable.
 *
 * Wrapping the three writes in a single `withTransaction` block is the
 * standard fix. The Mongo adapter (`infrastructure/db/mongo-transactional-vault-writer.ts`)
 * uses `db.startSession() + session.withTransaction()`; the in-memory
 * test adapter (if needed) is just a closure. The command is identical
 * either way.
 */
import type { AuditEntry } from './repositories';
import type { NewIdentityRecord } from './repositories';
import type { NewToken, TokenRow } from './repositories';

/**
 * The set of write operations the command is allowed to perform inside
 * one transactional unit. Only methods the command actually needs are
 * exposed; the command must not reach for unrelated repository
 * capabilities from within a transaction (e.g. `revoke`, `rotate`).
 */
export interface VaultWriteConnection {
  insertIdentity(rec: NewIdentityRecord): Promise<void>;
  insertToken(token: NewToken & { id: string }): Promise<TokenRow>;
  appendAudit(entry: AuditEntry): Promise<void>;
}

/**
 * Wraps a unit of work in a single vault transaction.
 *
 * The writer is responsible for:
 *
 *   - Opening a transactional scope (Mongo `withTransaction` or equivalent);
 *   - Handing the work a `VaultWriteConnection` bound to that
 *     scope;
 *   - Committing if the work resolves;
 *   - Rolling back if the work throws, then re-throwing;
 *   - Releasing the underlying session in `finally`.
 *
 * The work may return any value, which is propagated to the caller.
 */
export interface TransactionalVaultWriter {
  runWrite<T>(work: (conn: VaultWriteConnection) => Promise<T>): Promise<T>;
}
