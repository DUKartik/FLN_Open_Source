/**
 * MongoAuditRepository — implements the `AuditRepository` port
 * (Phase 2, tokenize milestone; Phase 3 widens with `listByIdentity`).
 * Append-only. There is intentionally no `update` or `delete` method —
 * retention is handled out-of-band by a TTL policy or a cron job.
 *
 * Schema (collection `vault_audit_log`):
 *   _id:          ObjectId  (server-assigned; returned as the auditId)
 *   identityId:   string | null
 *   actor:        string
 *   action:       string
 *   outcome:      'allow' | 'deny' | 'error'
 *   reason:       string | null
 *   requestId:    string | null
 *   meta:         object
 *   occurredAt:   Date
 *
 * The `meta` field is opaque from the audit chain's perspective;
 * the calling command decides what to put in it.
 */
import type { Collection, Db, ClientSession, ObjectId } from 'mongodb';
import { VAULT_COLLECTIONS } from '../../schema/collections';
import type {
  AuditEntry,
  AuditRecord,
  AuditRepository,
} from '../../application/ports/repositories';

interface AuditDoc {
  _id: ObjectId;
  identityId: string | null;
  actor: string;
  action: string;
  outcome: 'allow' | 'deny' | 'error';
  reason: string | null;
  requestId: string | null;
  meta: Record<string, unknown>;
  occurredAt: Date;
}

function toRecord(doc: AuditDoc): AuditRecord {
  return {
    auditId: doc._id.toHexString(),
    identityId: doc.identityId,
    actor: doc.actor,
    action: doc.action,
    outcome: doc.outcome,
    reason: doc.reason,
    requestId: doc.requestId,
    meta: doc.meta,
    occurredAt: doc.occurredAt,
  };
}

export class MongoAuditRepository implements AuditRepository {
  constructor(
    private readonly db: Db,
    private readonly session?: ClientSession,
  ) {}

  private col(): Collection<AuditDoc> {
    return this.db.collection<AuditDoc>(VAULT_COLLECTIONS.auditLog);
  }

  async append(entry: AuditEntry): Promise<string> {
    const doc: Omit<AuditDoc, '_id'> = {
      identityId: entry.identityId,
      actor: entry.actor,
      action: entry.action,
      outcome: entry.outcome,
      reason: entry.reason ?? null,
      requestId: entry.requestId ?? null,
      meta: entry.meta ?? {},
      occurredAt: new Date(),
    };
    const { insertedId } = await this.col().insertOne(doc as AuditDoc, { session: this.session });
    return insertedId.toHexString();
  }

  async listByIdentity(
    identityId: string,
    opts: { limit?: number } = {},
  ): Promise<AuditRecord[]> {
    const limit = Math.max(1, Math.min(opts.limit ?? 100, 1000));
    const docs = await this.col()
      .find({ identityId })
      .sort({ occurredAt: -1 })
      .limit(limit)
      .toArray();
    return docs.map(toRecord);
  }
}
