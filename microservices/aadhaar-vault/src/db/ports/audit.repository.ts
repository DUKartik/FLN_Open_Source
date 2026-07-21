/**
 * Audit repository port.
 *
 * Append-only. There is intentionally no `update` or `delete` method —
 * retention is handled out-of-band by a cron job that moves old rows
 * to cold storage.
 *
 * See AADHAAR_VAULT_FREE_ARCHITECTURE.md §4.2.
 */
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
    auditId: number;
    occurredAt: Date;
}

export interface AuditRepository {
    append(entry: AuditEntry): Promise<void>;
    listByIdentity(
        identityId: string,
        opts?: { limit?: number },
    ): Promise<AuditRecord[]>;
}