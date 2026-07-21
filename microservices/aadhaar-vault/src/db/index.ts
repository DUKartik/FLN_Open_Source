/**
 * Database wiring module.
 *
 * Produces a ready-to-use {@link Database} object containing the pool
 * and four repository instances. The factory is intentionally thin so
 * that any future orchestration (transactions, replicas, read-only
 * pools) lives in one file rather than scattered across repositories.
 *
 * Usage (production):
 *
 *   const db = await createDatabase({
 *       uri: cfg.VAULT_DB_URI,
 *       logger: childLogger,
 *   });
 *
 *   const token = await db.identities.insert({...});
 *   await db.audit.append({...});
 *
 * In production, call `await db.close()` from the shutdown handler.
 * Tests get the same shape via `createMemoryDatabase()` which uses a
 * hand-rolled `MemoryPool` instead of booting Postgres or pulling in
 * `pg-mem`.
 *
 * Why a hand-rolled pool?
 *   `pg-mem` hung indefinitely against the rewritten DDL during local
 *   regression. Rather than patch a regex-based rewriter over each
 *   migration file we declare the schema once, in TypeScript, against
 *   the typed column shapes the adapters expect. The supported SQL
 *   surface in `memory-pool.ts` is, by construction, exactly the
 *   surface the four adapters issue — anything divergent trips a
 *   thrown error and is caught in CI instead of returning wrong rows.
 */
import type { FastifyBaseLogger } from 'fastify';

import {
    PostgresAuditRepository,
} from './adapters/audit.postgres.js';
import {
    PostgresIdentityRepository,
} from './adapters/identity.postgres.js';
import {
    PostgresKeyMetadataRepository,
} from './adapters/key-metadata.postgres.js';
import {
    PostgresMfaRepository,
} from './adapters/mfa.postgres.js';
import { MemoryPool, type TableSpec } from './memory-pool.js';
import { runMigrations } from './migrator.js';
import type { AuditRepository } from './ports/audit.repository.js';
import type { IdentityRepository } from './ports/identity.repository.js';
import type { KeyMetadataRepository } from './ports/key-metadata.repository.js';
import type { MfaRepository } from './ports/mfa.repository.js';
import {
    createMemoryPool,
    createRealPool,
    pingPool,
    type PoolLike,
} from './pool.js';

export { pingPool };

export interface Database {
    pool: PoolLike;
    identities: IdentityRepository;
    audit: AuditRepository;
    mfa: MfaRepository;
    keyMetadata: KeyMetadataRepository;
    close(): Promise<void>;
}

export interface CreateDatabaseOptions {
    uri: string;
    logger?: FastifyBaseLogger;
    /** Skip the migrate-on-boot step. Used by unit tests that
     *  pre-arrange their schema. Default: `false`. */
    skipMigrations?: boolean;
}

/**
 * Build a {@link Database} against a real Postgres URI. Migrations are
 * applied unless `skipMigrations` is set.
 */
export async function createDatabase(
    options: CreateDatabaseOptions,
): Promise<Database> {
    const pool = createRealPool(options.uri);

    if (!options.skipMigrations) {
        const result = await runMigrations(pool);
        if (options.logger) {
            if (result.applied.length > 0) {
                options.logger.info(
                    { applied: result.applied, skipped: result.skipped },
                    'vault.db.migrations.applied',
                );
            } else {
                options.logger.debug(
                    { skipped: result.skipped },
                    'vault.db.migrations.noop',
                );
            }
        }
    }

    return assembleDb(pool);
}

/**
 * Build a {@link Database} against an in-process {@link MemoryPool}.
 * Pre-declares the schema (no migrator pass).
 */
export async function createMemoryDatabase(): Promise<Database> {
    const pool = createMemoryPool();
    declareSchema(pool);
    return assembleDb(pool);
}

async function assembleDb(pool: PoolLike): Promise<Database> {
    return {
        pool,
        identities: new PostgresIdentityRepository(pool),
        audit: new PostgresAuditRepository(pool),
        mfa: new PostgresMfaRepository(pool),
        keyMetadata: new PostgresKeyMetadataRepository(pool),
        async close() {
            await pool.end();
        },
    };
}

/**
 * Hand-written TypeScript schema for the in-memory pool.
 *
 * Mirrors `src/db/migrations/001_initial_schema.sql` exactly:
 *
 *   - `vault_schema_migrations`  — bookkeeping only
 *   - `vault_identities`         — encrypted blobs
 *   - `vault_audit_log`          — append-only trail
 *   - `vault_mfa_challenges`     — step-up auth artifacts
 *   - `vault_key_metadata`       — key lifecycle
 *
 * The supported SQL grammar in `MemoryPool` is
 * `INSERT / UPDATE / SELECT` of the shapes the adapters issue; DDL is
 * implicitly satisfied by `define()` here, so the test path skips
 * `runMigrations` entirely.
 */
function declareSchema(pool: MemoryPool): void {
    const tables: TableSpec[] = [
        {
            name: 'vault_schema_migrations',
            pk: 'version',
            columns: [
                { name: 'version', type: 'text', nullable: false },
                { name: 'applied_at', type: 'date', nullable: false },
            ],
        },
        {
            name: 'vault_identities',
            pk: 'identity_id',
            columns: [
                { name: 'identity_id', type: 'text', nullable: false },
                { name: 'ciphertext', type: 'bytes', nullable: false },
                { name: 'aad', type: 'bytes', nullable: false },
                { name: 'pepper_version', type: 'int', nullable: false },
                { name: 'key_version', type: 'int', nullable: false },
                { name: 'created_at', type: 'date', nullable: false },
                { name: 'rotated_at', type: 'date', nullable: true },
                { name: 'revoked_at', type: 'date', nullable: true },
            ],
        },
        {
            name: 'vault_audit_log',
            pk: 'audit_id',
            columns: [
                { name: 'audit_id', type: 'int', nullable: false },
                { name: 'identity_id', type: 'text', nullable: true },
                { name: 'actor', type: 'text', nullable: false },
                { name: 'action', type: 'text', nullable: false },
                { name: 'outcome', type: 'text', nullable: false },
                { name: 'reason', type: 'text', nullable: true },
                { name: 'request_id', type: 'text', nullable: true },
                { name: 'occurred_at', type: 'date', nullable: false },
                { name: 'meta', type: 'json', nullable: false },
            ],
            autoIncrement: true,
        },
        {
            name: 'vault_mfa_challenges',
            pk: 'challenge_id',
            columns: [
                { name: 'challenge_id', type: 'text', nullable: false },
                { name: 'actor', type: 'text', nullable: false },
                { name: 'challenge_type', type: 'text', nullable: false },
                { name: 'status', type: 'text', nullable: false },
                { name: 'expires_at', type: 'date', nullable: false },
                { name: 'consumed_at', type: 'date', nullable: true },
                { name: 'created_at', type: 'date', nullable: false },
            ],
            // `DEFAULT 'pending'` in 001_initial_schema.sql + an
            // application-supplied `created_at` (the adapter always
            // passes it; see `mfa.postgres.ts`).
            defaults: {
                status: () => 'pending',
            },
        },
        {
            name: 'vault_key_metadata',
            pk: 'key_id',
            columns: [
                { name: 'key_id', type: 'text', nullable: false },
                { name: 'algorithm', type: 'text', nullable: false },
                { name: 'pepper_version', type: 'int', nullable: false },
                { name: 'status', type: 'text', nullable: false },
                { name: 'created_at', type: 'date', nullable: false },
                { name: 'retired_at', type: 'date', nullable: true },
                { name: 'destroyed_at', type: 'date', nullable: true },
            ],
            // `DEFAULT 'active'` in 001_initial_schema.sql + an
            // application-supplied `created_at` (the adapter passes it).
            defaults: {
                status: () => 'active',
            },
        },
    ];
    for (const t of tables) pool.define(t);
}
