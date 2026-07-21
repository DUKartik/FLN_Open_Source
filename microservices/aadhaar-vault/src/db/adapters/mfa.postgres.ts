/**
 * Postgres adapter for `MfaRepository`.
 *
 * The DB enforces the `status = 'pending'` default. Adapters therefore
 * use `RETURNING` to surface the server-assigned `status` /
 * `created_at` so callers don't have to guess.
 */
import type {
    MfaChallenge,
    MfaChallengeStatus,
    MfaRepository,
} from '../ports/mfa.repository.js';
import type { PoolLike } from '../pool.js';

interface MfaRow {
    challenge_id: string;
    actor: string;
    challenge_type: string;
    status: string;
    expires_at: Date;
    consumed_at: Date | null;
    created_at: Date;
}

function mapRow(row: MfaRow): MfaChallenge {
    return {
        challengeId: row.challenge_id,
        actor: row.actor,
        challengeType: row.challenge_type as MfaChallenge['challengeType'],
        status: row.status as MfaChallengeStatus,
        expiresAt: row.expires_at,
        consumedAt: row.consumed_at,
        createdAt: row.created_at,
    };
}

export class PostgresMfaRepository implements MfaRepository {
    constructor(private readonly pool: PoolLike) {}

    async insert(
        rec: Omit<MfaChallenge, 'createdAt' | 'consumedAt' | 'status'>,
    ): Promise<MfaChallenge> {
        const { rows } = await this.pool.query<MfaRow>(
            `INSERT INTO vault_mfa_challenges
                (challenge_id, actor, challenge_type, expires_at)
             VALUES ($1, $2, $3, $4)
             RETURNING challenge_id, actor, challenge_type, status,
                       expires_at, consumed_at, created_at`,
            [rec.challengeId, rec.actor, rec.challengeType, rec.expiresAt],
        );
        return mapRow(rows[0]!);
    }

    async markStatus(
        challengeId: string,
        status: MfaChallengeStatus,
    ): Promise<MfaChallenge | null> {
        const { rows } = await this.pool.query<MfaRow>(
            `UPDATE vault_mfa_challenges
             SET status = $2,
                 consumed_at = CASE
                     WHEN $2 = 'consumed' THEN now()
                     ELSE consumed_at
                 END
             WHERE challenge_id = $1
             RETURNING challenge_id, actor, challenge_type, status,
                       expires_at, consumed_at, created_at`,
            [challengeId, status],
        );
        return rows[0] ? mapRow(rows[0]) : null;
    }

    async getById(challengeId: string): Promise<MfaChallenge | null> {
        const { rows } = await this.pool.query<MfaRow>(
            `SELECT challenge_id, actor, challenge_type, status,
                    expires_at, consumed_at, created_at
             FROM vault_mfa_challenges
             WHERE challenge_id = $1`,
            [challengeId],
        );
        return rows[0] ? mapRow(rows[0]) : null;
    }
}