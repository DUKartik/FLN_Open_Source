/**
 * MFA challenge repository port.
 *
 * Step-up authentication is used when the caller wants to detokenize
 * (i.e. unwrap the ciphertext and obtain the plaintext identity
 * number). The challenge is short-lived and consumed exactly once.
 */
export type MfaChallengeType = 'totp' | 'webauthn' | 'email-otp';
export type MfaChallengeStatus =
    | 'pending'
    | 'consumed'
    | 'expired'
    | 'failed';

export interface MfaChallenge {
    challengeId: string;
    actor: string;
    challengeType: MfaChallengeType;
    status: MfaChallengeStatus;
    expiresAt: Date;
    consumedAt: Date | null;
    createdAt: Date;
}

export interface MfaRepository {
    insert(
        rec: Omit<MfaChallenge, 'createdAt' | 'consumedAt' | 'status'>,
    ): Promise<MfaChallenge>;
    markStatus(
        challengeId: string,
        status: MfaChallengeStatus,
    ): Promise<MfaChallenge | null>;
    getById(challengeId: string): Promise<MfaChallenge | null>;
}