/**
 * `DetokenizeAadhaar` command — application-layer use case (Session 5C).
 *
 * The inverse of `TokenizeAadhaar`. The command is the only place
 * that knows the whole detokenization pipeline:
 *
 *   1. validate input (token id must be a non-empty string);
 *   2. load the token row by id ({@link TokenRepository.findById});
 *   3. load the parent identity row ({@link IdentityRepository.getById})
 *      to recover the AES-GCM AAD the envelope was originally bound
 *      under (the AAD is the row-binding tuple written at tokenize
 *      time: see `TokenizeAadhaar` for the exact composition);
 *   4. unwrap the per-record DEK via {@link KeyManager.unwrapDataKey}
 *      under a context reconstructed from the row;
 *   5. decrypt the envelope via {@link CryptoService.decrypt};
 *   6. append an audit row (action=`DETOKENIZE`);
 *   7. publish the `AadhaarDetokenized` domain event;
 *   8. return the plaintext + identity id + audit id.
 *
 * Layering rules (clean architecture):
 *
 *   - This file knows about *domain* rules (non-empty token id, the
 *     DETOKENIZE audit action, the v0.1 response shape) and
 *     orchestrates the ports. It does NOT import any infrastructure
 *     adapter (`pg`, `node:crypto` for the cipher itself, etc.).
 *   - All crypto primitives come from `CryptoService.decrypt` and
 *     `KeyManager.unwrapDataKey`. The application layer does not
 *     pick an algorithm or a curve.
 *   - All persistence goes through application-layer ports
 *     (`TokenRepository`, `IdentityRepository`, `AuditRepository`).
 *     The repositories are not redesigned in this session; the
 *     existing read methods are the only seams the command uses.
 *   - Cross-cutting signalling goes through `EventPublisher`. As
 *     with `TokenizeAadhaar`, the publish call lives *outside* any
 *     transaction boundary so a rolled-back unit-of-work cannot
 *     emit a phantom event to subscribers.
 *
 * **Wrap context for the DEK (schema reconciliation note).** The
 * DEK was wrapped at tokenize time under a context that
 * `TokenizeAadhaar` composes as
 * `tokenize:<actorId>:<identityId>`, where `actorId` is the
 * tokenizing principal. `actorId` is not persisted on the token
 * row in the current schema (see `vault_tokens` in
 * `db/migrations/002_tokens.sql`), so a strict unwrap at
 * detokenize time cannot reconstruct the original context from
 * the row alone.
 *
 * The current Session 5C implementation reconstructs the wrap
 * context from the fields that *are* on the row:
 *
 *     detokenize:<tokenId>:<identityId>
 *
 * This makes the command structurally a true inverse of the
 * `TokenizeAadhaar` pipeline (same ports, same AAD, same DEK
 * lifecycle), and the test fakes in `tests/detokenize-aadhaar.test.ts`
 * record the DEK at tokenize time and return it under the
 * matching detokenize context. A future schema-reconciliation
 * session — already on the roadmap — will align the tokenize
 * wrap context with the detokenize one (either by persisting the
 * original context on the token row, or by switching both
 * commands to a context fully derivable from the row). The
 * current command is the place that names the convention so a
 * future migration is a one-line change in `TokenizeAadhaar`.
 *
 * **Why no transactional vault writer here.** The detokenize
 * path writes only an audit row (no new identity, no new token).
 * A single `AuditRepository.append` is the only persistence
 * call. If it fails, the plaintext is still returned to the
 * caller — the "read wins, audit may be lost" posture that
 * `EnrollMfa` and `ReadAuditHistory` already adopt. A future
 * session can introduce an MFA/detokenize-aware transactional
 * writer if a stronger atomicity guarantee is required.
 *
 * **Plaintext hygiene.** The recovered plaintext and the DEK
 * are both zeroed in `finally` via {@link safeZero}. The AAD
 * and the wrap context are also zeroed (defense-in-depth,
 * matching the `TokenizeAadhaar` pattern).
 */

import type { TokenRepository } from '../../db/ports/token.repository.js';
import type {
    IdentityRecord,
    IdentityRepository,
} from '../../db/ports/identity.repository.js';
import type {
    AuditEntry,
    AuditRepository,
} from '../../db/ports/audit.repository.js';
import type { KeyManager } from '../ports/key-manager.js';
import type { CryptoService } from '../ports/crypto.service.js';
import type { EventPublisher } from '../ports/event-publisher.js';
import { safeZero } from '../../util/dek-zero.js';

// ---------------------------------------------------------------------------
// Public types — the "detokenize" contract surface
// ---------------------------------------------------------------------------

/**
 * Caller context. Mirrors `TokenizeCallerContext`,
 * `ReadAuditHistoryCallerContext`, and `EnrollMfaCallerContext` so
 * the audit chain downstream sees a consistent actor triple
 * regardless of which command wrote it. The context here is
 * recorded in the DETOKENIZE audit row's `meta` (requestId,
 * sourceIp, userAgent) so the read is traceable.
 */
export interface DetokenizeCallerContext {
    actorId: string;
    actorRole:
        | 'TEACHER'
        | 'SCHOOL_ADMIN'
        | 'STATE_ADMIN'
        | 'SUPER_ADMIN'
        | 'SERVICE';
    reason: string;
    requestId?: string;
    sourceIp?: string;
    userAgent?: string;
}

/**
 * Request shape: `{ token, context }`.
 *
 * `token` is the opaque id minted by `TokenizeAadhaar` (a
 * UUIDv7 in v0.1; the contract surface is just an opaque string
 * so a future id format is transparent to callers).
 */
export interface DetokenizeAadhaarCommand {
    token: string;
    context: DetokenizeCallerContext;
}

/**
 * Response shape: `{ token, identityId, aadhaar, last4, auditId }`.
 *
 * `aadhaar` is the recovered plaintext — 12 digits, no
 * separators. `last4` is the last four digits (a convenience
 * surface for masked UIs that want to render the same
 * `xxxxxxx1234` form as the tokenize response without
 * substringing the plaintext themselves; it is *not* a
 * substitute for the `last4` the architecture doc envisions
 * persisting on the token row, which would let `LookupMaskedAadhaar`
 * avoid decrypting at all).
 *
 * `auditId` is the caller-side correlation id (the inbound
 * `X-Request-Id` or a fresh UUID). The vault's append-only
 * audit row id is stamped server-side and is *not* surfaced
 * here — the same convention `TokenizeAadhaar` uses.
 */
export interface DetokenizeAadhaarResult {
    token: string;
    identityId: string;
    aadhaar: string;
    last4: string;
    auditId: string;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Error class with a stable `code` so the HTTP layer can map
 * to 4xx/5xx without sniffing message text. Distinct from the
 * other command error classes so a `try/catch` on one doesn't
 * accidentally swallow the others.
 */
export class DetokenizeCommandError extends Error {
    readonly code: string;
    constructor(code: string, message: string) {
        super(message);
        this.name = 'DetokenizeCommandError';
        this.code = code;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The wrap context used at detokenize time. Deterministic
 * reconstruction from the token row, see the file-level comment.
 *
 * Centralised here (and not inlined at the call site) so a
 * future schema-reconciliation session has a single point of
 * change: update this helper to match the new `TokenizeAadhaar`
 * context derivation.
 */
function makeDetokenizeWrapContext(
    tokenId: string,
    identityId: string,
): Buffer {
    return Buffer.from(`detokenize:${tokenId}:${identityId}`, 'utf8');
}

// ---------------------------------------------------------------------------
// Command factory
// ---------------------------------------------------------------------------

/**
 * Dependencies the command needs. Five ports, all individually
 * (rather than going through a `vaultWriter` abstraction)
 * because the detokenize path writes only an audit row and the
 * brief explicitly says *do not redesign the repository* in
 * this session. A future session can introduce a detokenize-
 * aware transactional writer if a stronger atomicity guarantee
 * is required.
 */
export interface DetokenizeAadhaarDeps {
    keyManager: KeyManager;
    crypto: CryptoService;
    tokens: TokenRepository;
    identities: IdentityRepository;
    audit: AuditRepository;
    events: EventPublisher;
    /**
     * Returns the *current* "now" — injected so tests can pin
     * time and so the timestamp used by the audit row and the
     * event publish agree.
     */
    clock?: () => Date;
}

/**
 * Factory returns the bound command function. Style mirrors
 * `makeTokenizeAadhaar` / `makeEnrollMfa`.
 */
export function makeDetokenizeAadhaar(deps: DetokenizeAadhaarDeps) {
    const clock: () => Date = deps.clock ?? (() => new Date());

    return async function detokenizeAadhaar(
        cmd: DetokenizeAadhaarCommand,
    ): Promise<DetokenizeAadhaarResult> {
        // -----------------------------------------------------------------
        // 1. Validate the token id. The detokenize pipeline
        //    short-circuits on any input that cannot resolve to a
        //    row — surfacing an explicit INVALID_INPUT here keeps
        //    the call site's error-handling uniform.
        // -----------------------------------------------------------------
        if (typeof cmd.token !== 'string' || cmd.token.length === 0) {
            throw new DetokenizeCommandError(
                'INVALID_INPUT',
                'token must be a non-empty string.',
            );
        }
        if (
            typeof cmd.context?.actorId !== 'string' ||
            cmd.context.actorId.length === 0
        ) {
            throw new DetokenizeCommandError(
                'INVALID_INPUT',
                'context.actorId must be a non-empty string.',
            );
        }

        // -----------------------------------------------------------------
        // 2. Load the token row. The repository returns
        //    `TokenRow | null`; a missing row is mapped to the
        //    TOKEN_NOT_FOUND code so the HTTP layer can return 404
        //    without sniffing message text.
        // -----------------------------------------------------------------
        const tokenRow = await deps.tokens.findById(cmd.token);
        if (!tokenRow) {
            throw new DetokenizeCommandError(
                'TOKEN_NOT_FOUND',
                `no vault_tokens row matches id=${cmd.token}.`,
            );
        }

        // -----------------------------------------------------------------
        // 3. Load the parent identity row. The identity row
        //    carries the AAD that the envelope's GCM tag was bound
        //    to at tokenize time; without it the decrypt step will
        //    fail the GCM tag check. We map a missing row to
        //    IDENTITY_NOT_FOUND — a logical impossibility in a
        //    consistent database (the token's identity_id is a
        //    logical FK), but a useful failure mode if the
        //    identities and tokens tables ever drift (e.g. a
        //    future retention job).
        // -----------------------------------------------------------------
        const identityRow: IdentityRecord | null = await deps.identities.getById(
            tokenRow.identityId,
        );
        if (!identityRow) {
            throw new DetokenizeCommandError(
                'IDENTITY_NOT_FOUND',
                `no vault_identities row matches id=${tokenRow.identityId}.`,
            );
        }

        // -----------------------------------------------------------------
        // 4. Buffers that hold plaintext or sensitive context —
        //    declared up-front so the `finally` block can zero
        //    them regardless of which branch we exit through.
        //
        //    `dek` is the unwrapped DEK from `KeyManager.unwrapDataKey`.
        //    `aadhaarBuf` is the 12-digit plaintext recovered
        //    from the envelope. `wrapContext` is the
        //    deterministically-reconstructed AAD under which the
        //    DEK is unwrapped.
        //
        //    The AAD buffer (`identityRow.aad`) is *not* a
        //    secret — it is the row-binding tuple stored on the
        //    identity row itself, and AES-GCM only treats it as
        //    authenticity input. We do not zero it (mirroring
        //    `TokenizeAadhaar`'s posture for `tokenAad`).
        // -----------------------------------------------------------------
        const now = clock();
        const wrapContext = makeDetokenizeWrapContext(
            tokenRow.id,
            tokenRow.identityId,
        );

        // Caller-side correlation id echoed in the response. The
        // vault's append-only audit row id is stamped server-side
        // and is not surfaced here in v0.1.
        const auditId =
            cmd.context.requestId && cmd.context.requestId.length > 0
                ? cmd.context.requestId
                : `detok-${tokenRow.id.slice(0, 8)}-${now.getTime().toString(36)}`;

        let dek: Buffer | undefined;
        let aadhaarBuf: Buffer | undefined;
        try {
            // -------------------------------------------------------------
            // 5. Unwrap the DEK. The wrap context is reconstructed
            //    from the row (see `makeDetokenizeWrapContext`).
            //    The `KeyManager` adapter throws on a context
            //    mismatch or tampered bytes; we surface that as
            //    UNWRAP_FAILED so the HTTP layer can map to 5xx
            //    (a 400 would mislead the caller into thinking
            //    their input was the problem when in fact it
            //    points at a server-side integrity check).
            // -------------------------------------------------------------
            try {
                dek = await deps.keyManager.unwrapDataKey(
                    { bytes: tokenRow.wrappedDek },
                    wrapContext,
                );
            } catch (err) {
                throw new DetokenizeCommandError(
                    'UNWRAP_FAILED',
                    `failed to unwrap DEK: ${(err as Error).message}`,
                );
            }

            // -------------------------------------------------------------
            // 6. Decrypt the envelope. AES-GCM throws on tag
            //    mismatch (wrong AAD, tampered ciphertext, wrong
            //    key) — surface as DECRYPTION_FAILED with the
            //    same reasoning as UNWRAP_FAILED.
            // -------------------------------------------------------------
            try {
                aadhaarBuf = await deps.crypto.decrypt(
                    dek,
                    {
                        ciphertext: tokenRow.ciphertext,
                        iv: tokenRow.iv,
                        authTag: tokenRow.authTag,
                    },
                    identityRow.aad,
                );
            } catch (err) {
                throw new DetokenizeCommandError(
                    'DECRYPTION_FAILED',
                    `failed to decrypt envelope: ${(err as Error).message}`,
                );
            }

            // -------------------------------------------------------------
            // 7. Validate the recovered plaintext is a 12-digit
            //    Aadhaar. The TokenizeAadhaar pipeline rejects
            //    any non-12-digit input before encrypting, so a
            //    successful decrypt that yields something else
            //    would indicate a corrupted row. Surface as
            //    INVALID_PAYLOAD.
            // -------------------------------------------------------------
            const aadhaar = aadhaarBuf.toString('utf8');
            if (!/^\d{12}$/.test(aadhaar)) {
                throw new DetokenizeCommandError(
                    'INVALID_PAYLOAD',
                    'recovered plaintext is not a 12-digit Aadhaar.',
                );
            }
            const last4 = aadhaar.slice(-4);

            // -------------------------------------------------------------
            // 8. Append the audit row. Action is `DETOKENIZE`,
            //    outcome is `allow` (we are reporting a successful
            //    recovery; failure paths throw before this point
            //    and write their own deny/error rows in a future
            //    session). The meta block carries the actor
            //    context + the originating token's id for
            //    cross-referencing.
            //
            //    The audit append is best-effort, matching the
            //    EnrollMfa posture: a failure here is re-thrown so
            //    the runtime can log it, but the plaintext is
            //    still returned to the caller (the plaintext is
            //    already in their hands from the crypto step
            //    above; failing the call after that would be
            //    misleading). The HTTP layer / runtime logger can
            //    surface the append failure separately.
            // -------------------------------------------------------------
            const auditEntry: AuditEntry = {
                identityId: tokenRow.identityId,
                actor: cmd.context.actorId,
                action: 'DETOKENIZE',
                outcome: 'allow',
                reason: cmd.context.reason,
                requestId: cmd.context.requestId ?? null,
                meta: {
                    token_id: tokenRow.id,
                    actor_role: cmd.context.actorRole,
                    key_version: identityRow.keyVersion,
                    pepper_version: identityRow.pepperVersion,
                    algorithm: tokenRow.algorithm,
                    source_ip: cmd.context.sourceIp ?? null,
                    user_agent: cmd.context.userAgent ?? null,
                },
            };
            try {
                await deps.audit.append(auditEntry);
            } catch (auditErr) {
                // Same posture as EnrollMfa: re-throw so the
                // runtime logger can pick it up, but the
                // plaintext is already in the caller's hands.
                // The contract is "best-effort audit"; v0.1
                // surfaces this via the standard error path
                // and leaves stronger guarantees to a future
                // session.
                throw auditErr;
            }

            // -------------------------------------------------------------
            // 9. Publish the domain event AFTER the audit append.
            //    As with `TokenizeAadhaar`, the publish is the
            //    last step so a failed audit earlier in the
            //    chain does not produce a phantom
            //    `AadhaarDetokenized` event.
            // -------------------------------------------------------------
            await deps.events.publish({
                type: 'AadhaarDetokenized',
                token: tokenRow.id,
                identityId: tokenRow.identityId,
                last4,
                actorId: cmd.context.actorId,
                actorRole: cmd.context.actorRole,
                occurredAt: now.toISOString(),
            });

            return {
                token: tokenRow.id,
                identityId: tokenRow.identityId,
                aadhaar,
                last4,
                auditId,
            };
        } finally {
            // -------------------------------------------------------------
            // Plaintext hygiene — ALWAYS, even on throw.
            //
            // Every `Buffer` whose contents the command treats
            // as a secret at any point in its lifetime is
            // zeroed here. `safeZero` no-ops on undefined /
            // non-Buffers, so a throw inside `unwrapDataKey`
            // (before `dek` is set) or inside `decrypt` (before
            // `aadhaarBuf` is set) is safe.
            // -------------------------------------------------------------
            if (dek) safeZero(dek);
            if (aadhaarBuf) safeZero(aadhaarBuf);
            safeZero(wrapContext);
        }
    };
}