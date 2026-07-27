/**
 * `POST /v1/detokenize` — HTTP surface for the {@link DetokenizeAadhaar}
 * application command (Session 5C).
 *
 * The route is the only place where the v0.1 partition between
 * application and infrastructure changes direction: the route
 * receives a JSON body, validates it, builds the application-layer
 * `DetokenizeCallerContext`, and asks the command to do the work.
 * The command itself never imports `fastify`.
 *
 * # Auth boundary
 *
 *   1. Caller must present a verified Bearer JWT — supplied by the
 *      Session 5 Phase 1 auth plugin. No token → `401`.
 *   2. The token must carry `vault:detokenize` in its `scope` claim.
 *      Otherwise → `403`.
 *   3. The JWT subject (a stable principal id) is the *trusted*
 *      `actorId`. The body's `context.actorId` is intentionally
 *      ignored if the JWT subject is present. This mirrors the
 *      invariant documented on the tokenize route: an authenticated
 *      caller cannot impersonate a different principal by rewriting
 *      the body. When the JWT subject is absent (e.g. a service
 *      credential where `subject` is empty) the body's `actorId`
 *      is used as a fallback so the audit log still has a non-empty
 *      actor.
 *
 * # Status mapping
 *
 *   - `200` — plaintext recovered, audit row appended.
 *   - `400` — JSON body failed schema validation.
 *   - `401` — missing / malformed / expired / untrusted Bearer.
 *   - `403` — token verified but missing `vault:detokenize`.
 *   - `404` — `TOKEN_NOT_FOUND` or `IDENTITY_NOT_FOUND`.
 *   - `500` — `UNWRAP_FAILED`, `DECRYPTION_FAILED`, anything else.
 *   - `503` — vault dependencies were not wired before the request
 *             arrived (race during startup).
 *
 * # Why the deps are lazy getters
 *
 *   `buildServer()` constructs the vault lazily via
 *   `createKeyManager()` / `createEventPublisher()` / `createDatabase()`.
 *   The route handlers run in the same fastify boot that registers them,
 *   so the deps may not yet be ready at `app.register` time. Each
 *   handler rebuilds the command inside the request, fetching the
 *   current deps from the server-owned getters; this keeps the
 *   command heap-isolated and matches the tokenize-route pattern.
 *
 * # Schema reconciliation notes (RESOLVED)
 *
 *   Both `TokenizeAadhaar` and `DetokenizeAadhaar` derive the wrap
 *   context from `wrap:<identityId>`. The local-dev HKDF binding
 *   therefore matches, and a tokenize → detokenize round-trip
 *   decrypts the plaintext back to the original input. The route
 *   still exercises the command plus the DB plus the auth boundary
 *   end-to-end; `tests/live-roundtrip.test.ts` covers the same flow
 *   against the bundled Postgres container.
 */
import type { FastifyInstance, FastifyPluginAsync, FastifyReply } from 'fastify';
import { z } from 'zod';

import {
    DetokenizeCommandError,
    makeDetokenizeAadhaar,
} from '../application/commands/detokenize-aadhaar.js';
import type { CryptoService } from '../application/ports/crypto.service.js';
import type { EventPublisher } from '../application/ports/event-publisher.js';
import type { KeyManager } from '../application/ports/key-manager.js';
import type { Database } from '../db/index.js';
import type { Logger } from '../logger.js';

const ActorRoleEnum = z.enum([
    'TEACHER',
    'SCHOOL_ADMIN',
    'STATE_ADMIN',
    'SUPER_ADMIN',
    'SERVICE',
]);

/**
 * `context` is largely the same shape as the tokenize route, with one
 * behavioral change: the `actorId` field is treated as a *fallback*
 * only when the JWT subject is absent. Validation here is therefore
 * mirrored against the tokenize route's contract so callers can use
 * the same client-side types.
 */
const DetokenizeContextSchema = z
    .object({
        actorId: z.string().min(1).max(128),
        actorRole: ActorRoleEnum,
        reason: z.string().min(10).max(512),
        requestId: z.string().min(1).max(128).optional(),
        sourceIp: z.string().max(64).optional(),
        userAgent: z.string().max(512).optional(),
    })
    .strict();

const DetokenizeRequestSchema = z
    .object({
        token: z.string().min(1).max(128),
        context: DetokenizeContextSchema,
    })
    .strict();

/**
 * Status mapping for {@link DetokenizeCommandError} codes. Anything
 * not in this table is treated as a 500. Deliberately small: every
 * code is documented in the command's file-level comment.
 */
const ERROR_STATUS: Record<string, number> = {
    INVALID_INPUT: 400,
    TOKEN_NOT_FOUND: 404,
    IDENTITY_NOT_FOUND: 404,
    UNWRAP_FAILED: 500,
    DECRYPTION_FAILED: 500,
    INVALID_PAYLOAD: 500,
};

/**
 * Stable, non-leaky human-readable messages keyed by error code. The
 * `null` codes do not have a stable message; the handler falls back
 * to a generic message. We never echo the underlying error's `.message`
 * to the client — it has been logged with the full detail.
 */
const ERROR_MESSAGES: Record<string, string> = {
    INVALID_INPUT: 'Request input did not satisfy the detokenization contract.',
    TOKEN_NOT_FOUND: 'The supplied token does not match any vault row.',
    IDENTITY_NOT_FOUND: 'The vault row references a missing identity row.',
    UNWRAP_FAILED: 'Vault encryption key is unavailable.',
    DECRYPTION_FAILED: 'Vault ciphertext could not be decrypted.',
    INVALID_PAYLOAD: 'Vault row has an inconsistent payload.',
};

function replyForCommandError(
    reply: FastifyReply,
    err: DetokenizeCommandError,
): void {
    const status = ERROR_STATUS[err.code] ?? 500;
    reply.code(status).send({
        error: err.code,
        message:
            ERROR_MESSAGES[err.code] ?? 'An unexpected error occurred.',
    });
}

export interface DetokenizeDeps {
    /** API version surfaced in logs and audit `meta`. */
    version: string;
    keyManager: () => KeyManager | undefined;
    crypto: () => CryptoService | undefined;
    events: () => EventPublisher | undefined;
    db: () => Database | undefined;
    logger: Logger;
}

export const detokenizeRoutes: FastifyPluginAsync<{ deps: DetokenizeDeps }> =
    async (
        app: FastifyInstance,
        { deps }: { deps: DetokenizeDeps },
    ) => {
        app.post('/v1/detokenize', async (req, reply) => {
            // Auth boundary. `requireScope` throws a 401 / 403 reply
            // if the principal is missing or lacks the scope; the
            // throw is caught by Fastify's error handler before we
            // touch any vault dependency.
            req.requireScope('vault:detokenize');

            const keyManager = deps.keyManager();
            const crypto = deps.crypto();
            const events = deps.events();
            const db = deps.db();

            if (!keyManager || !crypto || !events || !db) {
                deps.logger.error(
                    { route: 'POST /v1/detokenize' },
                    'aadhaar-vault route invoked with missing dependency',
                );
                reply.code(503).send({
                    error: 'service_unavailable',
                    message: 'Vault not ready.',
                });
                return;
            }

            const parsed = DetokenizeRequestSchema.safeParse(req.body);
            if (!parsed.success) {
                reply.code(400).send({
                    error: 'invalid_request',
                    message: 'Request body failed validation.',
                    details: parsed.error.issues.map((i) => ({
                        path: i.path.join('.'),
                        code: i.code,
                    })),
                });
                return;
            }

            const body = parsed.data;

            // The JWT subject is the trusted principal. When the
            // tokenize route uses a service principal without a
            // subject, the body's `actorId` is the fallback. This
            // is the same principal-trust policy documented on
            // `tokenize.routes.ts`.
            const verifiedSubject = req.principal?.subject;
            const actorId =
                verifiedSubject && verifiedSubject.length > 0
                    ? verifiedSubject
                    : body.context.actorId;
            const actorRole = body.context.actorRole;

            const command = makeDetokenizeAadhaar({
                keyManager,
                crypto,
                tokens: db.tokens,
                identities: db.identities,
                audit: db.audit,
                events,
            });

            try {
                const result = await command({
                    token: body.token,
                    context: {
                        actorId,
                        actorRole,
                        reason: body.context.reason,
                        requestId:
                            body.context.requestId ?? req.id ?? undefined,
                        sourceIp: body.context.sourceIp ?? req.ip,
                        userAgent:
                            body.context.userAgent ??
                            (req.headers['user-agent']
                                ? String(req.headers['user-agent'])
                                : undefined),
                    },
                });

                reply.code(200).send({
                    token: result.token,
                    identityId: result.identityId,
                    aadhaar: result.aadhaar,
                    last4: result.last4,
                    auditId: result.auditId,
                });
            } catch (err) {
                if (err instanceof DetokenizeCommandError) {
                    deps.logger.info(
                        {
                            errCode: err.code,
                            actorId,
                            actorRole,
                            token: body.token,
                            reqId: req.id,
                        },
                        'aadhaar-vault detokenize rejected',
                    );
                    replyForCommandError(reply, err);
                    return;
                }
                deps.logger.error(
                    { err, reqId: req.id },
                    'aadhaar-vault detokenize unexpected error',
                );
                throw err;
            }
        });
    };

export default detokenizeRoutes;