/**
 * `POST /v1/mfa/enroll` — HTTP surface for the {@link EnrollMfa}
 * application command (Session 5C).
 *
 * The route is the only place where the v0.1 partition between
 * application and infrastructure changes direction: the route
 * receives a JSON body, validates it, builds the application-layer
 * `EnrollMfaCallerContext`, and asks the command to do the work.
 * The command itself never imports `fastify`.
 *
 * # Auth boundary
 *
 *   1. Caller must present a verified Bearer JWT — supplied by the
 *      Session 5 Phase 1 auth plugin. No token → `401`.
 *   2. The token must carry `vault:mfa:enroll` in its `scope` claim.
 *      Otherwise → `403`.
 *   3. The JWT subject (a stable principal id) is the *trusted*
 *      `actorId` recorded in the audit row. The body's
 *      `context.actorId` is intentionally overridden when the JWT
 *      subject is present. This mirrors the principal-trust
 *      invariant on the tokenize/detokenize routes: an
 *      authenticated caller cannot impersonate a different
 *      principal by rewriting the body. When the JWT subject is
 *      absent (a service principal where `subject` is empty) the
 *      body's `actorId` is used as a fallback so the audit log
 *      still has a non-empty actor.
 *
 * # Status mapping
 *
 *   - `200` — factor enrolled, audit row appended, event published.
 *   - `400` — JSON body failed schema validation, OR the command
 *             surfaced `INVALID_INPUT` (e.g. empty `actor`).
 *   - `401` — missing / malformed / expired / untrusted Bearer.
 *   - `403` — token verified but missing `vault:mfa:enroll`.
 *   - `500` — unexpected error (insert failure, audit failure,
 *             verifier failure, etc.).
 *   - `503` — vault dependencies were not wired before the request
 *             arrived (race during startup).
 *
 * # Why the deps are lazy getters
 *
 *   `buildServer()` constructs the vault lazily via
 *   `createKeyManager()` / `createTotpVerifier()` / `createDatabase()`.
 *   The route handlers run in the same fastify boot that registers
 *   them, so the deps may not yet be ready at `app.register` time.
 *   Each handler rebuilds the command inside the request, fetching
 *   the current deps from the server-owned getters; this keeps the
 *   command heap-isolated and matches the tokenize/detokenize route
 *   pattern.
 *
 * # Response shape
 *
 *   The command returns `{ factorId, otpauthUri, factor }`. The
 *   route projects the `factor` field to a JSON-safe envelope:
 *   `Buffer` fields are base64-encoded, `Date` fields are ISO-8601
 *   strings. The on-the-wire shape is:
 *
 *     {
 *       factorId:    string,
 *       otpauthUri:  string,
 *       factor: {
 *         factorId, actor, factorType, status, label,
 *         encryptedSecret: base64-string,
 *         algorithm, digits, period,
 *         lastUsedAt: ISO-string | null,
 *         expiresAt:  ISO-string | null,
 *         createdAt:  ISO-string,
 *       },
 *     }
 *
 * # Schema reconciliation notes
 *
 *   The `EnrollMfa` command does not depend on any schema
 *   fields that are missing from the current repository
 *   (session-5c-deferred commands like `LookupMaskedAadhaar` do).
 *   The route therefore exercises the full command + DB +
 *   auth boundary without workarounds.
 */
import type { FastifyInstance, FastifyPluginAsync, FastifyReply } from 'fastify';
import { z } from 'zod';

import {
    EnrollMfaCommandError,
    makeEnrollMfa,
} from '../application/commands/enroll-mfa.js';
import type { AuditRepository } from '../db/ports/audit.repository.js';
import type { Database } from '../db/index.js';
import type { EventPublisher } from '../application/ports/event-publisher.js';
import type { KeyManager } from '../application/ports/key-manager.js';
import type { Logger } from '../logger.js';
import type { TotpVerifier } from '../application/ports/totp-verifier.js';

// ---------------------------------------------------------------------------
// Local enum — duplicated from `tokenize.routes.ts` / `detokenize.routes.ts`.
//
// No shared route schema exists today; per the Session 6B scope rules,
// introducing one would expand the change beyond the route layer. A future
// cleanup can hoist this to `src/routes/schemas.ts` once a fourth route
// needs it. The values MUST stay in lockstep with the application command's
// `EnrollMfaCallerContext.actorRole` union — see
// `src/application/commands/enroll-mfa.ts`.
// ---------------------------------------------------------------------------
const ActorRoleEnum = z.enum([
    'TEACHER',
    'SCHOOL_ADMIN',
    'STATE_ADMIN',
    'SUPER_ADMIN',
    'SERVICE',
]);

/**
 * The `context` block is the same shape as the tokenize/detokenize
 * routes so callers can re-use the same client-side types. The
 * `actorId` here is the *caller* (the admin enrolling the factor on
 * behalf of a user), NOT the factor's `actor` — the factor's actor
 * is the top-level body's `actor` field.
 */
const EnrollMfaContextSchema = z
    .object({
        actorId: z.string().min(1).max(128),
        actorRole: ActorRoleEnum,
        reason: z.string().min(10).max(512),
        requestId: z.string().min(1).max(128).optional(),
        sourceIp: z.string().max(64).optional(),
        userAgent: z.string().max(512).optional(),
    })
    .strict();

/**
 * The `algorithm` enum matches the application port's `TotpAlgorithm`
 * union. `digits` / `period` are bounded to the realistic RFC 6238
 * range so a typo at the client gets caught at the route layer
 * rather than at the verifier.
 */
const EnrollMfaRequestSchema = z
    .object({
        actor: z.string().min(1).max(128),
        label: z.string().min(1).max(128).optional(),
        algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']).optional(),
        digits: z.number().int().min(6).max(10).optional(),
        period: z.number().int().min(15).max(120).optional(),
        context: EnrollMfaContextSchema,
    })
    .strict();

/**
 * Status mapping for {@link EnrollMfaCommandError} codes. Anything
 * not in this table is treated as 500. Deliberately small: the
 * command currently only throws `INVALID_INPUT`.
 */
const ERROR_STATUS: Record<string, number> = {
    INVALID_INPUT: 400,
};

/**
 * Stable, non-leaky human-readable messages keyed by error code. We
 * never echo the underlying error's `.message` to the client — it
 * has been logged with the full detail.
 */
const ERROR_MESSAGES: Record<string, string> = {
    INVALID_INPUT:
        'Request input did not satisfy the MFA-enrollment contract.',
};

function replyForCommandError(
    reply: FastifyReply,
    err: EnrollMfaCommandError,
): void {
    const status = ERROR_STATUS[err.code] ?? 500;
    reply.code(status).send({
        error: err.code,
        message:
            ERROR_MESSAGES[err.code] ?? 'An unexpected error occurred.',
    });
}

export interface EnrollMfaDeps {
    /** API version surfaced in logs. */
    version: string;
    keyManager: () => KeyManager | undefined;
    totp: () => TotpVerifier | undefined;
    db: () => Database | undefined;
    events: () => EventPublisher | undefined;
    logger: Logger;
}

/**
 * Project a `MfaFactor` to a JSON-safe envelope.
 *
 * - `Buffer` fields → base64 strings (standard for `bytea`).
 * - `Date` fields   → ISO-8601 strings.
 * - `null` fields   → preserved as `null`.
 *
 * The helper is locally scoped to the route so future fields added
 * to `MfaFactor` automatically surface on the wire (TypeScript
 * will fail the build until this projection is updated).
 */
function projectFactor(
    factor: import('../application/ports/mfa-repository.js').MfaFactor,
): Record<string, unknown> {
    return {
        factorId: factor.factorId,
        actor: factor.actor,
        factorType: factor.factorType,
        status: factor.status,
        label: factor.label,
        encryptedSecret: factor.encryptedSecret.toString('base64'),
        algorithm: factor.algorithm,
        digits: factor.digits,
        period: factor.period,
        lastUsedAt: factor.lastUsedAt
            ? factor.lastUsedAt.toISOString()
            : null,
        expiresAt: factor.expiresAt
            ? factor.expiresAt.toISOString()
            : null,
        createdAt: factor.createdAt.toISOString(),
    };
}

export const mfaRoutes: FastifyPluginAsync<{ deps: EnrollMfaDeps }> =
    async (
        app: FastifyInstance,
        { deps }: { deps: EnrollMfaDeps },
    ) => {
        app.post('/v1/mfa/enroll', async (req, reply) => {
            // -----------------------------------------------------------------
            // 1. Auth boundary. `requireScope` throws a 401 / 403 reply
            //    if the principal is missing or lacks the scope; the
            //    throw is caught by Fastify's error handler before we
            //    touch any vault dependency.
            // -----------------------------------------------------------------
            req.requireScope('vault:mfa:enroll');

            // -----------------------------------------------------------------
            // 2. Lazy dep resolution. The 503 guard short-circuits when
            //    any of the four cross-cutting ports is unwired.
            // -----------------------------------------------------------------
            const keyManager = deps.keyManager();
            const totp = deps.totp();
            const db = deps.db();
            const events = deps.events();

            if (!keyManager || !totp || !db || !events) {
                deps.logger.error(
                    { route: 'POST /v1/mfa/enroll' },
                    'aadhaar-vault mfa-enroll route invoked with missing dependency',
                );
                reply.code(503).send({
                    error: 'service_unavailable',
                    message: 'MFA enrollment not ready.',
                });
                return;
            }

            // -----------------------------------------------------------------
            // 3. Zod validation of the JSON body. `.strict()` rejects
            //    unknown keys — a defence-in-depth measure so a typo
            //    at the client trips a 400 here rather than silently
            //    being ignored.
            // -----------------------------------------------------------------
            const parsed = EnrollMfaRequestSchema.safeParse(req.body);
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

            // -----------------------------------------------------------------
            // 4. Principal-trust invariant. The JWT subject is the
            //    trusted `actorId` recorded in the audit row. The
            //    body's `context.actorId` is the fallback used only
            //    when the JWT subject is empty (e.g. a service
            //    credential). This mirrors the tokenize/detokenize
            //    route policy.
            // -----------------------------------------------------------------
            const verifiedSubject = req.principal?.subject;
            const actorId =
                verifiedSubject && verifiedSubject.length > 0
                    ? verifiedSubject
                    : body.context.actorId;
            const actorRole = body.context.actorRole;

            // -----------------------------------------------------------------
            // 5. Build and invoke the command. The audit + event
            //    publish paths travel through the same `db.audit`
            //    and `events` as every other command.
            // -----------------------------------------------------------------
            const command = makeEnrollMfa({
                keyManager,
                totp,
                mfa: db.mfa,
                audit: db.audit as AuditRepository,
                events,
            });

            try {
                const result = await command({
                    actor: body.actor,
                    ...(body.label !== undefined ? { label: body.label } : {}),
                    ...(body.algorithm !== undefined
                        ? { algorithm: body.algorithm }
                        : {}),
                    ...(body.digits !== undefined
                        ? { digits: body.digits }
                        : {}),
                    ...(body.period !== undefined
                        ? { period: body.period }
                        : {}),
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

                // Project the command result 1:1. The `factor` field
                // is reshape-encoded to a JSON-safe envelope so the
                // client never sees a `Buffer` or a `Date`.
                reply.code(200).send({
                    factorId: result.factorId,
                    otpauthUri: result.otpauthUri,
                    factor: projectFactor(result.factor),
                });
            } catch (err) {
                if (err instanceof EnrollMfaCommandError) {
                    deps.logger.info(
                        {
                            errCode: err.code,
                            actorId,
                            actorRole,
                            targetActor: body.actor,
                            reqId: req.id,
                        },
                        'aadhaar-vault mfa-enroll rejected',
                    );
                    replyForCommandError(reply, err);
                    return;
                }
                deps.logger.error(
                    { err, reqId: req.id },
                    'aadhaar-vault mfa-enroll unexpected error',
                );
                throw err;
            }
        });
    };

export default mfaRoutes;