/**
 * POST `/v1/tokenize` route (AADHAAR_VAULT_FREE_ARCHITECTURE.md §6.1, §6.2).
 *
 * This is the only write path that produces a vault token. It is the
 * narrow compile-time seam between the outside world (JSON over HTTP)
 * and the application-layer `TokenizeAadhaar` command. The route is
 * intentionally thin:
 *
 *   - Parse + validate the request body with Zod. Anything malformed
 *     never reaches the command.
 *   - Stitch a `TokenizeCallerContext` from explicit fields + the live
 *     Fastify request (`request.id`, `request.ip`, `user-agent`).
 *   - Invoke the command via the factory in `application/commands/`.
 *   - Translate `TokenizeCommandError.code` → HTTP status; never echo
 *     raw `err.message` into the response.
 *
 * # Authentication boundary
 *
 * Authentication & authorization are scoped for a later session. The
 * route currently reads `actorId` / `actorRole` from the request body,
 * which is acceptable ONLY behind an auth-bearing gateway that strips
 * or overrides those fields. The TODO marker in the handler flags the
 * gap; remove it once an auth plugin lands.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';

import type { Database } from '../db/index.js';
import type { Logger } from '../logger.js';
import type { CryptoService } from '../application/ports/crypto.service.js';
import type { EventPublisher } from '../application/ports/event-publisher.js';
import type { KeyManager } from '../application/ports/key-manager.js';
import type { TransactionalVaultWriter } from '../application/ports/transactional-vault-writer.js';
import {
  TokenizeCommandError,
  makeTokenizeAadhaar,
} from '../application/commands/tokenize-aadhaar.js';

/* -------------------------------------------------------------------- *
 * Zod schema                                                          *
 * -------------------------------------------------------------------- */

const IdentityTypeEnum = z.enum(['AADHAAR', 'BIRTH_CERTIFICATE']);

/** Minimal actor descriptor. Auth middleware (later session) will
 *  inject this from the verified bearer token; for now it travels in
 *  the body. The enum string-set MUST mirror `TokenizeCallerContext`
 *  in `application/commands/tokenize-aadhaar.ts` exactly — a mismatch
 *  here would only be caught when the command throws on a narrower
 *  type assertion. Keep them in sync. */
const ActorRoleEnum = z.enum([
  'TEACHER',
  'SCHOOL_ADMIN',
  'STATE_ADMIN',
  'SUPER_ADMIN',
  'SERVICE',
]);

const TokenizeContextSchema = z
  .object({
    actorId: z
      .string({ required_error: 'context.actorId is required' })
      .min(1)
      .max(128),
    actorRole: ActorRoleEnum,
    /** Free-text justification. Min length blocks empty-string laziness. */
    reason: z
      .string({ required_error: 'context.reason is required' })
      .min(10)
      .max(512),
    requestId: z.string().min(1).max(128).optional(),
    sourceIp: z.string().max(64).optional(),
    userAgent: z.string().max(512).optional(),
  })
  .strict();

/** Body schema. `.strict()` rejects unknown keys so the contract is
 *  additive — clients cannot smuggle new fields in to be silently
 *  ignored. */
const TokenizeRequestSchema = z
  .object({
    raw: z
      .string({ required_error: 'raw is required' })
      .min(1)
      // Hard cap matches Fastify's bodyLimit (64 KiB) with headroom;
      // an Aadhaar is 12 digits so anything over 32 chars is junk.
      .max(32),
    type: IdentityTypeEnum,
    context: TokenizeContextSchema,
  })
  .strict();

type TokenizeRequest = z.infer<typeof TokenizeRequestSchema>;

/* -------------------------------------------------------------------- *
 * Error mapping                                                        *
 * -------------------------------------------------------------------- */

/**
 * HTTP status + stable error code per `TokenizeCommandError.code`.
 *
 * Codes MUST match the architecture doc; adding a new code requires
 * extending this table. Each code maps to exactly one status so
 * observability dashboards can match response.status ↔ error.code.
 */
const ERROR_STATUS: Record<string, number> = {
  INVALID_INPUT: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  PEPPER_MISMATCH: 422,
  RATE_LIMIT: 429,
  INTERNAL: 500,
};

function replyForCommandError(
  reply: import('fastify').FastifyReply,
  err: TokenizeCommandError,
): void {
  const status = ERROR_STATUS[err.code] ?? 500;
  // We intentionally do not echo `err.message` to the client — some
  // messages may contain identifiers or operator notes; the body only
  // exposes the stable architectural code.
  reply.code(status).send({
    error: err.code,
      message:
        status >= 500
          ? 'An unexpected error occurred.'
          : err.code === 'INVALID_INPUT'
            ? 'Request input did not satisfy the tokenization contract.'
            : err.code === 'UNAUTHORIZED'
              ? 'Missing or invalid credentials.'
              : err.code === 'FORBIDDEN'
                ? 'Caller is not allowed to tokenize this identity.'
                : err.code === 'PEPPER_MISMATCH'
                  ? 'Identity does not match the active pepper.'
                  : err.code === 'RATE_LIMIT'
                    ? 'Too many tokenization requests; retry later.'
                    : 'Request could not be processed.',
  });
}

/* -------------------------------------------------------------------- *
 * Plugin dependencies                                                  *
 * -------------------------------------------------------------------- */

export interface TokenizeDeps {
  version: string;
  /** Resolves deps lazily so Fastify plugins are fully wired by the
   *  time the route first runs. Each getter re-reads `app.*` on every
   *  call; that is cheap and keeps test overrides honest. */
  keyManager: () => KeyManager | undefined;
  crypto: () => CryptoService | undefined;
  vaultWriter: () => TransactionalVaultWriter | undefined;
  events: () => EventPublisher | undefined;
  db: () => Database | undefined;
  logger: Logger;
}

export const tokenizeRoutes: FastifyPluginAsync<{ deps: TokenizeDeps }> = async (
  app: FastifyInstance,
  { deps },
) => {
  app.post('/v1/tokenize', async (req, reply) => {
    /* ---------------- dependency guard ---------------- */
    const keyManager = deps.keyManager();
    const crypto = deps.crypto();
    const vaultWriter = deps.vaultWriter();
    const events = deps.events();
    const db = deps.db();

    if (!keyManager || !crypto || !vaultWriter || !events || !db) {
      deps.logger.error(
        { route: 'POST /v1/tokenize' },
        'aadhaar-vault route invoked with missing dependency',
      );
      reply
        .code(503)
        .send({ error: 'service_unavailable', message: 'Vault not ready.' });
      return;
    }

    /* ---------------- request validation ---------------- */
    const parsed = TokenizeRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      // 400 with a stable shape. We strip the verbose zod issues to
      // a `details` array so logs stay grep-able without echoing
      // third-party path strings to the public response.
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

    const body: TokenizeRequest = parsed.data;

    /* ---------------- auth boundary (TODO) ----------------
     * When auth middleware lands, replace the `body.context.actorId`
     * / `actorRole` reads with values pulled from the verified bearer
     * token. The downstream audit row will then carry the verified
     * caller identity rather than a client-asserted one. Until then
     * the route MUST sit behind a trusted upstream gateway that
     * strips these fields. */
    const verifiedCaller = body.context;

    const command = makeTokenizeAadhaar({
      keyManager,
      crypto,
      vaultWriter,
      events,
    });

    let result;
    try {
      result = await command({
        raw: body.raw,
        type: body.type,
        context: {
          actorId: verifiedCaller.actorId,
          actorRole: verifiedCaller.actorRole,
          reason: verifiedCaller.reason,
          requestId: verifiedCaller.requestId ?? req.id,
          sourceIp: verifiedCaller.sourceIp ?? req.ip,
          userAgent:
            verifiedCaller.userAgent ??
            (req.headers['user-agent'] as string | undefined),
        },
      });
    } catch (err) {
      if (err instanceof TokenizeCommandError) {
        deps.logger.info(
          {
            err,
            errCode: err.code,
            actorId: verifiedCaller.actorId,
            type: body.type,
            reqId: req.id,
          },
          'aadhaar-vault tokenize rejected',
        );
        replyForCommandError(reply, err);
        return;
      }
      // Unknown error — let the central error handler in server.ts
      // format the 500. We re-throw so its log line carries the
      // request scope.
      deps.logger.error(
        { err, reqId: req.id },
        'aadhaar-vault tokenize unexpected error',
      );
      throw err;
    }

    /* ---------------- success response ---------------- */
      reply.code(201).send({
        token: result.token,
        last4: result.last4,
        tokenType: result.tokenType,
        auditId: result.auditId,
        identityId: result.identityId,
        keyVersion: result.keyVersion,
      });
      return;
  });
};

export default tokenizeRoutes;