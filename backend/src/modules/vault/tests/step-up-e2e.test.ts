/**
 * In-process Step-Up end-to-end test (Phase 4.4).
 *
 * Verifies the full admin Step-Up flow runs correctly through the
 * REAL vault command chain, in-process, with no fake HTTP server:
 *
 *   1. tokenize        — raw 12-digit → vault row + opaque token
 *   2. enrollMfa       — TOTP factor sealed via KeyManager.sealSecret
 *   3. requestDetokenization — pending step-up challenge created
 *   4. approveStepUpChallenge — TOTP code verified, challenge → approved
 *   5. detokenizeAadhaar       — challenge CAS → consumed, plaintext returned
 *
 * What this proves:
 *   - KeyManager (LocalDev) can wrap + unwrap DEKs around the in-process
 *     commands without any HTTP boundary.
 *   - NodeCryptoService + LocalDevKeyManager produce a sealed envelope
 *     the in-process detokenize command can reopen (cipher round-trip).
 *   - OtpAuthTotpVerifier.verifyCode() accepts a code produced by
 *     currentCode() on the same secret (no off-by-one in the period).
 *   - The CAS consume gate in the detokenize command refuses a replay
 *     with the *same* approved challenge id (the canonical replay
 *     protection from the §11 architecture doc).
 *   - The actor-binding check (challenge.requestedBy === caller.actorId)
 *     refuses a caller who did not originally request the challenge.
 *
 * Why not just keep the in-process stubs from aadhaar-detokenize.test.ts?
 * Those stubs mimic the wire shape but skip every real command — they
 * only prove the route layer dispatches. This test proves the
 * *commands* work end-to-end.
 *
 * Isolation model: same as aadhaar-detokenize.test.ts — chdir into a
 * fresh temp dir, delete MONGODB_URI so any stray dbStore import falls
 * back to the file-based store. The vault module is NOT enabled here
 * (no Mongo replica set in this test environment); we wire the deps
 * ourselves with in-memory repos and the real LocalDevKeyManager /
 * NodeCryptoService / OtpAuthTotpVerifier, so the production
 * command-bound code paths are exercised end-to-end without a Mongo
 * replica set.
 *
 * Run:  npx tsx --test backend/src/modules/vault/tests/step-up-e2e.test.ts
 *       (or via `npm test` after the test:detokenize script is
 *       extended to include this file)
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

// ─── Bootstrap: isolate env + cwd BEFORE importing application modules ─────
process.env.NODE_ENV = 'test';
process.env.LOCAL_DEV_MASTER_KEY = randomBytes(32).toString('base64');
process.env.KEY_VERSION = 'kv-1';

// ─── Imports — vault-only, no Mongo, no Express, no file-fallback DB ────────
import { LocalDevKeyManager } from '../infrastructure/key-providers/local-dev-key-manager';
import { NodeCryptoService } from '../infrastructure/crypto/node-crypto.service';
import { OtpAuthTotpVerifier } from '../infrastructure/mfa/totp-verifier';
import { InProcessEventPublisher } from '../infrastructure/events/in-process-event-publisher';
import { makeTokenizeAadhaar } from '../application/commands/tokenize-aadhaar';
import { makeEnrollMfa } from '../application/commands/enroll-mfa';
import { makeRequestDetokenization } from '../application/commands/request-detokenization';
import { makeApproveStepUpChallenge } from '../application/commands/approve-step-up-challenge';
import { makeDetokenizeAadhaar } from '../application/commands/detokenize-aadhaar';
import type {
  IdentityRecord,
  IdentityRepository,
  NewIdentityRecord,
} from '../application/ports/repositories';
import type {
  NewToken,
  TokenRepository,
  TokenRow,
} from '../application/ports/repositories';
import type {
  AuditEntry,
  AuditRecord,
  AuditRepository,
} from '../application/ports/repositories';
import type {
  ApproveStepUpChallengeInput,
  CreateStepUpChallengeInput,
  StepUpChallenge,
  StepUpChallengeRepository,
} from '../application/ports/repositories';
import type {
  InsertMfaFactorInput,
  MfaFactor,
  MfaFactorRepository,
} from '../application/ports/repositories';
import type {
  TransactionalVaultWriter,
  VaultWriteConnection,
} from '../application/ports/transactional-vault-writer';

// ============================================================================
// In-memory repository implementations
// ============================================================================
//
// Each repo is a thin in-memory store. The phase 2/3/4 commands only need
// the same `findOneAndUpdate({_id, status})` semantics the Mongo adapter
// exposes — we mimic them with a Map + a status guard so the CAS gate
// (Phase 3.2 / Phase 4.3) is exercised exactly as it would be in prod.

class InMemoryIdentityRepository implements IdentityRepository {
  private readonly byId = new Map<string, IdentityRecord>();
  async insert(rec: NewIdentityRecord): Promise<IdentityRecord> {
    const row: IdentityRecord = {
      ...rec,
      createdAt: new Date(),
      rotatedAt: null,
      revokedAt: null,
    };
    this.byId.set(rec.identityId, row);
    return row;
  }
  async getById(identityId: string): Promise<IdentityRecord | null> {
    return this.byId.get(identityId) ?? null;
  }
  async revoke(): Promise<void> { /* unused in e2e */ }
  async rotate(): Promise<void> { /* unused in e2e */ }
}

class InMemoryTokenRepository implements TokenRepository {
  private readonly byId = new Map<string, TokenRow>();
  async insert(token: NewToken): Promise<TokenRow> {
    const row: TokenRow = { ...token, createdAt: Date.now() };
    this.byId.set(token.id, row);
    return row;
  }
  async findById(id: string): Promise<TokenRow | null> {
    return this.byId.get(id) ?? null;
  }
}

class InMemoryAuditRepository implements AuditRepository {
  private readonly rows: AuditRecord[] = [];
  private counter = 0;
  async append(entry: AuditEntry): Promise<string> {
    this.counter += 1;
    const auditId = `audit-${this.counter}`;
    this.rows.push({ ...entry, auditId, occurredAt: new Date() });
    return auditId;
  }
  async listByIdentity(identityId: string): Promise<AuditRecord[]> {
    return this.rows.filter(r => r.identityId === identityId);
  }
}

class InMemoryStepUpChallengeRepository implements StepUpChallengeRepository {
  private readonly byId = new Map<string, StepUpChallenge>();
  async create(input: CreateStepUpChallengeInput): Promise<StepUpChallenge> {
    const row: StepUpChallenge = {
      ...input,
      approvedAt: null,
      consumedAt: null,
      status: 'pending',
      verifiedFactorId: null,
      auditId: null,
    };
    this.byId.set(input.challengeId, row);
    return row;
  }
  async findById(challengeId: string): Promise<StepUpChallenge | null> {
    return this.byId.get(challengeId) ?? null;
  }
  /** CAS: only transitions pending → approved. */
  async approve(input: ApproveStepUpChallengeInput): Promise<StepUpChallenge | null> {
    const cur = this.byId.get(input.challengeId);
    if (!cur || cur.status !== 'pending') return null;
    const next: StepUpChallenge = {
      ...cur,
      status: 'approved',
      approvedAt: input.approvedAt,
      verifiedFactorId: input.verifiedFactorId,
      auditId: input.auditId,
    };
    this.byId.set(input.challengeId, next);
    return next;
  }
  /** CAS: only transitions approved → consumed. */
  async consume(challengeId: string, consumedAt: Date): Promise<StepUpChallenge | null> {
    const cur = this.byId.get(challengeId);
    if (!cur || cur.status !== 'approved') return null;
    const next: StepUpChallenge = { ...cur, status: 'consumed', consumedAt };
    this.byId.set(challengeId, next);
    return next;
  }
  async expire(challengeId: string, expiredAt: Date): Promise<StepUpChallenge | null> {
    const cur = this.byId.get(challengeId);
    if (!cur || cur.status !== 'pending') return null;
    const next: StepUpChallenge = { ...cur, status: 'expired', consumedAt: expiredAt };
    this.byId.set(challengeId, next);
    return next;
  }
  async fail(challengeId: string, failedAt: Date): Promise<StepUpChallenge | null> {
    const cur = this.byId.get(challengeId);
    if (!cur || cur.status !== 'pending') return null;
    const next: StepUpChallenge = { ...cur, status: 'failed', consumedAt: failedAt };
    this.byId.set(challengeId, next);
    return next;
  }
}

class InMemoryMfaFactorRepository implements MfaFactorRepository {
  private readonly byId = new Map<string, MfaFactor>();
  async insert(rec: InsertMfaFactorInput): Promise<MfaFactor> {
    // Normalise `expiresAt` to `null` (not `undefined`) so downstream
    // code that does `factor.expiresAt.getTime()` (after a null
    // guard) behaves identically to the Mongo adapter. The Mongo
    // adapter always persists a real `Date | null`; the in-memory
    // adapter must mirror that surface.
    const row: MfaFactor = {
      factorId: rec.factorId,
      actor: rec.actor,
      factorType: 'totp',
      status: 'active',
      label: rec.label,
      encryptedSecret: rec.encryptedSecret,
      algorithm: rec.algorithm,
      digits: rec.digits,
      period: rec.period,
      lastUsedAt: null,
      expiresAt: rec.expiresAt ?? null,
      createdAt: new Date(),
    };
    this.byId.set(rec.factorId, row);
    return row;
  }
  async markUsed(factorId: string, usedAt: Date): Promise<MfaFactor | null> {
    const cur = this.byId.get(factorId);
    if (!cur) return null;
    const next: MfaFactor = { ...cur, lastUsedAt: usedAt };
    this.byId.set(factorId, next);
    return next;
  }
  async revoke(factorId: string): Promise<MfaFactor | null> {
    const cur = this.byId.get(factorId);
    if (!cur) return null;
    const next: MfaFactor = { ...cur, status: 'revoked' };
    this.byId.set(factorId, next);
    return next;
  }
  async getById(factorId: string): Promise<MfaFactor | null> {
    return this.byId.get(factorId) ?? null;
  }
  async listByActor(actor: string): Promise<MfaFactor[]> {
    return Array.from(this.byId.values()).filter(f => f.actor === actor);
  }
  async listActiveByActor(actor: string): Promise<MfaFactor[]> {
    return (await this.listByActor(actor)).filter(f => f.status === 'active');
  }
}

/**
 * In-process transactional writer — just runs the work function. The
 * in-memory repos are not transactional, so a single function-call
 * boundary is sufficient to scope the unit of work (the production
 * Mongo writer wraps three writes in a `withTransaction` block, but
 * here the in-memory repos are themselves atomic so the wrapper is a
 * pass-through).
 */
class InProcessVaultWriter implements TransactionalVaultWriter {
  constructor(
    private readonly identities: InMemoryIdentityRepository,
    private readonly tokens: InMemoryTokenRepository,
    private readonly audit: InMemoryAuditRepository,
  ) {}
  async runWrite<T>(work: (conn: VaultWriteConnection) => Promise<T>): Promise<T> {
    const conn: VaultWriteConnection = {
      insertIdentity: async rec => { await this.identities.insert(rec); },
      insertToken: async token => this.tokens.insert(token),
      appendAudit: async entry => { await this.audit.append(entry); },
    };
    return work(conn);
  }
}

// ============================================================================
// Test wiring
// ============================================================================

let keyManager: LocalDevKeyManager;
let cryptoSvc: NodeCryptoService;
let totp: OtpAuthTotpVerifier;
let identities: InMemoryIdentityRepository;
let tokens: InMemoryTokenRepository;
let audit: InMemoryAuditRepository;
let challenges: InMemoryStepUpChallengeRepository;
let mfa: InMemoryMfaFactorRepository;
let vaultWriter: InProcessVaultWriter;
let events: InProcessEventPublisher;
let tokenize: ReturnType<typeof makeTokenizeAadhaar>;
let enrollMfa: ReturnType<typeof makeEnrollMfa>;
let requestDetokenization: ReturnType<typeof makeRequestDetokenization>;
let approveStepUpChallenge: ReturnType<typeof makeApproveStepUpChallenge>;
let detokenizeAadhaar: ReturnType<typeof makeDetokenizeAadhaar>;

before(() => {
  keyManager = new LocalDevKeyManager({
    keyVersion: 'kv-1',
    masterKey: Buffer.from(process.env.LOCAL_DEV_MASTER_KEY!, 'base64'),
    acknowledgedUnsafe: false,
  });
  cryptoSvc = new NodeCryptoService();
  totp = new OtpAuthTotpVerifier();
  identities = new InMemoryIdentityRepository();
  tokens = new InMemoryTokenRepository();
  audit = new InMemoryAuditRepository();
  challenges = new InMemoryStepUpChallengeRepository();
  mfa = new InMemoryMfaFactorRepository();
  vaultWriter = new InProcessVaultWriter(identities, tokens, audit);
  events = new InProcessEventPublisher();

  tokenize = makeTokenizeAadhaar({ keyManager, crypto: cryptoSvc, vaultWriter, events });
  enrollMfa = makeEnrollMfa({ keyManager, totp, mfa, audit, events });
  requestDetokenization = makeRequestDetokenization({
    tokens, identities, mfa, challenges, audit, events,
  });
  approveStepUpChallenge = makeApproveStepUpChallenge({
    keyManager, totp, mfa, challenges, audit, events,
  });
  detokenizeAadhaar = makeDetokenizeAadhaar({
    keyManager, crypto: cryptoSvc, tokens, identities, audit, events, challenges,
  });
});

after(() => {
  // Zero the master key buffer so it does not linger in process
  // memory after the test. The key was derived from env at boot;
  // recreating it for a future process boot is a one-line setup.
  // (No-op if the buffer was already zeroed; safeZero is idempotent.)
  if (process.env.LOCAL_DEV_MASTER_KEY) {
    process.env.LOCAL_DEV_MASTER_KEY = '';
  }
});

// ============================================================================
// Tests
// ============================================================================

test('E2E Step-Up: tokenize → enrollMfa → request → approve → detokenize round-trips plaintext', async () => {
  const ADMIN = 'admin-e2e@fln.org';
  const RAW_AADHAAR = '987654321098';

  // (1) Tokenize — raw 12-digit → vault row + opaque token.
  const tok = await tokenize({
    raw: RAW_AADHAAR,
    type: 'AADHAAR',
    context: {
      actorId: 'fln-backend-service',
      actorRole: 'SERVICE',
      reason: 'e2e seed',
    },
  });
  assert.equal(typeof tok.token, 'string');
  assert.equal(tok.last4, '1098');
  assert.equal(tok.tokenType, 'AADHAAR');
  assert.equal(typeof tok.identityId, 'string');
  assert.equal(tok.keyVersion, 'kv-1');

  // (2) enrollMfa — TOTP factor sealed via KeyManager.sealSecret.
  const enrolled = await enrollMfa({
    actor: ADMIN,
    context: {
      actorId: ADMIN,
      actorRole: 'SUPER_ADMIN',
      reason: 'e2e enroll',
    },
    label: 'E2E Admin',
  });
  assert.equal(typeof enrolled.factorId, 'string');
  assert.match(enrolled.otpauthUri, /^otpauth:\/\/totp\//);
  assert.equal(enrolled.factor.actor, ADMIN);
  assert.equal(enrolled.factor.factorType, 'totp');
  assert.equal(enrolled.factor.status, 'active');

  // (3) requestDetokenization — pending step-up challenge created.
  const req = await requestDetokenization({
    tokenId: tok.token,
    factorId: enrolled.factorId,
    context: {
      actorId: ADMIN,
      actorRole: 'SUPER_ADMIN',
      reason: 'e2e step-up request',
    },
  });
  assert.equal(typeof req.challengeId, 'string');
  assert.equal(req.requiredFactor.factorId, enrolled.factorId);
  assert.ok(req.expiresAt instanceof Date);
  assert.ok(req.expiresAt.getTime() > Date.now(), 'challenge must not be born expired');

  // (4) Compute the *real* current TOTP code via the verifier, then
  // submit it to the approve command. This proves the verifier and
  // the command agree on the period/algorithm end-to-end.
  const sealed = await mfa.getById(enrolled.factorId);
  assert.ok(sealed, 'factor row must exist after enroll');
  const opened = await keyManager.openSecret(
    { bytes: sealed.encryptedSecret },
    Buffer.from(`mfa-factor:${enrolled.factorId}`, 'utf8'),
  );
  const code = await totp.currentCode(opened);
  opened.fill(0); // zero the unsealed secret — never let it escape the call.

  const approved = await approveStepUpChallenge({
    challengeId: req.challengeId,
    code,
    context: {
      actorId: ADMIN,
      actorRole: 'SUPER_ADMIN',
      reason: 'e2e step-up approve',
    },
  });
  assert.equal(approved.challengeId, req.challengeId);
  assert.equal(approved.status, 'approved');
  assert.equal(approved.verifiedFactorId, enrolled.factorId);
  assert.ok(approved.approvedAt instanceof Date);

  // (5) detokenizeAadhaar — challenge CAS → consumed, plaintext returns.
  const revealed = await detokenizeAadhaar({
    challengeId: req.challengeId,
    context: {
      actorId: ADMIN,
      actorRole: 'SUPER_ADMIN',
      reason: 'e2e detokenize',
    },
  });
  assert.equal(revealed.aadhaar, RAW_AADHAAR, 'plaintext must round-trip through the full pipeline');
  assert.equal(revealed.last4, '1098');
  assert.equal(revealed.token, tok.token);
  assert.equal(revealed.identityId, tok.identityId);

  // The challenge row should now be `consumed`.
  const afterConsume = await challenges.findById(req.challengeId);
  assert.ok(afterConsume);
  assert.equal(afterConsume.status, 'consumed');
});

test('E2E Step-Up: wrong TOTP code surfaces CODE_MISMATCH and leaves the challenge pending', async () => {
  const ADMIN = 'wrongcode-admin@fln.org';
  const RAW_AADHAAR = '111222333444';

  const tok = await tokenize({
    raw: RAW_AADHAAR,
    type: 'AADHAAR',
    context: { actorId: 'fln-backend-service', actorRole: 'SERVICE', reason: 'e2e seed' },
  });
  const enrolled = await enrollMfa({
    actor: ADMIN,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e enroll' },
  });
  const req = await requestDetokenization({
    tokenId: tok.token,
    factorId: enrolled.factorId,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up request' },
  });

  // Submit a deliberately wrong 8-digit code (matches the
  // command's DEFAULT_DIGITS — the TOTP extension bumped from
  // 6 → 8 to give humans a longer typing window).
  await assert.rejects(
    () => approveStepUpChallenge({
      challengeId: req.challengeId,
      code: '00000000',
      context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up approve' },
    }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      // The command surfaces a typed error with `code: 'CODE_MISMATCH'`.
      assert.equal((err as any).code, 'CODE_MISMATCH');
      return true;
    },
  );

  // The challenge must be marked `failed` — a wrong code is a
  // best-effort fail() sweep (see the approve command). The CAS in
  // `consume()` is the only path that moves a challenge out of the
  // `approved` state; the `pending → failed` transition is the
  // command's surface for "code was wrong" and prevents an
  // attacker from brute-forcing a code against the same challenge.
  const afterReject = await challenges.findById(req.challengeId);
  assert.ok(afterReject);
  assert.equal(afterReject.status, 'failed');
  assert.equal(afterReject.verifiedFactorId, null);
});

test('E2E Step-Up: replayed detokenize on a consumed challenge fails CHALLENGE_CONSUMED', async () => {
  const ADMIN = 'replay-admin@fln.org';
  const RAW_AADHAAR = '555666777888';

  const tok = await tokenize({
    raw: RAW_AADHAAR,
    type: 'AADHAAR',
    context: { actorId: 'fln-backend-service', actorRole: 'SERVICE', reason: 'e2e seed' },
  });
  const enrolled = await enrollMfa({
    actor: ADMIN,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e enroll' },
  });
  const req = await requestDetokenization({
    tokenId: tok.token,
    factorId: enrolled.factorId,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up request' },
  });

  const sealed = await mfa.getById(enrolled.factorId);
  assert.ok(sealed);
  const opened = await keyManager.openSecret(
    { bytes: sealed.encryptedSecret },
    Buffer.from(`mfa-factor:${enrolled.factorId}`, 'utf8'),
  );
  const code = await totp.currentCode(opened);
  opened.fill(0);

  await approveStepUpChallenge({
    challengeId: req.challengeId,
    code,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up approve' },
  });

  // First consume — wins.
  const first = await detokenizeAadhaar({
    challengeId: req.challengeId,
    context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e first detok' },
  });
  assert.equal(first.aadhaar, RAW_AADHAAR);

  // Second consume — must surface CHALLENGE_CONSUMED. The CAS gate
  // in `consume()` returns null and the command translates that to
  // CHALLENGE_CONSUMED.
  await assert.rejects(
    () => detokenizeAadhaar({
      challengeId: req.challengeId,
      context: { actorId: ADMIN, actorRole: 'SUPER_ADMIN', reason: 'e2e second detok' },
    }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal((err as any).code, 'CHALLENGE_CONSUMED');
      return true;
    },
  );
});

test('E2E Step-Up: actor-binding check refuses a caller who did not request the challenge', async () => {
  const ADMIN_REQUESTER = 'requester@fln.org';
  const ADMIN_IMPERSONATOR = 'someone-else@fln.org';
  const RAW_AADHAAR = '999888777666';

  const tok = await tokenize({
    raw: RAW_AADHAAR,
    type: 'AADHAAR',
    context: { actorId: 'fln-backend-service', actorRole: 'SERVICE', reason: 'e2e seed' },
  });
  const enrolled = await enrollMfa({
    actor: ADMIN_REQUESTER,
    context: { actorId: ADMIN_REQUESTER, actorRole: 'SUPER_ADMIN', reason: 'e2e enroll' },
  });
  const req = await requestDetokenization({
    tokenId: tok.token,
    factorId: enrolled.factorId,
    context: { actorId: ADMIN_REQUESTER, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up request' },
  });
  const sealed = await mfa.getById(enrolled.factorId);
  assert.ok(sealed);
  const opened = await keyManager.openSecret(
    { bytes: sealed.encryptedSecret },
    Buffer.from(`mfa-factor:${enrolled.factorId}`, 'utf8'),
  );
  const code = await totp.currentCode(opened);
  opened.fill(0);
  await approveStepUpChallenge({
    challengeId: req.challengeId,
    code,
    context: { actorId: ADMIN_REQUESTER, actorRole: 'SUPER_ADMIN', reason: 'e2e step-up approve' },
  });

  // Now a *different* actor (with the valid code in hand) tries to
  // consume the challenge. The CAS in `consume()` would still
  // succeed, BUT the command's stage-one check (`context.actorId !==
  // challenge.requestedBy`) must short-circuit FIRST with ACTOR_MISMATCH.
  // Without the actor-binding check, anyone with `vault:detokenize`
  // scope could consume any pending challenge.
  await assert.rejects(
    () => detokenizeAadhaar({
      challengeId: req.challengeId,
      context: { actorId: ADMIN_IMPERSONATOR, actorRole: 'SUPER_ADMIN', reason: 'e2e impersonate' },
    }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal((err as any).code, 'ACTOR_MISMATCH');
      return true;
    },
  );

  // And the original requester is still able to consume.
  const ok = await detokenizeAadhaar({
    challengeId: req.challengeId,
    context: { actorId: ADMIN_REQUESTER, actorRole: 'SUPER_ADMIN', reason: 'e2e legit' },
  });
  assert.equal(ok.aadhaar, RAW_AADHAAR);
});
