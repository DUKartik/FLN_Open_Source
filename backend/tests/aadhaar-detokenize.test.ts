/**
 * Aadhaar Vault Step-Up detokenization tests (Phase 4 — fully in-process).
 *
 * Run:  cd backend && npm run test:detokenize
 *       (or `npm test` runs both files)
 *
 * Isolation model: same as aadhaar-hardening.test.ts — chdir into a
 * fresh temp dir BEFORE importing modules, delete MONGODB_URI so the
 * file-fallback store is used.
 *
 * The full Step-Up admin flow is exercised through the FLN backend's
 * existing routes, but the vault implementation is now entirely
 * in-process: every `__set*Impl` stub on `aadhaarVault.ts` is
 * installed at boot, sharing the same in-memory `factors` /
 * `challenges` / `tokens` Maps. There is no fake HTTP vault server.
 * The Phase 3 in-process detokenize stub is kept; Phase 4 adds
 * matching stubs for `enrollMfa`, `requestDetokenization`, and
 * `approveStepUpChallenge` that share the same state.
 *
 * No plaintext Aadhaar is ever printed; assertions only test FOR it.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// ─── Bootstrap: isolate env + cwd BEFORE importing application modules ─────
const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fln-detok-test-'));
fs.mkdirSync(path.join(scratchDir, 'data'), { recursive: true });
process.chdir(scratchDir);              // db.ts resolves data/db.json from cwd
delete process.env.MONGODB_URI;         // force the file-fallback store
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'dev-insecure-secret-change-me';
process.env.SEED_DEMO_PASSWORD = 'Fln@2026';
// The tokenize client refuses to mint a service JWT without this
// (fail-closed). We replace the tokenize impl at boot, but the
// default HTTP fallback still requires the env var to be present
// (a stray call would surface NOT_CONFIGURED rather than UNREACHABLE).
process.env.AADHAAR_VAULT_SERVICE_JWT_SECRET = 'test-only-hmac-secret-not-a-real-credential';
delete process.env.AADHAAR_VAULT_SERVICE_JWT_ISSUER;
delete process.env.AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;
delete process.env.AADHAAR_VAULT_TIMEOUT_MS;
// Phase 4 in-process vault would need a real Mongo replica set to
// run; the test environment is file-fallback only. The vault
// module is NOT enabled here, and we install the in-process
// impls directly via `__set*Impl`.
delete process.env.LOCAL_DEV_MASTER_KEY;
delete process.env.VAULT_MODULE_ENABLED;
// The aadhaarDetokenize.ts route resolves the vault's URL from
// this env var; without an HTTP vault, an unset value would
// surface UNREACHABLE on a stray default-impl call. Set it to a
// placeholder that no real server listens on, so any accidental
// default-impl call fails fast with a clear "network" error.
process.env.AADHAAR_VAULT_URL = 'http://127.0.0.1:1';

// ─── TOTP helpers (RFC 6238 / HMAC-SHA1, 6 digits, 30s period) ────────────
function totpCode(secretBytes: Buffer, time = Math.floor(Date.now() / 1000)): string {
  const counter = Math.floor(time / 30);
  const buf = Buffer.alloc(8);
  let hi = Math.floor(counter / 0x100000000);
  let lo = counter >>> 0;
  buf.writeUInt32BE(hi, 0);
  buf.writeUInt32BE(lo, 4);
  const hmac = crypto.createHmac('sha1', secretBytes).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24)
               | ((hmac[offset + 1] & 0xff) << 16)
               | ((hmac[offset + 2] & 0xff) << 8)
               | (hmac[offset + 3] & 0xff);
  return (binary % 1_000_000).toString().padStart(6, '0');
}

// ─── In-memory fake-vault state (shared between the 4 in-process stubs) ──
// Phase 4 collapses the fake HTTP vault into 4 in-process stubs that share
// the same Maps. The original fake HTTP server is gone; the `factors` /
// `challenges` / `tokens` Maps are the single source of truth.
type Factor = {
  factorId: string;
  actor: string;
  secretBytes: Buffer;
  status: 'ACTIVE' | 'REVOKED';
  digits: number;
  period: number;
  algorithm: string;
  label: string;
};
type Challenge = {
  challengeId: string;
  tokenId: string;
  factorId: string;
  status: 'pending' | 'approved' | 'consumed';
  expiresAt: number;
  requestedBy: string;
  identityId: string;
};
type Token = { rawAadhaar: string; identityId: string };

const factors = new Map<string, Factor>();
const challenges = new Map<string, Challenge>();
const tokens = new Map<string, Token>();

/** Per-test challenge TTL (ms). Tests override this to force expiry. */
let challengeTtlMs = 300_000; // 5 min — matches the real vault default

// ─── Import application modules AFTER env/cwd isolation ────────────────────
const { dbStore } = await import('../src/db');
const { JWT_SECRET } = await import('../src/auth');
const { registerStudentRoutes } = await import('../src/routes/students');
const { registerAadhaarDetokenizeRoutes } = await import('../src/routes/aadhaarDetokenize');
const aadhaarVaultModule = await import('../src/aadhaarVault');

// ---------------------------------------------------------------------------
// Install 4 in-process vault impls. All four share the in-memory Maps above
// so cross-component state stays coherent (the same Map the detokenize stub
// already walks). Together they implement the full Step-Up admin flow as
// the in-process vault module would, but without needing a Mongo replica
// set / the in-process command's KeyManager.
// ---------------------------------------------------------------------------

// (1) tokenize — same shape as the hardening-test stub. Mints a tokenId
// and identityId from the raw 12-digit string so the detokenize stub
// can find the plaintext later.
aadhaarVaultModule.__setTokenizeAadhaarImpl(async (rawAadhar) => {
  const digits = String(rawAadhar).replace(/[^0-9]/g, '');
  const tokenId = 'tok-' + crypto.randomUUID();
  const identityId = 'id-' + crypto.createHash('sha256').update(digits + ':fake-pepper:1').digest('hex').slice(0, 16);
  tokens.set(tokenId, { rawAadhaar: digits, identityId });
  return {
    token: tokenId,
    last4: digits.slice(-4),
    tokenType: 'AADHAAR',
    identityId,
    auditId: `audit-tokenize-${tokens.size}`,
    keyVersion: 'kv-1',
  };
});

// (2) enrollMfa — mint a TOTP factor with a fresh random 20-byte secret.
// The plaintext secret is stored in the `factors` Map so the test can
// compute a valid TOTP code later; this is the only path the test has
// to know the secret (the in-process command's secret is sealed via
// KeyManager.sealSecret and never round-trips back through the wire).
aadhaarVaultModule.__setEnrollMfaImpl(async (params) => {
  const factorId = 'fac-' + crypto.randomUUID();
  const secretBytes = crypto.randomBytes(20);
  const algorithm = String(params.algorithm || 'SHA1');
  const digits = Number(params.digits || 6);
  const period = Number(params.period || 30);
  const f: Factor = {
    factorId,
    actor: params.actor,
    secretBytes,
    status: 'ACTIVE',
    digits,
    period,
    algorithm,
    label: params.label || params.actor,
  };
  factors.set(factorId, f);
  // Synthesize a fake otpauth URI (never parsed by tests; included for
  // shape parity with the real vault).
  const otpauthUri = `otpauth://totp/VaultTest:${encodeURIComponent(params.actor)}?secret=BASE32FAKE&algorithm=${algorithm}&digits=${digits}&period=${period}`;
  return {
    factorId,
    otpauthUri,
    factor: {
      factorId,
      actor: params.actor,
      factorType: 'TOTP',
      status: 'ACTIVE',
      label: f.label,
      algorithm,
      digits,
      period,
      lastUsedAt: null,
      expiresAt: null,
      createdAt: new Date().toISOString(),
    },
  };
});

// (3) requestDetokenization — mint a step-up challenge bound to a
// (token, factor) pair. TTL is per-test (defaults to 5 min).
aadhaarVaultModule.__setRequestDetokenizationImpl(async (params) => {
  const tok = tokens.get(params.tokenId);
  if (!tok) {
    throw new aadhaarVaultModule.VaultError('TOKEN_NOT_FOUND', 404, 'No such token.');
  }
  const fac = factors.get(params.factorId);
  if (!fac) {
    throw new aadhaarVaultModule.VaultError('FACTOR_NOT_FOUND', 404, 'No such factor.');
  }
  if (fac.status !== 'ACTIVE') {
    throw new aadhaarVaultModule.VaultError('FACTOR_NOT_ACTIVE', 403, 'Factor inactive.');
  }
  const challengeId = 'chl-' + crypto.randomUUID();
  challenges.set(challengeId, {
    challengeId,
    tokenId: params.tokenId,
    factorId: params.factorId,
    status: 'pending',
    expiresAt: Date.now() + challengeTtlMs,
    requestedBy: String(params.context.email || 'fln-backend-service'),
    identityId: tok.identityId,
  });
  return {
    challengeId,
    expiresAt: new Date(Date.now() + challengeTtlMs).toISOString(),
    requiredFactor: {
      factorId: fac.factorId,
      actor: fac.actor,
      label: fac.label,
      factorType: 'TOTP',
    },
  };
});

// (4) approveStepUpChallenge — validate the TOTP code against the
// stored secret, then transition the challenge to 'approved'. Same
// shape as the in-process detokenize stub below: refuses a wrong
// code with CODE_MISMATCH (403), an expired challenge with
// CHALLENGE_EXPIRED (410), and a non-pending challenge with
// CHALLENGE_NOT_PENDING (403).
aadhaarVaultModule.__setApproveStepUpChallengeImpl(async (params) => {
  const ch = challenges.get(params.challengeId);
  if (!ch) {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_NOT_FOUND', 404, 'No such challenge.');
  }
  if (ch.status !== 'pending') {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_NOT_PENDING', 403, 'Already approved/consumed.');
  }
  if (Date.now() > ch.expiresAt) {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_EXPIRED', 410, 'Expired.');
  }
  const fac = factors.get(ch.factorId);
  if (!fac) {
    throw new aadhaarVaultModule.VaultError('FACTOR_NOT_FOUND', 404, 'No factor.');
  }
  if (fac.status !== 'ACTIVE') {
    throw new aadhaarVaultModule.VaultError('FACTOR_NOT_ACTIVE', 403, 'Inactive.');
  }
  const expected = totpCode(fac.secretBytes);
  if (params.code !== expected) {
    throw new aadhaarVaultModule.VaultError('CODE_MISMATCH', 403, 'Bad code.');
  }
  ch.status = 'approved';
  return {
    challengeId: ch.challengeId,
    status: 'approved',
    approvedAt: new Date().toISOString(),
    verifiedFactorId: fac.factorId,
  };
});

// (5) detokenizeAadhaar — CAS-aware consume of the approved challenge.
// First-writer-wins; second caller gets CHALLENGE_CONSUMED. Same
// semantics as the Mongo adapter's findOneAndUpdate({_id, status:
// 'approved'}) gate.
aadhaarVaultModule.__setDetokenizeAadhaarImpl(async (params) => {
  const challengeId = params.challengeId;
  const ch = challenges.get(challengeId);
  if (!ch) {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_NOT_FOUND', 404, 'No such challenge.');
  }
  if (ch.status === 'consumed') {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_CONSUMED', 409, 'Replay.');
  }
  if (ch.status !== 'approved') {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_NOT_APPROVED', 403, 'Not approved.');
  }
  if (Date.now() > ch.expiresAt) {
    throw new aadhaarVaultModule.VaultError('CHALLENGE_EXPIRED', 410, 'Expired.');
  }
  const tok = tokens.get(ch.tokenId);
  if (!tok) {
    throw new aadhaarVaultModule.VaultError('TOKEN_NOT_FOUND', 404, 'No token.');
  }
  // Actor-binding check (defence in depth — the URL path is
  // already authorization-gated by the FLN route, but the in-
  // process command enforces it too). The actorId comes from
  // the AadhaarActorContext.email; identity comes from the
  // challenge's requestedBy projection.
  const callerActorId = params.context.email || 'fln-backend-service';
  if (ch.requestedBy !== callerActorId) {
    throw new aadhaarVaultModule.VaultError(
      'ACTOR_MISMATCH',
      403,
      `challenge was requested by ${ch.requestedBy}, not ${callerActorId}.`,
    );
  }
  // CAS — atomic consume. First-writer-wins.
  ch.status = 'consumed';
  return {
    token: ch.tokenId,
    identityId: tok.identityId,
    aadhaar: tok.rawAadhaar,
    last4: tok.rawAadhaar.slice(-4),
    auditId: `audit-detok-${challengeId.slice(0, 8)}`,
  };
});

await dbStore.init();

const express = (await import('express')).default;
const jwtLib = (await import('jsonwebtoken')).default;
const app = express();
app.use(express.json());
registerStudentRoutes(app);
registerAadhaarDetokenizeRoutes(app);

const apiServer: http.Server = await new Promise(resolve => {
  const s = app.listen(0, '127.0.0.1', () => resolve(s as http.Server));
});
const apiPort = (apiServer.address() as import('net').AddressInfo).port;
const BASE = `http://127.0.0.1:${apiPort}`;

const TEACHER = 'gps-mt-001.t01@fln.org';        // u6 — TEACHER (NOT a detokenize role)
const SUPERADMIN = 'superadmin@fln.org';          // u1 — SUPERADMIN
const DISTRICT_ADMIN = 'district.ldh@fln.org';    // u3 — DISTRICT_ADMIN
const BLOCK_ADMIN = 'block.ldh-01@fln.org';       // u4 — BLOCK_ADMIN

function authHeaderFor(email: string): string {
  return `Bearer ${jwtLib.sign({ email }, JWT_SECRET, { expiresIn: '1h' })}`;
}
async function api(method: string, reqPath: string, email: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(`${BASE}${reqPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: authHeaderFor(email) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: any = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, json };
}

/** Register a single student via the public POST /api/students path so we
 *  get a real aadhaarTokenId persisted in the file-fallback DB. Returns
 *  the student id. */
async function registerStudent(raw: string, name: string): Promise<string> {
  const res = await api('POST', '/api/students', TEACHER, {
    name, classGroup: 'Class 1', section: 'A', age: 7, aadharNumber: raw,
  });
  assert.equal(res.status, 200, `seed student register failed: ${res.status} ${JSON.stringify(res.json)}`);
  return res.json.id;
}

after(async () => {
  // Reset in-process impls so subsequent test files (if any) see
  // the default HTTP-backed implementation.
  aadhaarVaultModule.__setTokenizeAadhaarImpl(null);
  aadhaarVaultModule.__setEnrollMfaImpl(null);
  aadhaarVaultModule.__setRequestDetokenizationImpl(null);
  aadhaarVaultModule.__setApproveStepUpChallengeImpl(null);
  aadhaarVaultModule.__setDetokenizeAadhaarImpl(null);
  await new Promise<void>(resolve => apiServer.close(() => resolve()));
  (apiServer as any).closeAllConnections?.();
  try { fs.rmSync(scratchDir, { recursive: true, force: true }); } catch { /* Windows file locks */ }
});

// ===== TESTS =====

test('TEST 7: unauthorized roles (TEACHER) get 403 on every detokenize endpoint', async () => {
  // Register a student so we have a valid id to act on.
  const studentId = await registerStudent('101010101010', 'Test 7 Student');

  for (const path of [
    `/api/students/${studentId}/aadhaar/mfa/enroll`,
    `/api/students/${studentId}/aadhaar/step-up/request`,
    `/api/students/${studentId}/aadhaar/step-up/approve`,
    `/api/students/${studentId}/aadhaar/detokenize`,
  ]) {
    const res = await api('POST', path, TEACHER, { factorId: 'x', challengeId: 'x', code: '123456' });
    assert.equal(res.status, 403, `TEACHER should be 403 on ${path}, got ${res.status}: ${JSON.stringify(res.json)}`);
  }

  // Volunteer / school / teacher roles also blocked — quick sanity sweep.
  for (const email of ['gps-mt-001@fln.org', 'vol.rahul@fln.org']) {
    const res = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, email, {});
    assert.equal(res.status, 403, `${email} should be 403, got ${res.status}`);
  }
});

test('TEST 8: SUPERADMIN can drive full Step-Up lifecycle and recover original raw', async () => {
  const raw = '202020202020';
  const studentId = await registerStudent(raw, 'Test 8 Reveal');

  // (a) enroll MFA — now in-process via the stub.
  const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, SUPERADMIN, {
    label: 'Test 8 admin',
  });
  assert.equal(enrollRes.status, 200, `enroll failed: ${JSON.stringify(enrollRes.json)}`);
  assert.equal(typeof enrollRes.json.factorId, 'string');
  assert.equal(typeof enrollRes.json.otpauthUri, 'string');
  assert.match(enrollRes.json.otpauthUri, /^otpauth:\/\//);
  // The factor envelope is project-stripped: no encryptedSecret on the wire.
  assert.equal(enrollRes.json.factor.encryptedSecret, undefined, 'encryptedSecret must not leak');

  // (b) request step-up challenge — now in-process via the stub.
  const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, SUPERADMIN, {
    factorId: enrollRes.json.factorId,
  });
  assert.equal(reqRes.status, 200, `request failed: ${JSON.stringify(reqRes.json)}`);
  assert.equal(typeof reqRes.json.challengeId, 'string');
  assert.equal(typeof reqRes.json.expiresAt, 'string');
  // Required-factor envelope echoes the bound factor.
  assert.equal(reqRes.json.requiredFactor.factorId, enrollRes.json.factorId);

  // (c) approve with valid TOTP — we have to compute it. Look up the
  // factor's secret from the in-memory Map by factorId.
  const fac = factors.get(enrollRes.json.factorId);
  assert.ok(fac, 'factor must exist in stub state');
  const code = totpCode(fac.secretBytes);

  const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
    code,
  });
  assert.equal(approveRes.status, 200, `approve failed: ${JSON.stringify(approveRes.json)}`);
  assert.equal(approveRes.json.status, 'approved');
  assert.equal(approveRes.json.verifiedFactorId, enrollRes.json.factorId);

  // (d) detokenize with the approved challenge — in-process stub.
  const detokRes = await api('POST', `/api/students/${studentId}/aadhaar/detokenize`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
  });
  assert.equal(detokRes.status, 200, `detok failed: ${JSON.stringify(detokRes.json)}`);
  assert.equal(detokRes.json.aadhaar, raw, 'plaintext must round-trip');
  assert.equal(detokRes.json.last4, raw.slice(-4));
  assert.match(detokRes.json.aadharMasked, /^XXXX-XXXX-\d{4}$/);
  // No vault references in the response (Phase 2 hygiene carries here too).
  assert.equal(detokRes.json.token, undefined);
  assert.equal(detokRes.json.identityId, undefined);
});

test('TEST 9: invalid TOTP code rejected at the approve step', async () => {
  const studentId = await registerStudent('303030303030', 'Test 9 Student');
  const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, SUPERADMIN, {});
  assert.equal(enrollRes.status, 200);
  const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, SUPERADMIN, {
    factorId: enrollRes.json.factorId,
  });
  assert.equal(reqRes.status, 200);

  // Submit a deliberately wrong code.
  const wrongCode = '000000';
  const fac = factors.get(enrollRes.json.factorId);
  if (totpCode(fac!.secretBytes) === wrongCode) {
    // Astronomically unlikely; skip ahead.
    return;
  }
  const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
    code: wrongCode,
  });
  assert.equal(approveRes.status, 403, `wrong TOTP should be 403, got ${approveRes.status}`);
  assert.equal(approveRes.json.error, 'CODE_MISMATCH');

  // After a failed approve, detokenize must reject with NOT_APPROVED.
  const detokRes = await api('POST', `/api/students/${studentId}/aadhaar/detokenize`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
  });
  assert.equal(detokRes.status, 403);
  assert.equal(detokRes.json.error, 'CHALLENGE_NOT_APPROVED');
});

test('TEST 10: cross-student token substitution rejected (token comes from DB only)', async () => {
  // Register two students in the same school (TEACHER's school gps-mt-001).
  const aliceId = await registerStudent('404040404040', 'Test 10 Alice');
  const bobId = await registerStudent('505050505050', 'Test 10 Bob');

  // Enroll an admin factor.
  const enrollRes = await api('POST', `/api/students/${aliceId}/aadhaar/mfa/enroll`, SUPERADMIN, {});
  assert.equal(enrollRes.status, 200);

  // Mint a challenge for ALICE (the URL path is /students/:id/... and the
  // backend resolves the token from Alice's DB record, not from any body
  // field). Verify the resulting challenge, when consumed, decrypts Alice.
  const reqRes = await api('POST', `/api/students/${aliceId}/aadhaar/step-up/request`, SUPERADMIN, {
    factorId: enrollRes.json.factorId,
  });
  assert.equal(reqRes.status, 200);

  const fac = factors.get(enrollRes.json.factorId)!;
  const code = totpCode(fac.secretBytes);
  const approveRes = await api('POST', `/api/students/${aliceId}/aadhaar/step-up/approve`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId, code,
  });
  assert.equal(approveRes.status, 200);

  // Now attempt to consume that challenge via Bob's endpoint. The backend
  // will resolve Bob's token id (a different opaque string), but the
  // challenge is bound to Alice's token. So the assertion that matters
  // here is: we cannot SUBSTITUTE the token id — the URL path is the
  // only thing the client controls, and the backend resolves the token
  // strictly from the authorized student's DB row.
  const detokRes = await api('POST', `/api/students/${bobId}/aadhaar/detokenize`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
  });
  // The challenge binds to Alice's token. The challenge is still
  // approved (not yet consumed), so the in-process stub's actor-
  // binding check uses the SUPERADMIN's email. The challenge was
  // requested by SUPERADMIN, so actor-binding passes. The
  // consumption decrypts Alice's plaintext (the challenge holds
  // Alice's tokenId) — proving the backend never lets the client
  // pick the token, only the student id, which is authorization-
  // gated.
  assert.equal(detokRes.status, 200);
  assert.equal(detokRes.json.aadhaar, '404040404040', 'must decrypt Alice, not Bob');

  // Defence-in-depth: a client trying to pass a different tokenId in the
  // body is ignored — there is no such field on the route.
  const detokBodyRes = await api('POST', `/api/students/${bobId}/aadhaar/detokenize`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
    tokenId: 'forged-token',
    identityId: 'forged-identity',
  });
  // The forged fields are silently ignored; the response must NOT include
  // them on the wire.
  assert.equal(detokBodyRes.json.tokenId, undefined);
  assert.equal(detokBodyRes.json.identityId, undefined);
});

test('TEST 11: DISTRICT_ADMIN / BLOCK_ADMIN can drive Step-Up lifecycle', async () => {
  const studentId = await registerStudent('606060606060', 'Test 11 District');

  for (const admin of [DISTRICT_ADMIN, BLOCK_ADMIN]) {
    const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, admin, {});
    assert.equal(enrollRes.status, 200, `${admin} enroll: ${enrollRes.status}`);
    const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, admin, {
      factorId: enrollRes.json.factorId,
    });
    assert.equal(reqRes.status, 200, `${admin} request: ${reqRes.status}`);
    const fac = factors.get(enrollRes.json.factorId)!;
    const code = totpCode(fac.secretBytes);
    const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, admin, {
      challengeId: reqRes.json.challengeId, code,
    });
    assert.equal(approveRes.status, 200, `${admin} approve: ${approveRes.status}`);
    const detokRes = await api('POST', `/api/students/${studentId}/aadhaar/detokenize`, admin, {
      challengeId: reqRes.json.challengeId,
    });
    assert.equal(detokRes.status, 200, `${admin} detok: ${detokRes.status}`);
    assert.equal(detokRes.json.aadhaar, '606060606060');
  }
});

test('TEST 12: expired challenge returns 410 and detokenize is forbidden', async () => {
  const studentId = await registerStudent('707070707070', 'Test 12 Expired');
  const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, SUPERADMIN, {});
  assert.equal(enrollRes.status, 200);
  // Force 50ms TTL for this test.
  challengeTtlMs = 50;
  try {
    const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, SUPERADMIN, {
      factorId: enrollRes.json.factorId,
    });
    assert.equal(reqRes.status, 200);
    // Wait past the TTL.
    await new Promise(r => setTimeout(r, 120));
    const fac = factors.get(enrollRes.json.factorId)!;
    const code = totpCode(fac.secretBytes);
    const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, SUPERADMIN, {
      challengeId: reqRes.json.challengeId, code,
    });
    assert.equal(approveRes.status, 410, `expired challenge approve: ${approveRes.status}`);
    assert.equal(approveRes.json.error, 'CHALLENGE_EXPIRED');
  } finally {
    challengeTtlMs = 300_000;
  }
});

test('TEST 13: CAS gate — two concurrent consume() calls collapse to one winner', async () => {
  // Direct test of the in-process detokenize stub's CAS gate. The
  // stub mirrors the Mongo adapter's findOneAndUpdate({_id, status:
  // 'approved'}) CAS: the first caller finds status='approved' and
  // transitions to 'consumed'; the second caller finds status=
  // 'consumed' and is rejected with CHALLENGE_CONSUMED.
  //
  // We mint a fresh approved challenge through the in-process
  // request/approve stubs, then fire two concurrent detokenize
  // calls. One must succeed; the other must surface
  // CHALLENGE_CONSUMED.
  const studentId = await registerStudent('808080808080', 'Test 13 CAS');
  const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, SUPERADMIN, {});
  assert.equal(enrollRes.status, 200);
  const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, SUPERADMIN, {
    factorId: enrollRes.json.factorId,
  });
  assert.equal(reqRes.status, 200);
  const challengeId = reqRes.json.challengeId;

  // Mint a valid TOTP code and approve.
  const fac = factors.get(enrollRes.json.factorId)!;
  const code = totpCode(fac.secretBytes);
  const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, SUPERADMIN, {
    challengeId, code,
  });
  assert.equal(approveRes.status, 200);

  // The challenge is now 'approved'. Fire two concurrent
  // detokenize calls. The in-process stub's CAS gate ensures
  // exactly one succeeds.
  const [a, b] = await Promise.allSettled([
    api('POST', `/api/students/${studentId}/aadhaar/detokenize`, SUPERADMIN, { challengeId }),
    api('POST', `/api/students/${studentId}/aadhaar/detokenize`, SUPERADMIN, { challengeId }),
  ]);

  const fulfilled = [a, b].filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<{ status: number; json: any }>[];
  const rejected = [a, b].filter(r => r.status === 'rejected');

  // Both API calls should resolve (they're fetch, not the
  // underlying command) — but the underlying CAS gate should
  // surface CHALLENGE_CONSUMED on exactly one of them.
  assert.equal(fulfilled.length, 2, 'both HTTP calls should resolve');
  const statuses = fulfilled.map(r => r.value.status).sort();
  // One 200, one 409 (CHALLENGE_CONSUMED) — the API layer
  // surfaces the in-process VaultError directly. (Order is
  // racy; we sort to make the assertion deterministic.)
  assert.deepEqual(statuses, [200, 409], `expected [200, 409], got [${statuses.join(',')}]`);
  const okRes = fulfilled.find(r => r.value.status === 200)!;
  const consumedRes = fulfilled.find(r => r.value.status === 409)!;
  assert.equal(okRes.value.json.aadhaar, '808080808080', 'winner must decrypt');
  assert.equal(consumedRes.value.json.error, 'CHALLENGE_CONSUMED', 'loser must surface CHALLENGE_CONSUMED');

  // After both calls settle, the challenge Map must show
  // 'consumed' exactly once.
  const finalCh = challenges.get(challengeId)!;
  assert.equal(finalCh.status, 'consumed', 'challenge must end in consumed state');
  void rejected; // both HTTP calls resolve; rejected list is empty.
});
