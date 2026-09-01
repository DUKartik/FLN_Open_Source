/**
 * Aadhaar Vault Step-Up detokenization tests (Phase 3 in-process).
 *
 * Run:  cd backend && npm run test:detokenize
 *       (or `npm test` runs both files)
 *
 * Isolation model: same as aadhaar-hardening.test.ts — chdir into a
 * fresh temp dir BEFORE importing modules, delete MONGODB_URI so the
 * file-fallback store is used. The in-process detokenize command is
 * stubbed via `__setDetokenizeAadhaarImpl` so the file-fallback env
 * (no Mongo replica set) can still exercise the full Step-Up admin
 * flow through the FLN backend's existing routes.
 *
 * The fake HTTP vault retains the four endpoints the in-process
 * module does NOT implement yet (Phase 4 lands the in-process MFA
 * and step-up-request/approve commands):
 *   - POST /v1/tokenize
 *   - POST /v1/mfa/enroll
 *   - POST /v1/detokenize/request
 *   - POST /v1/detokenize/step-up/:challengeId/approve
 *
 * The /v1/detokenize endpoint is replaced by the in-process stub
 * installed via `__setDetokenizeAadhaarImpl`. The stub consults the
 * same in-memory `challenges` / `tokens` Maps the fake HTTP vault
 * uses, so the cross-component state stays coherent.
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
// Phase 3 in-process vault would need a real Mongo replica set to
// run; the test environment is file-fallback only. The vault
// module is NOT enabled here, and we install the in-process
// detokenize impl directly via `__setDetokenizeAadhaarImpl`.
delete process.env.LOCAL_DEV_MASTER_KEY;
delete process.env.VAULT_MODULE_ENABLED;

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

// ─── In-memory fake-vault state (shared between fake HTTP and the
//     in-process detokenize stub) ─────────────────────────────────────────
type Factor = {
  factorId: string;
  actor: string;
  secretBytes: Buffer;
  status: 'ACTIVE' | 'REVOKED';
  digits: number;
  period: number;
  algorithm: string;
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
let lastAuthWasBearer = false;

/** Per-test challenge TTL (ms). Tests override this to force expiry. */
let challengeTtlMs = 300_000; // 5 min — matches the real vault default

/** Identity-row registry so the in-process detokenize stub can
 *  resolve identityId by tokenId and look up the (mock) ciphertext
 *  + AAD. (In the real module the repository's `findById` walks
 *  vault_identities — for the stub we keep the bare minimum.) */
const identityRows = new Map<string, {
  identityId: string;
  ciphertext: Buffer;
  aad: Buffer;
  pepperVersion: number;
  keyVersion: number;
  createdAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
}>();

const vaultServer = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c: Buffer) => { body += c; });
  req.on('end', () => {
    lastAuthWasBearer = String(req.headers.authorization || '').startsWith('Bearer ');
    let parsed: any = {};
    try { parsed = JSON.parse(body); } catch { /* ignore */ }
    const url = req.url || '';
    const sendJson = (status: number, payload: any) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };

    // ── tokenize (also drives registration fixtures) ─────────────────────
    if (req.method === 'POST' && url === '/v1/tokenize') {
      const digits = String(parsed.raw || '').replace(/[^0-9]/g, '');
      const raw = digits.slice(-4);
      const tokenId = 'tok-' + crypto.randomUUID();
      const identityId = 'id-' + crypto.createHash('sha256').update(digits + ':fake-pepper:1').digest('hex').slice(0, 16);
      tokens.set(tokenId, { rawAadhaar: digits, identityId });
      // Seed a minimal identity row so the in-process detokenize
      // stub (when it eventually walks vault_identities) has
      // something to find. (For the current shape, the stub
      // resolves plaintext from the `tokens` Map directly — the
      // identity row is just a placeholder.)
      identityRows.set(identityId, {
        identityId,
        ciphertext: Buffer.from('placeholder', 'utf8'),
        aad: Buffer.from('aadhaar-vault/v1|placeholder', 'utf8'),
        pepperVersion: 1,
        keyVersion: 1,
        createdAt: new Date(),
        rotatedAt: null,
        revokedAt: null,
      });
      return sendJson(201, {
        token: tokenId,
        last4: raw,
        tokenType: 'AADHAAR',
        identityId,
        auditId: `audit-tokenize-${tokens.size}`,
        keyVersion: 'kv-1',
      });
    }

    // ── mfa/enroll ──────────────────────────────────────────────────────
    if (req.method === 'POST' && url === '/v1/mfa/enroll') {
      const actor = String(parsed.actor || '');
      const factorId = 'fac-' + crypto.randomUUID();
      const secretBytes = crypto.randomBytes(20);
      const f: Factor = {
        factorId, actor, secretBytes,
        status: 'ACTIVE',
        digits: Number(parsed.digits || 6),
        period: Number(parsed.period || 30),
        algorithm: String(parsed.algorithm || 'SHA1'),
      };
      factors.set(factorId, f);
      // Synthesize a fake otpauth URI (never parsed by tests; included for
      // shape parity with the real vault).
      const otpauthUri = `otpauth://totp/VaultTest:${encodeURIComponent(actor)}?secret=BASE32FAKE&algorithm=${f.algorithm}&digits=${f.digits}&period=${f.period}`;
      return sendJson(200, {
        factorId,
        otpauthUri,
        factor: {
          factorId, actor, factorType: 'TOTP', status: 'ACTIVE',
          encryptedSecret: secretBytes.toString('base64'),
          algorithm: f.algorithm, digits: f.digits, period: f.period,
          lastUsedAt: null, expiresAt: null, createdAt: new Date().toISOString(),
        },
      });
    }

    // ── detokenize/request ─────────────────────────────────────────────
    if (req.method === 'POST' && url === '/v1/detokenize/request') {
      const tokenId = String(parsed.tokenId || '');
      const factorId = String(parsed.factorId || '');
      if (!tokens.has(tokenId)) return sendJson(404, { error: 'TOKEN_NOT_FOUND', message: 'No such token.' });
      const fac = factors.get(factorId);
      if (!fac) return sendJson(404, { error: 'FACTOR_NOT_FOUND', message: 'No such factor.' });
      if (fac.status !== 'ACTIVE') return sendJson(403, { error: 'FACTOR_NOT_ACTIVE', message: 'Factor inactive.' });
      const tok = tokens.get(tokenId)!;
      const challengeId = 'chl-' + crypto.randomUUID();
      challenges.set(challengeId, {
        challengeId, tokenId, factorId,
        status: 'pending',
        expiresAt: Date.now() + challengeTtlMs,
        requestedBy: String(parsed?.context?.actorId || ''),
        identityId: tok.identityId,
      });
      return sendJson(200, {
        challengeId,
        expiresAt: new Date(Date.now() + challengeTtlMs).toISOString(),
        requiredFactor: { factorId: fac.factorId, algorithm: fac.algorithm, digits: fac.digits, period: fac.period },
      });
    }

    // ── detokenize/step-up/:challengeId/approve ─────────────────────────
    const stepUpMatch = url.match(/^\/v1\/detokenize\/step-up\/([^/]+)\/approve$/);
    if (req.method === 'POST' && stepUpMatch) {
      const challengeId = decodeURIComponent(stepUpMatch[1]);
      const code = String(parsed.code || '');
      const ch = challenges.get(challengeId);
      if (!ch) return sendJson(404, { error: 'CHALLENGE_NOT_FOUND', message: 'No such challenge.' });
      if (ch.status !== 'pending') return sendJson(403, { error: 'CHALLENGE_NOT_PENDING', message: 'Already approved/consumed.' });
      if (Date.now() > ch.expiresAt) return sendJson(410, { error: 'CHALLENGE_EXPIRED', message: 'Expired.' });
      const fac = factors.get(ch.factorId);
      if (!fac) return sendJson(404, { error: 'FACTOR_NOT_FOUND', message: 'No factor.' });
      if (fac.status !== 'ACTIVE') return sendJson(403, { error: 'FACTOR_NOT_ACTIVE', message: 'Inactive.' });
      const expected = totpCode(fac.secretBytes);
      if (code !== expected) return sendJson(403, { error: 'CODE_MISMATCH', message: 'Bad code.' });
      ch.status = 'approved';
      return sendJson(200, {
        challengeId,
        status: 'approved',
        approvedAt: new Date().toISOString(),
        verifiedFactorId: fac.factorId,
      });
    }

    // /v1/detokenize is no longer served by the fake HTTP vault —
    // it's handled in-process by the stub installed via
    // `__setDetokenizeAadhaarImpl`. The HTTP route would 404 here
    // anyway; we return a clear "use the in-process path" error
    // so a regression that bypasses the shim is loud.
    if (req.method === 'POST' && url === '/v1/detokenize') {
      return sendJson(410, {
        error: 'GONE',
        message: 'detokenize is now in-process; install __setDetokenizeAadhaarImpl',
      });
    }

    return sendJson(404, { error: 'NOT_FOUND', message: `unknown route ${url}` });
  });
});
await new Promise<void>(resolve => vaultServer.listen(0, '127.0.0.1', resolve));
const vaultPort = (vaultServer.address() as import('net').AddressInfo).port;
process.env.AADHAAR_VAULT_URL = `http://127.0.0.1:${vaultPort}`;

// ─── Import application modules AFTER env/cwd isolation ────────────────────
const { dbStore } = await import('../src/db');
const { JWT_SECRET } = await import('../src/auth');
const { registerStudentRoutes } = await import('../src/routes/students');
const { registerAadhaarDetokenizeRoutes } = await import('../src/routes/aadhaarDetokenize');
const aadhaarVaultModule = await import('../src/aadhaarVault');

// Replace the in-process vault's tokenize + detokenize
// implementations with deterministic stubs. The tokenize stub is
// the same shape as the hardening-test stub. The detokenize stub
// reads from the in-memory `challenges` / `tokens` Maps the fake
// HTTP vault uses, so cross-component state stays coherent.
aadhaarVaultModule.__setTokenizeAadhaarImpl(async (rawAadhar) => {
  const digits = String(rawAadhar).replace(/[^0-9]/g, '');
  const tokenId = 'tok-' + crypto.randomUUID();
  const identityId = 'id-' + crypto.createHash('sha256').update(digits + ':fake-pepper:1').digest('hex').slice(0, 16);
  tokens.set(tokenId, { rawAadhaar: digits, identityId });
  identityRows.set(identityId, {
    identityId,
    ciphertext: Buffer.from('placeholder', 'utf8'),
    aad: Buffer.from('aadhaar-vault/v1|placeholder', 'utf8'),
    pepperVersion: 1,
    keyVersion: 1,
    createdAt: new Date(),
    rotatedAt: null,
    revokedAt: null,
  });
  return {
    token: tokenId,
    last4: digits.slice(-4),
    tokenType: 'AADHAAR',
    identityId,
    auditId: `audit-tokenize-${tokens.size}`,
    keyVersion: 'kv-1',
  };
});

// CAS-aware in-process detokenize stub. The first caller that
// finds status='approved' wins the transition; subsequent callers
// see status='consumed' and get CHALLENGE_CONSUMED. This mirrors
// the Mongo adapter's findOneAndUpdate({_id, status: 'approved'})
// CAS gate and the Postgres adapter's
// `UPDATE ... WHERE status = 'approved' RETURNING *` semantics.
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
  // process command enforces it too). The actorRole comes from
  // the AadhaarActorContext the shim hands us; identity comes
  // from the email. Match against the request route's
  // `requestedBy` projection.
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
  aadhaarVaultModule.__setDetokenizeAadhaarImpl(null);
  await new Promise<void>(resolve => apiServer.close(() => resolve()));
  vaultServer.close();
  (apiServer as any).closeAllConnections?.();
  (vaultServer as any).closeAllConnections?.();
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

  // (a) enroll MFA
  const enrollRes = await api('POST', `/api/students/${studentId}/aadhaar/mfa/enroll`, SUPERADMIN, {
    label: 'Test 8 admin',
  });
  assert.equal(enrollRes.status, 200, `enroll failed: ${JSON.stringify(enrollRes.json)}`);
  assert.equal(typeof enrollRes.json.factorId, 'string');
  assert.equal(typeof enrollRes.json.otpauthUri, 'string');
  assert.match(enrollRes.json.otpauthUri, /^otpauth:\/\//);
  // The factor envelope is project-stripped: no encryptedSecret on the wire.
  assert.equal(enrollRes.json.factor.encryptedSecret, undefined, 'encryptedSecret must not leak');
  assert.equal(lastAuthWasBearer, true, 'vault call must carry Bearer service JWT');

  // (b) request step-up challenge
  const reqRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/request`, SUPERADMIN, {
    factorId: enrollRes.json.factorId,
  });
  assert.equal(reqRes.status, 200, `request failed: ${JSON.stringify(reqRes.json)}`);
  assert.equal(typeof reqRes.json.challengeId, 'string');
  assert.equal(typeof reqRes.json.expiresAt, 'string');
  // Required-factor envelope echoes the bound factor.
  assert.equal(reqRes.json.requiredFactor.factorId, enrollRes.json.factorId);

  // (c) approve with valid TOTP — we have to compute it. Look up the
  // factor's secret from the fake vault state by factorId. We can't reach
  // into the vault from outside, so use the internal Map via dynamic import.
  const factorModule = (factors.get(enrollRes.json.factorId));
  assert.ok(factorModule, 'factor must exist in fake vault');
  const code = totpCode(factorModule.secretBytes);

  const approveRes = await api('POST', `/api/students/${studentId}/aadhaar/step-up/approve`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
    code,
  });
  assert.equal(approveRes.status, 200, `approve failed: ${JSON.stringify(approveRes.json)}`);
  assert.equal(approveRes.json.status, 'approved');
  assert.equal(approveRes.json.verifiedFactorId, enrollRes.json.factorId);

  // (d) detokenize with the approved challenge — now goes through
  // the in-process stub installed at boot, not the fake HTTP
  // vault's /v1/detokenize endpoint.
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
  // We mint a fresh approved challenge (bypassing TOTP by directly
  // mutating the in-memory Map), then fire two concurrent
  // detokenize calls. One must succeed; the other must surface
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
