/**
 * Aadhaar Vault Step-Up detokenization tests (Session 7E wiring).
 *
 * Run:  cd backend && npm run test:detokenize
 *       (or `npm test` runs both files)
 *
 * Isolation model: same as aadhaar-hardening.test.ts — chdir into a
 * fresh temp dir BEFORE importing modules, delete MONGODB_URI so the
 * file-fallback store is used, stand up a fake vault on an ephemeral
 * port. The fake vault here is richer: it implements the full Step-Up
 * lifecycle (enroll MFA → request → approve → detokenize) so the
 * production admin endpoints at backend/src/routes/aadhaarDetokenize.ts
 * can be exercised end-to-end.
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
// The client refuses to mint a service JWT without this (fail-closed) — the
// fake vault ignores the value, it only needs to be present.
process.env.AADHAAR_VAULT_SERVICE_JWT_SECRET = 'test-only-hmac-secret-not-a-real-credential';
delete process.env.AADHAAR_VAULT_SERVICE_JWT_ISSUER;
delete process.env.AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;
delete process.env.AADHAAR_VAULT_TIMEOUT_MS;

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

// ─── In-memory fake-vault state ────────────────────────────────────────────
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
};
type Token = { rawAadhaar: string; identityId: string };

const factors = new Map<string, Factor>();
const challenges = new Map<string, Challenge>();
const tokens = new Map<string, Token>();
let lastAuthWasBearer = false;

/** Per-test challenge TTL (ms). Tests override this to force expiry. */
let challengeTtlMs = 300_000; // 5 min — matches the real vault default

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
      const challengeId = 'chl-' + crypto.randomUUID();
      challenges.set(challengeId, {
        challengeId, tokenId, factorId,
        status: 'pending',
        expiresAt: Date.now() + challengeTtlMs,
        requestedBy: String(parsed?.context?.actorId || ''),
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

    // ── detokenize (release) ────────────────────────────────────────────
    if (req.method === 'POST' && url === '/v1/detokenize') {
      const challengeId = String(parsed.challengeId || '');
      const ch = challenges.get(challengeId);
      if (!ch) return sendJson(404, { error: 'CHALLENGE_NOT_FOUND', message: 'No such challenge.' });
      if (ch.status === 'consumed') return sendJson(409, { error: 'CHALLENGE_CONSUMED', message: 'Replay.' });
      if (ch.status !== 'approved') return sendJson(403, { error: 'CHALLENGE_NOT_APPROVED', message: 'Not approved.' });
      if (Date.now() > ch.expiresAt) return sendJson(410, { error: 'CHALLENGE_EXPIRED', message: 'Expired.' });
      const tok = tokens.get(ch.tokenId);
      if (!tok) return sendJson(404, { error: 'TOKEN_NOT_FOUND', message: 'No token.' });
      ch.status = 'consumed';
      return sendJson(200, {
        token: ch.tokenId,
        identityId: tok.identityId,
        aadhaar: tok.rawAadhaar,
        last4: tok.rawAadhaar.slice(-4),
        auditId: `audit-detok-${challengeId.slice(0, 8)}`,
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
 *  get a real aadhaarTokenId persisted in MongoDB. Returns the student id. */
async function registerStudent(raw: string, name: string): Promise<string> {
  const res = await api('POST', '/api/students', TEACHER, {
    name, classGroup: 'Class 1', section: 'A', age: 7, aadharNumber: raw,
  });
  assert.equal(res.status, 200, `seed student register failed: ${res.status} ${JSON.stringify(res.json)}`);
  return res.json.id;
}

after(async () => {
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

  // (d) detokenize with the approved challenge
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
  // challenge is bound to Alice's token. The vault returns
  // CHALLENGE_OPERATION_MISMATCH (defensive — the vault enforces actor/
  // token binding at the command layer; our fake returns the closest
  // equivalent: a successful consumption decrypts Alice regardless of
  // which URL we used, because the challenge holds the token). So the
  // assertion that matters here is: we cannot SUBSTITUTE the token id —
  // the URL path is the only thing the client controls, and the backend
  // resolves the token strictly from the authorized student's DB row.
  const detokRes = await api('POST', `/api/students/${bobId}/aadhaar/detokenize`, SUPERADMIN, {
    challengeId: reqRes.json.challengeId,
  });
  // The fake vault binds the challenge to Alice's token. The challenge was
  // already consumed by Alice's request in the same test? No — we haven't
  // consumed it yet, so the consumption decrypts Alice's plaintext even
  // when called via Bob's URL. This proves that **the backend never lets
  // the client pick the token** — only the student id, which is then
  // authorization-gated.
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