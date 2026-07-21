# Aadhaar Vault — Microservice (Session 1: Bootstrap)

> **Status:** Session 1 of 5 (reference-grade prototype per [`AADHAAR_VAULT_FREE_ARCHITECTURE.md`](../../AADHAAR_VAULT_FREE_ARCHITECTURE.md)).
> This commit ships the bootable scaffold: `docker compose up`, `npm test`,
> `npm run dev`, `GET /health` → 200. **No business logic, no crypto, no JWT,
> no MFA.** Those arrive in Sessions 2–5.

## What this is

This directory is an **isolated microservice** that implements the
`Aadhaar Vault` boundary described in
`AADHAAR_VAULT_FREE_ARCHITECTURE.md` §3.1. It runs alongside the existing
`backend/` (Express + Mongo), `frontend/` (Vite + React), and `Database/`
fixtures without touching them. Its only job is to tokenize FLN student
identity numbers (Aadhaar, Birth Certificate) so the rest of the FLN
stack never holds raw PII.

## Why it's isolated

- It uses **Fastify + PostgreSQL**, while the main backend uses **Express + Mongo**.
  This is a deliberate decision per the architecture doc (§3.3, §3.6) — the vault
  has different security, audit, and crypto requirements than the FLN backend.
- It lives under a new top-level `microservices/` directory. **Nothing outside
  this directory is modified.** No changes to `backend/`, `frontend/`,
  `Database/`, root `package.json`, or any existing `.env` file.

## Stack

| Layer | Choice | Why |
|---|---|---|
| Runtime | Node 20, TypeScript 5.6 (strict, ESM) | Matches repo conventions (`backend/package.json` uses `"type": "module"` + tsx) |
| Web framework | Fastify 4 | Architecture doc §3.3 commits to Fastify for `@fastify/swagger` schema-as-source-of-truth OpenAPI |
| Validation | Zod 3 | Same JSON Schema → OpenAPI pipeline |
| Logging | Pino 9 | Production-grade structured JSON logs with redaction |
| Tests | Vitest 2 | Node-native, TS-native, Fastify `inject()` compatibility |
| Database | PostgreSQL 16 (via Docker) | Architecture doc §3.6 — append-only audit + transactional chain integrity |
| Container | Multi-stage Dockerfile, Alpine | ~150 MB final image |

## Directory layout (Session 1 only)

```text
microservices/aadhaar-vault/
├── .gitignore
├── .dockerignore
├── .env.example
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── vitest.config.ts
├── docker-compose.yml
├── Dockerfile
├── README.md
├── src/
│   ├── config.ts          # Typed env loader (Zod). Refuses unsafe local-dev in production.
│   ├── logger.ts          # Pino logger; redacts 12-digit Aadhaar-shaped strings.
│   ├── server.ts          # Fastify bootstrap + graceful shutdown + route registration.
│   └── routes/
│       └── health.routes.ts   # GET /health, /health/live, /health/ready.
└── tests/
    └── boot.test.ts       # Verifies Fastify boots and /health returns 200.
```

Sessions 2–5 will add the schema, repositories, crypto, JWT/MFA, OpenAPI,
and full test suite under this directory.

## Quick start

```bash
cd microservices/aadhaar-vault

# 1. Bring up PostgreSQL
docker compose up -d postgres

# 2. Install JS dependencies
npm install

# 3. Run the boot test (verifies the Fastify stack)
npm test

# 4. Run the dev server
npm run dev
# Server is now on http://127.0.0.1:4101
```

## Smoke verification

Once the dev server is running, all three should return 200:

```bash
curl http://127.0.0.1:4101/health
# → {"status":"ok","service":"aadhaar-vault","version":"0.1.0","timestamp":"..."}

curl http://127.0.0.1:4101/health/live
# → {"status":"alive"}

curl http://127.0.0.1:4101/health/ready
# → {"status":"ready","checks":{"postgres":"deferred-session-2"}}
```

`/health/ready` intentionally reports `deferred-session-2` for the
PostgreSQL dependency. Sessions 2 wires up the actual readiness probe
against a live Postgres ping.

## Configuration

All env vars live in `.env.example`. Copy this file to `.env` and
customize locally. **`.env` is gitignored.** The actual values used at
runtime are validated by `src/config.ts` (Zod); invalid configuration
will refuse to start Fastify rather than silently accept defaults.

Key vars (Session 1 only — others are placeholders for Sessions 2+):

| Variable | Default | Purpose |
|---|---|---|
| `NODE_ENV` | `development` | Selected logger format + safety guards |
| `PORT` | `4101` | HTTP listen port (per architecture doc §4 Mode A) |
| `HOST` | `0.0.0.0` | Listen host |
| `LOG_LEVEL` | `info` | Pino level (`trace`…`fatal`) |

Safety guard (deferred to Session 3, but reserved here): when
`NODE_ENV=production`, the Vault refuses to start with
`KEY_PROVIDER=local-dev` unless `VAULT_ALLOW_UNSAFE_KEY_PROVIDER=true` is
explicitly set. See architecture doc §5.1.

## Validation status (Session 1)

After running `npm test`, you should see:

```text
✓ tests/boot.test.ts  (1 test)  ~120ms

Test Files  1 passed (1)
     Tests  1 passed (1)
  Duration  ~Xs
```

If you see this, the bootstrap is verified.

> **Test stack note (Session 2+):** subsequent sessions add the schema
> and four repository adapters under `src/db/adapters/`. Their tests
> run against an **in-process `MemoryPool`** (see
> `src/db/memory-pool.ts`) that pre-declares the four-table schema and
> parses the SQL the adapters actually emit. Anything outside that
> envelope throws, so a divergent query is caught in CI rather than
> silently returning the wrong rows. We do **not** use `pg-mem` — its
> parser hung on our production DDL (`BYTEA`, `JSONB`, `BIGSERIAL`,
> `timestamptz`, partial indexes). `pg` remains the production driver
> and runs the migrations against the bundled Postgres from
> `docker compose up postgres`.

## What is NOT in Session 1

Per the implementation rules: **all generated code compiles, no TODOs,
no pseudo-code, no duplicate utilities.** This means the following
features are **entirely absent** from this commit and only stubs would
exist if I tried to include them:

- ❌ Tokenization endpoint `POST /v1/tokenize`
- ❌ Lookup endpoint `GET /v1/lookup/:token`
- ❌ Detokenize endpoint `POST /v1/detokenize`
- ❌ Audit chain
- ❌ JWT / JWKS verification
- ❌ TOTP / MFA
- ❌ OpenAPI generation
- ❌ Rate limiting
- ❌ Repositories or migrations

These land in Sessions 2–5, in that order. Each session will be a
self-contained, reviewable commit.

## Architecture reference

- [`AADHAAR_VAULT_FREE_ARCHITECTURE.md`](../../AADHAAR_VAULT_FREE_ARCHITECTURE.md) — canonical architecture, v0.2.

## License

TBD by upstream project.