// Aadhaar Vault client — shared by the backend's route modules.
//
// Moves raw Aadhaar out of the primary request path: on student registration
// the backend calls the vault's POST /v1/tokenize and persists only a mask,
// an opaque token, and a deterministic identity id. This module is the single
// integration point for the Aadhaar Vault microservice
// (microservices/aadhaar-vault/), so route modules can call it without
// creating a circular dependency on index.ts.
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const AADHAAR_VAULT_URL = (process.env.AADHAAR_VAULT_URL || 'http://127.0.0.1:4101').replace(/\/+$/, '');
const AADHAAR_VAULT_SERVICE_JWT_SECRET = process.env.AADHAAR_VAULT_SERVICE_JWT_SECRET;
const AADHAAR_VAULT_SERVICE_JWT_ISSUER = process.env.AADHAAR_VAULT_SERVICE_JWT_ISSUER;
const AADHAAR_VAULT_SERVICE_JWT_AUDIENCE = process.env.AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;
const AADHAAR_VAULT_SERVICE_JWT_SUBJECT = process.env.AADHAAR_VAULT_SERVICE_JWT_SUBJECT || 'fln-backend-service';

export type AadhaarVaultTokenizeResult = {
  token: string;
  last4: string;
  tokenType: string;
  identityId: string;
  auditId: string;
  keyVersion: string | number;
};

/** XXXX-XXXX-<last4> — the only Aadhaar representation allowed at rest. */
export function formatAadhaarMask(rawAadhar: string): string {
  const digits = rawAadhar.replace(/[^0-9]/g, '');
  return 'XXXX-XXXX-' + digits.slice(-4);
}

function buildVaultServiceJwt(): string {
  if (!AADHAAR_VAULT_SERVICE_JWT_SECRET) {
    throw new Error('AADHAAR_VAULT_SERVICE_JWT_SECRET is not configured');
  }

  const signingOptions: jwt.SignOptions = {
    algorithm: 'HS256',
    expiresIn: '5m',
  };
  if (AADHAAR_VAULT_SERVICE_JWT_ISSUER) signingOptions.issuer = AADHAAR_VAULT_SERVICE_JWT_ISSUER;
  if (AADHAAR_VAULT_SERVICE_JWT_AUDIENCE) signingOptions.audience = AADHAAR_VAULT_SERVICE_JWT_AUDIENCE;

  return jwt.sign(
    {
      sub: AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
      scope: 'vault:tokenize',
    },
    AADHAAR_VAULT_SERVICE_JWT_SECRET,
    signingOptions,
  );
}

export type AadhaarTokenizeContext = {
  email?: string;
  sourceIp?: string;
  userAgent?: string;
  requestId?: string;
};

/**
 * Tokenize a raw 12-digit Aadhaar with the Aadhaar Vault microservice.
 * The raw value is sent to the vault over HTTPS and is never stored in the
 * FLN backend's own database. Throws on vault error.
 */
export async function tokenizeAadhaar(
  rawAadhar: string,
  context: AadhaarTokenizeContext = {},
): Promise<AadhaarVaultTokenizeResult> {
  const token = buildVaultServiceJwt();
  const response = await fetch(`${AADHAAR_VAULT_URL}/v1/tokenize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      raw: rawAadhar,
      type: 'AADHAAR',
      context: {
        actorId: AADHAAR_VAULT_SERVICE_JWT_SUBJECT,
        actorRole: 'SERVICE',
        reason: `Aadhaar tokenization for student registration by ${context.email || 'unknown user'}`,
        requestId: context.requestId || `fln-${randomUUID()}`,
        sourceIp: context.sourceIp,
        userAgent: context.userAgent,
      },
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = data?.error || 'vault_tokenization_failed';
    const message = data?.message || 'Aadhaar vault tokenization failed.';
    throw new Error(`${error}: ${message}`);
  }

  return data as AadhaarVaultTokenizeResult;
}
