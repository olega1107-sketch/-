import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  StaticBearerAuthenticator,
  WorkloadIdentityAuthenticator,
} from '../src/service-auth.js';
import {
  Ed25519WorkloadTokenIssuer,
  Ed25519WorkloadTokenVerifier,
  parseWorkloadVerificationKeyset,
} from '../src/workload-identity.js';

describe('Director service authentication configuration', () => {
  it('requires an explicit peer identity when mutual TLS is enabled', () => {
    expect(
      () => new StaticBearerAuthenticator({ token: 'gateway-service-token' }),
    ).toThrow(/allowed Gateway certificate Common Name/);
  });

  it('accepts a fresh audience-bound token and rejects expiry, wrong audience, and tampering', () => {
    const keys = keyPair('gateway-key-current');
    const now = new Date('2026-08-12T12:00:00.000Z');
    const verifier = new Ed25519WorkloadTokenVerifier({
      issuer: 'agent-gateway',
      audience: 'director-api',
      keys: [keys.verification],
      clockSkewSeconds: 0,
      clock: () => now,
    });
    const authenticator = new WorkloadIdentityAuthenticator({
      verifier,
      requireMutualTls: false,
    });
    const fresh = issuer(keys, now, 'director-api').issue();
    expect(() => authenticator.authenticate({ authorization: `Bearer ${fresh}`, socket: {} })).not.toThrow();

    const expired = issuer(keys, new Date(now.getTime() - 61_000), 'director-api').issue();
    const wrongAudience = issuer(keys, now, 'agent-gateway').issue();
    const tampered = `${fresh.slice(0, -1)}${fresh.endsWith('A') ? 'B' : 'A'}`;
    for (const token of [expired, wrongAudience, tampered]) {
      expect(() => authenticator.authenticate({ authorization: `Bearer ${token}`, socket: {} })).toThrow(/invalid/);
    }
  });

  it('supports overlap rotation and strict verification-keyset parsing', () => {
    const oldKeys = keyPair('gateway-key-old');
    const currentKeys = keyPair('gateway-key-current');
    const now = new Date('2026-08-12T12:00:00.000Z');
    const parsed = parseWorkloadVerificationKeyset(JSON.stringify({
      schema_version: 1,
      keys: [oldKeys.document, currentKeys.document],
    }));
    const verifier = new Ed25519WorkloadTokenVerifier({
      issuer: 'agent-gateway',
      audience: 'director-api',
      keys: parsed,
      clock: () => now,
    });
    expect(() => verifier.verify(issuer(oldKeys, now, 'director-api').issue())).not.toThrow();
    expect(() => verifier.verify(issuer(currentKeys, now, 'director-api').issue())).not.toThrow();
    expect(() => parseWorkloadVerificationKeyset('{"schema_version":1,"keys":[],"extra":true}')).toThrow(/fields/);
  });
});

function issuer(keys: ReturnType<typeof keyPair>, now: Date, audience: string) {
  return new Ed25519WorkloadTokenIssuer({
    issuer: 'agent-gateway',
    audience,
    keyId: keys.verification.kid,
    privateKeyBase64: keys.privateKeyBase64,
    ttlSeconds: 60,
    clock: () => now,
    idGenerator: () => '11111111-1111-4111-8111-111111111111',
  });
}

function keyPair(kid: string) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyBase64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  return {
    privateKeyBase64: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    verification: { kid, publicKeyBase64 },
    document: { kid, public_key_base64: publicKeyBase64 },
  };
}
