import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';

const tokenPartPattern = /^[A-Za-z0-9_-]+$/;
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const identityPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface WorkloadVerificationKey {
  kid: string;
  publicKeyBase64: string;
}

export interface WorkloadTokenIssuerOptions {
  issuer: string;
  audience: string;
  keyId: string;
  privateKeyBase64: string;
  ttlSeconds?: number;
  clock?: () => Date;
  idGenerator?: () => string;
}

export interface WorkloadTokenVerifierOptions {
  issuer: string;
  audience: string;
  keys: readonly WorkloadVerificationKey[];
  maxTtlSeconds?: number;
  clockSkewSeconds?: number;
  clock?: () => Date;
}

export class Ed25519WorkloadTokenIssuer {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly keyId: string;
  private readonly privateKey: KeyObject;
  private readonly ttlSeconds: number;
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;

  constructor(options: WorkloadTokenIssuerOptions) {
    this.issuer = identity(options.issuer, 'issuer');
    this.audience = identity(options.audience, 'audience');
    this.keyId = keyId(options.keyId);
    this.privateKey = createPrivateKey({
      key: decodeKeyMaterial(options.privateKeyBase64, 'private'),
      format: 'der',
      type: 'pkcs8',
    });
    if (this.privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('Workload signing key must be Ed25519.');
    }
    this.ttlSeconds = boundedInteger(options.ttlSeconds ?? 60, 10, 300, 'token TTL');
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? randomUUID;
  }

  issue(): string {
    const issuedAt = epochSeconds(this.clock());
    const tokenId = this.idGenerator();
    if (!uuidPattern.test(tokenId)) {
      throw new Error('Workload token ID must be a UUID.');
    }
    const header = encodeJson({ alg: 'EdDSA', kid: this.keyId, typ: 'dirizhor-workload+jwt' });
    const payload = encodeJson({
      v: 1,
      iss: this.issuer,
      aud: this.audience,
      iat: issuedAt,
      nbf: issuedAt,
      exp: issuedAt + this.ttlSeconds,
      jti: tokenId,
    });
    const signingInput = `${header}.${payload}`;
    const signature = sign(null, Buffer.from(signingInput, 'ascii'), this.privateKey);
    return `${signingInput}.${signature.toString('base64url')}`;
  }
}

export class Ed25519WorkloadTokenVerifier {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly keys: ReadonlyMap<string, KeyObject>;
  private readonly maxTtlSeconds: number;
  private readonly clockSkewSeconds: number;
  private readonly clock: () => Date;

  constructor(options: WorkloadTokenVerifierOptions) {
    this.issuer = identity(options.issuer, 'issuer');
    this.audience = identity(options.audience, 'audience');
    if (options.keys.length < 1 || options.keys.length > 8) {
      throw new Error('Workload verification keyset must contain 1 through 8 keys.');
    }
    const keys = new Map<string, KeyObject>();
    for (const candidate of options.keys) {
      const kid = keyId(candidate.kid);
      if (keys.has(kid)) {
        throw new Error('Workload verification key IDs must be unique.');
      }
      const publicKey = createPublicKey({
        key: decodeKeyMaterial(candidate.publicKeyBase64, 'public'),
        format: 'der',
        type: 'spki',
      });
      if (publicKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('Workload verification keys must be Ed25519.');
      }
      keys.set(kid, publicKey);
    }
    this.keys = keys;
    this.maxTtlSeconds = boundedInteger(
      options.maxTtlSeconds ?? 300,
      10,
      300,
      'maximum token TTL',
    );
    this.clockSkewSeconds = boundedInteger(
      options.clockSkewSeconds ?? 5,
      0,
      30,
      'clock skew',
    );
    this.clock = options.clock ?? (() => new Date());
  }

  verify(token: string): void {
    try {
      if (token.length < 32 || token.length > 4096) throw new Error('token length');
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('token shape');
      const [encodedHeader, encodedPayload, encodedSignature] = parts;
      if (
        encodedHeader === undefined ||
        encodedPayload === undefined ||
        encodedSignature === undefined
      ) {
        throw new Error('token shape');
      }
      const header = parseJsonPart(encodedHeader);
      exactKeys(header, ['alg', 'kid', 'typ']);
      if (
        header.alg !== 'EdDSA' ||
        header.typ !== 'dirizhor-workload+jwt' ||
        typeof header.kid !== 'string'
      ) {
        throw new Error('token header');
      }
      const publicKey = this.keys.get(header.kid);
      if (publicKey === undefined) throw new Error('unknown key');
      const signature = decodePart(encodedSignature);
      if (
        !verify(
          null,
          Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
          publicKey,
          signature,
        )
      ) {
        throw new Error('signature');
      }

      const payload = parseJsonPart(encodedPayload);
      exactKeys(payload, ['aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'v']);
      if (
        payload.v !== 1 ||
        payload.iss !== this.issuer ||
        payload.aud !== this.audience ||
        typeof payload.iat !== 'number' ||
        typeof payload.nbf !== 'number' ||
        typeof payload.exp !== 'number' ||
        !Number.isSafeInteger(payload.iat) ||
        !Number.isSafeInteger(payload.nbf) ||
        !Number.isSafeInteger(payload.exp) ||
        payload.nbf !== payload.iat ||
        payload.exp <= payload.iat ||
        payload.exp - payload.iat > this.maxTtlSeconds ||
        typeof payload.jti !== 'string' ||
        !uuidPattern.test(payload.jti)
      ) {
        throw new Error('token claims');
      }
      const now = epochSeconds(this.clock());
      if (
        payload.iat > now + this.clockSkewSeconds ||
        payload.nbf > now + this.clockSkewSeconds ||
        payload.exp <= now - this.clockSkewSeconds
      ) {
        throw new Error('token lifetime');
      }
    } catch {
      throw new Error('Workload token is invalid.');
    }
  }
}

export function parseWorkloadVerificationKeyset(value: string): WorkloadVerificationKey[] {
  let document: unknown;
  try {
    document = JSON.parse(value);
  } catch {
    throw new Error('Workload verification keyset must be valid JSON.');
  }
  if (!isRecord(document)) {
    throw new Error('Workload verification keyset must be an object.');
  }
  exactKeys(document, ['keys', 'schema_version']);
  if (document.schema_version !== 1 || !Array.isArray(document.keys)) {
    throw new Error('Workload verification keyset schema is invalid.');
  }
  return document.keys.map((candidate) => {
    if (!isRecord(candidate)) {
      throw new Error('Workload verification key must be an object.');
    }
    exactKeys(candidate, ['kid', 'public_key_base64']);
    if (typeof candidate.kid !== 'string' || typeof candidate.public_key_base64 !== 'string') {
      throw new Error('Workload verification key fields are invalid.');
    }
    return { kid: keyId(candidate.kid), publicKeyBase64: candidate.public_key_base64 };
  });
}

function parseJsonPart(value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(decodePart(value).toString('utf8'));
  if (!isRecord(parsed)) throw new Error('token JSON');
  return parsed;
}

function encodeJson(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodePart(value: string): Buffer {
  if (!tokenPartPattern.test(value)) throw new Error('token encoding');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error('token encoding');
  return decoded;
}

function decodeKeyMaterial(value: string, label: string): Buffer {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Workload ${label} key must be canonical base64.`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length < 32 || decoded.toString('base64') !== value) {
    throw new Error(`Workload ${label} key must be canonical base64.`);
  }
  return decoded;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new Error('object fields');
  }
}

function identity(value: string, label: string): string {
  if (!identityPattern.test(value)) throw new Error(`Workload ${label} is invalid.`);
  return value;
}

function keyId(value: string): string {
  if (!keyIdPattern.test(value)) throw new Error('Workload key ID is invalid.');
  return value;
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Workload ${label} must be an integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

function epochSeconds(value: Date): number {
  const milliseconds = value.getTime();
  if (!Number.isFinite(milliseconds)) throw new Error('Workload clock returned an invalid date.');
  return Math.floor(milliseconds / 1000);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
