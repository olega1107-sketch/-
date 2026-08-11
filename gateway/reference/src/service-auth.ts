import { timingSafeEqual } from 'node:crypto';
import { TLSSocket } from 'node:tls';

import { GatewayProtocolError } from './errors.js';
import type { ServiceAuthenticator, ServiceAuthInput } from './ports.js';
import type { Ed25519WorkloadTokenVerifier } from './workload-identity.js';

export interface StaticBearerAuthenticatorOptions {
  token: string;
  requireMutualTls?: boolean;
  allowedPeerCommonNames?: readonly string[];
}

/** Reference verifier. Production should inject a short-lived workload-token verifier. */
export class StaticBearerAuthenticator implements ServiceAuthenticator {
  private readonly expectedToken: Buffer;
  private readonly requireMutualTls: boolean;
  private readonly allowedPeerCommonNames: ReadonlySet<string>;

  constructor(options: StaticBearerAuthenticatorOptions) {
    if (options.token.length === 0) {
      throw new Error('Director bearer token must not be empty.');
    }
    this.expectedToken = Buffer.from(options.token, 'utf8');
    this.requireMutualTls = options.requireMutualTls ?? true;
    this.allowedPeerCommonNames = new Set(options.allowedPeerCommonNames ?? []);
    if (this.requireMutualTls && this.allowedPeerCommonNames.size === 0) {
      throw new Error('At least one allowed Director certificate Common Name is required.');
    }
  }

  authenticate(input: ServiceAuthInput): void {
    this.verifyBearer(input.authorization);
    if (!this.requireMutualTls) {
      return;
    }
    if (!(input.socket instanceof TLSSocket) || !input.socket.authorized) {
      throw new GatewayProtocolError(
        401,
        'unauthorized_service',
        'A verified mutual TLS connection is required.',
      );
    }
    const commonName = input.socket.getPeerCertificate().subject?.CN;
    const commonNames = Array.isArray(commonName) ? commonName : [commonName];
    if (!commonNames.some((name) => name !== undefined && this.allowedPeerCommonNames.has(name))) {
      throw new GatewayProtocolError(403, 'access_denied', 'The caller service is not allowed.');
    }
  }

  private verifyBearer(authorization: string | undefined): void {
    const prefix = 'Bearer ';
    if (authorization === undefined || !authorization.startsWith(prefix)) {
      throw new GatewayProtocolError(401, 'unauthorized_service', 'Service bearer is required.');
    }
    const received = Buffer.from(authorization.slice(prefix.length), 'utf8');
    if (
      received.byteLength !== this.expectedToken.byteLength ||
      !timingSafeEqual(received, this.expectedToken)
    ) {
      throw new GatewayProtocolError(401, 'unauthorized_service', 'Service bearer is invalid.');
    }
  }
}

export interface WorkloadIdentityAuthenticatorOptions {
  verifier: Ed25519WorkloadTokenVerifier;
  requireMutualTls?: boolean;
  allowedPeerCommonNames?: readonly string[];
}

export class WorkloadIdentityAuthenticator implements ServiceAuthenticator {
  private readonly verifier: Ed25519WorkloadTokenVerifier;
  private readonly requireMutualTls: boolean;
  private readonly allowedPeerCommonNames: ReadonlySet<string>;

  constructor(options: WorkloadIdentityAuthenticatorOptions) {
    this.verifier = options.verifier;
    this.requireMutualTls = options.requireMutualTls ?? true;
    this.allowedPeerCommonNames = new Set(options.allowedPeerCommonNames ?? []);
    if (this.requireMutualTls && this.allowedPeerCommonNames.size === 0) {
      throw new Error('At least one allowed Director certificate Common Name is required.');
    }
  }

  authenticate(input: ServiceAuthInput): void {
    const match = input.authorization?.match(/^Bearer[ \t]+([^ \t]+)$/i);
    if (match?.[1] === undefined) {
      throw new GatewayProtocolError(401, 'unauthorized_service', 'Workload token is required.');
    }
    try {
      this.verifier.verify(match[1]);
    } catch {
      throw new GatewayProtocolError(401, 'unauthorized_service', 'Workload token is invalid.');
    }
    if (!this.requireMutualTls) return;
    if (!(input.socket instanceof TLSSocket) || !input.socket.authorized) {
      throw new GatewayProtocolError(
        401,
        'unauthorized_service',
        'A verified mutual TLS connection is required.',
      );
    }
    const commonName = input.socket.getPeerCertificate().subject?.CN;
    const commonNames = Array.isArray(commonName) ? commonName : [commonName];
    if (!commonNames.some((name) => name !== undefined && this.allowedPeerCommonNames.has(name))) {
      throw new GatewayProtocolError(403, 'access_denied', 'The caller service is not allowed.');
    }
  }
}
