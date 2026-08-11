import { createHmac } from 'node:crypto';

import type { CapabilityTokenIssuer } from './task-ports.js';

export class HmacCapabilityTokenIssuer implements CapabilityTokenIssuer {
  private readonly key: Buffer;

  constructor(key: Uint8Array) {
    if (key.byteLength !== 32) {
      throw new Error('Capability token key must contain exactly 32 bytes.');
    }
    this.key = Buffer.from(key);
  }

  static keyFromBase64(value: string): Buffer {
    const key = Buffer.from(value, 'base64');
    if (key.byteLength !== 32 || key.toString('base64') !== value) {
      throw new Error('DIRECTOR_CAPABILITY_KEY_BASE64 must be canonical base64 for 32 bytes.');
    }
    return key;
  }

  issue(capabilityId: string): string {
    const mac = createHmac('sha256', this.key)
      .update('dirizhor-capability-v1\0', 'utf8')
      .update(capabilityId, 'utf8')
      .digest('base64url');
    return `cap_v1.${mac}`;
  }
}
