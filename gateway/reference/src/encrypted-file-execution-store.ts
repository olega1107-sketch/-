import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, mkdir, open, readdir, readFile, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

import type { ExecutionRecord, ExecutionStore } from './ports.js';

interface EncryptedEnvelope {
  version: 1;
  iv: string;
  tag: string;
  ciphertext: string;
}

export class EncryptedFileExecutionStore implements ExecutionStore {
  private readonly key: Buffer;

  constructor(
    private readonly directory: string,
    key: Uint8Array,
  ) {
    if (key.byteLength !== 32) {
      throw new Error('Execution store key must contain exactly 32 bytes.');
    }
    this.key = Buffer.from(key);
  }

  static keyFromBase64(value: string): Buffer {
    const key = Buffer.from(value, 'base64');
    if (key.byteLength !== 32 || key.toString('base64') !== value) {
      throw new Error('GATEWAY_SPOOL_KEY_BASE64 must be canonical base64 for 32 bytes.');
    }
    return key;
  }

  async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    await this.checkReady();
  }

  async checkReady(): Promise<void> {
    await access(this.directory, constants.R_OK | constants.W_OK);
  }

  async load(agentRunId: string): Promise<ExecutionRecord | undefined> {
    try {
      const serialized = await readFile(this.recordPath(agentRunId), 'utf8');
      return this.decrypt(JSON.parse(serialized) as EncryptedEnvelope);
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') {
        return undefined;
      }
      throw error;
    }
  }

  async save(record: ExecutionRecord): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    const destination = this.recordPath(record.agentRunId);
    const temporary = `${destination}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify(this.encrypt(record)), 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temporary, destination);
      const directoryHandle = await open(this.directory, 'r');
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    } catch (error) {
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }

  async listPending(): Promise<ExecutionRecord[]> {
    try {
      const names = await readdir(this.directory);
      const records = await Promise.all(
        names
          .filter((name) => name.endsWith('.json'))
          .map((name) => this.load(name.slice(0, -'.json'.length))),
      );
      return records.filter(
        (record): record is ExecutionRecord =>
          record !== undefined && !['completed', 'failed', 'cancelled'].includes(record.phase),
      );
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  private recordPath(agentRunId: string): string {
    if (!/^[0-9a-fA-F-]{36}$/.test(agentRunId)) {
      throw new Error('Invalid agent run ID for execution store path.');
    }
    return path.join(this.directory, `${agentRunId}.json`);
  }

  private encrypt(record: ExecutionRecord): EncryptedEnvelope {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const plaintext = Buffer.from(JSON.stringify(record), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      version: 1,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
  }

  private decrypt(envelope: EncryptedEnvelope): ExecutionRecord {
    if (envelope.version !== 1) {
      throw new Error('Unsupported encrypted execution record version.');
    }
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(envelope.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString('utf8')) as ExecutionRecord;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
