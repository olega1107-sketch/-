import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

import { sha256Bytes } from './canonical.js';
import type { DocumentStore, DocumentVersionBytes, StagedDocument } from './ports.js';

export class FileDocumentStore implements DocumentStore {
  private readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
  }

  async initialize(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await chmod(this.root, 0o700);
    await this.checkReady();
  }

  async checkReady(): Promise<void> {
    await access(this.root, constants.R_OK | constants.W_OK);
  }

  async readImmutable(storageUri: string): Promise<DocumentVersionBytes> {
    return { bytes: await readFile(this.resolveStorageUri(storageUri)) };
  }

  async stageAgentResult(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<StagedDocument> {
    return this.stageImmutableDocument(deterministicKey, content, contentType, expectedHash);
  }

  async stageImmutableDocument(
    deterministicKey: string,
    content: Uint8Array,
    contentType: string,
    expectedHash: string,
  ): Promise<StagedDocument> {
    if (contentType.length === 0 || sha256Bytes(content) !== expectedHash) {
      throw new Error('Immutable document staging metadata is invalid.');
    }
    const destination = this.resolveStorageUri(deterministicKey);
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    await chmod(this.root, 0o700);

    try {
      const existing = await readFile(destination);
      if (sha256Bytes(existing) !== expectedHash) {
        throw new Error('Deterministic result key contains different bytes.');
      }
      return { storageUri: deterministicKey };
    } catch (error) {
      if (!isNodeError(error) || error.code !== 'ENOENT') {
        throw error;
      }
    }

    const temporary = `${destination}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try {
        await handle.writeFile(content);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temporary, destination);
      return { storageUri: deterministicKey };
    } catch (error) {
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }

  private resolveStorageUri(storageUri: string): string {
    if (storageUri.length === 0 || path.isAbsolute(storageUri) || storageUri.includes('\0')) {
      throw new Error('Document storage URI must be a relative key.');
    }
    const resolved = path.resolve(this.root, storageUri);
    const relative = path.relative(this.root, resolved);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('Document storage URI escapes the configured root.');
    }
    return resolved;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
