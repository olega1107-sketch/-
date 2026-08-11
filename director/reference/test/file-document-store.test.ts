import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { sha256Bytes } from '../src/canonical.js';
import { FileDocumentStore } from '../src/file-document-store.js';

describe('FileDocumentStore', () => {
  let temporaryDirectory: string | undefined;

  afterEach(async () => {
    if (temporaryDirectory !== undefined) {
      await rm(temporaryDirectory, { recursive: true, force: true });
      temporaryDirectory = undefined;
    }
  });

  it('stages deterministic content atomically with restrictive permissions', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'dirizhor-director-'));
    const root = path.join(temporaryDirectory, 'store');
    const store = new FileDocumentStore(root);
    const content = Buffer.from('verified result', 'utf8');
    const hash = sha256Bytes(content);
    const key = `agent-results/run/${hash}`;

    await expect(
      store.stageAgentResult(key, content, 'text/plain', hash),
    ).resolves.toEqual({ storageUri: key });
    await expect(
      store.stageAgentResult(key, content, 'text/plain', hash),
    ).resolves.toEqual({ storageUri: key });
    await expect(store.readImmutable(key)).resolves.toEqual({ bytes: content });

    const rootMode = (await stat(root)).mode & 0o777;
    const fileMode = (await stat(path.join(root, key))).mode & 0o777;
    expect(rootMode).toBe(0o700);
    expect(fileMode).toBe(0o600);
  });

  it('rejects path traversal and deterministic key collisions', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'dirizhor-director-'));
    const store = new FileDocumentStore(path.join(temporaryDirectory, 'store'));
    const first = Buffer.from('first', 'utf8');
    const second = Buffer.from('second', 'utf8');

    await store.stageAgentResult('results/fixed', first, 'text/plain', sha256Bytes(first));
    await expect(
      store.stageAgentResult('results/fixed', second, 'text/plain', sha256Bytes(second)),
    ).rejects.toThrow('different bytes');
    await expect(store.readImmutable('../outside')).rejects.toThrow('escapes');
    await expect(store.readImmutable('/absolute/path')).rejects.toThrow('relative key');
  });
});
