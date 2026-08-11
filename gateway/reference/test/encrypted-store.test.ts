import { readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';

import { EncryptedFileExecutionStore } from '../src/encrypted-file-execution-store.js';
import type { ExecutionRecord } from '../src/ports.js';
import { executionFixture } from './helpers.js';

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
});

describe('EncryptedFileExecutionStore', () => {
  it('round-trips an encrypted record through an atomic private file', async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'dirizhor-gateway-'));
    directories.push(directory);
    const store = new EncryptedFileExecutionStore(directory, Buffer.alloc(32, 7));
    const fixture = executionFixture();
    const record: ExecutionRecord = {
      version: 1,
      agentRunId: fixture.agentRunId,
      requestFingerprint: fixture.request.request_fingerprint,
      acceptedAt: '2026-08-10T10:00:00.000Z',
      phase: 'accepted',
      eventIds: [],
      request: fixture.request,
      context: fixture.bundle,
    };

    await store.save(record);

    const file = path.join(directory, `${fixture.agentRunId}.json`);
    const serialized = await readFile(file, 'utf8');
    expect(serialized).not.toContain(fixture.request.purpose);
    expect(serialized).not.toContain(fixture.bundle.items[0]!.content);
    expect((await stat(directory)).mode & 0o777).toBe(0o700);
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    await expect(store.load(fixture.agentRunId)).resolves.toEqual(record);
    await expect(store.listPending()).resolves.toHaveLength(1);
  });
});
