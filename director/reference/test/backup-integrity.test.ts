import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  copyVerifiedDocumentStore,
  verifyDocumentStoreBackup,
} from '../src/backup-integrity.js';
import { sha256Bytes } from '../src/canonical.js';
import {
  createDirectorFixture,
  type DirectorFixture,
} from './helpers.js';

describe('backup Document Store integrity', () => {
  let fixture: DirectorFixture | undefined;
  let temporaryDirectory: string | undefined;

  afterEach(async () => {
    await fixture?.close();
    if (temporaryDirectory !== undefined) {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
    fixture = undefined;
    temporaryDirectory = undefined;
  });

  it('verifies and copies every database-referenced immutable file', async () => {
    ({ fixture, temporaryDirectory } = await preparedStore());
    const sourceRoot = path.join(temporaryDirectory, 'source');
    const verified = await verifyDocumentStoreBackup(fixture.database, sourceRoot);

    expect(verified.evidence).toMatchObject({
      referenceCount: 1,
      uniqueFileCount: 1,
      totalBytes: Buffer.byteLength(fixture.contextContent),
    });
    expect(verified.evidence.manifestHash).toMatch(/^sha256:[0-9a-f]{64}$/);

    const destinationRoot = path.join(temporaryDirectory, 'restored');
    await copyVerifiedDocumentStore(verified.files, destinationRoot);
    await expect(
      verifyDocumentStoreBackup(fixture.database, destinationRoot),
    ).resolves.toMatchObject({ evidence: verified.evidence });
  });

  it('rejects changed bytes and symlink escapes', async () => {
    ({ fixture, temporaryDirectory } = await preparedStore());
    const sourceRoot = path.join(temporaryDirectory, 'source');
    const storagePath = path.join(sourceRoot, 'documents/architecture-v1.md');
    await writeFile(storagePath, 'changed bytes', { mode: 0o600 });
    await expect(
      verifyDocumentStoreBackup(fixture.database, sourceRoot),
    ).rejects.toThrow(/metadata|hash/);

    const outside = path.join(temporaryDirectory, 'outside.md');
    await writeFile(outside, fixture.contextContent, { mode: 0o600 });
    await rm(storagePath);
    await symlink(outside, storagePath);
    await expect(
      verifyDocumentStoreBackup(fixture.database, sourceRoot),
    ).rejects.toThrow(/outside|metadata/);
  });
});

async function preparedStore(): Promise<{
  fixture: DirectorFixture;
  temporaryDirectory: string;
}> {
  const fixture = await createDirectorFixture();
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'dirizhor-backup-'));
  const documentDirectory = path.join(temporaryDirectory, 'source/documents');
  await mkdir(documentDirectory, { recursive: true, mode: 0o700 });
  const bytes = Buffer.from(fixture.contextContent, 'utf8');
  expect(sha256Bytes(bytes)).toMatch(/^sha256:[0-9a-f]{64}$/);
  await writeFile(path.join(documentDirectory, 'architecture-v1.md'), bytes, {
    mode: 0o600,
  });
  return { fixture, temporaryDirectory };
}
