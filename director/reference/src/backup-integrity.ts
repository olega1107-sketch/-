import { createHash } from 'node:crypto';
import { createReadStream, constants } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { hashCanonical } from './canonical.js';
import type { SqlQueryable } from './ports.js';

interface StorageReferenceRow {
  referenceType: 'agent_run_result' | 'document_version';
  referenceId: string;
  storageUri: string;
  contentHash: string;
  sizeBytes: number | string;
}

export interface VerifiedStorageFile {
  storageUri: string;
  absolutePath: string;
  contentHash: string;
  sizeBytes: number;
}

export interface DocumentStoreEvidence {
  referenceCount: number;
  uniqueFileCount: number;
  totalBytes: number;
  manifestHash: string;
}

export interface VerifiedDocumentStore {
  evidence: DocumentStoreEvidence;
  files: VerifiedStorageFile[];
}

export async function verifyDocumentStoreBackup(
  database: SqlQueryable,
  documentStoreRoot: string,
): Promise<VerifiedDocumentStore> {
  const root = await realpath(documentStoreRoot);
  const references = await storageReferences(database);
  const uniqueFiles = new Map<string, Omit<VerifiedStorageFile, 'absolutePath'>>();
  for (const reference of references) {
    const sizeBytes = safeSize(reference.sizeBytes);
    const existing = uniqueFiles.get(reference.storageUri);
    if (
      existing !== undefined &&
      (existing.contentHash !== reference.contentHash || existing.sizeBytes !== sizeBytes)
    ) {
      throw new Error('One storage URI has conflicting database metadata.');
    }
    uniqueFiles.set(reference.storageUri, {
      storageUri: reference.storageUri,
      contentHash: reference.contentHash,
      sizeBytes,
    });
  }

  const files: VerifiedStorageFile[] = [];
  for (const file of [...uniqueFiles.values()].sort((left, right) =>
    left.storageUri.localeCompare(right.storageUri),
  )) {
    const absolutePath = await verifiedStoragePath(root, file.storageUri);
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== file.sizeBytes) {
      throw new Error('Document Store file metadata does not match the database.');
    }
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error('Document Store file is writable by group or others.');
    }
    const actualHash = await sha256File(absolutePath);
    if (actualHash !== file.contentHash) {
      throw new Error('Document Store file hash does not match the database.');
    }
    files.push({ ...file, absolutePath });
  }

  const normalizedReferences = references
    .map((reference) => ({
      reference_type: reference.referenceType,
      reference_id: reference.referenceId,
      storage_uri: reference.storageUri,
      content_hash: reference.contentHash,
      size_bytes: safeSize(reference.sizeBytes),
    }))
    .sort((left, right) =>
      `${left.reference_type}:${left.reference_id}`.localeCompare(
        `${right.reference_type}:${right.reference_id}`,
      ),
    );
  const totalBytes = files.reduce((sum, file) => safeSum(sum, file.sizeBytes), 0);
  return {
    evidence: {
      referenceCount: references.length,
      uniqueFileCount: files.length,
      totalBytes,
      manifestHash: hashCanonical({
        version: 1,
        references: normalizedReferences,
      }),
    },
    files,
  };
}

export async function copyVerifiedDocumentStore(
  files: readonly VerifiedStorageFile[],
  destinationRoot: string,
): Promise<void> {
  const root = path.resolve(destinationRoot);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  for (const file of files) {
    const destination = safeDestination(root, file.storageUri);
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await copyFile(file.absolutePath, destination, constants.COPYFILE_EXCL);
    await chmod(destination, 0o600);
  }
}

async function storageReferences(database: SqlQueryable): Promise<StorageReferenceRow[]> {
  const result = await database.query<StorageReferenceRow>(
    `
      SELECT
        'document_version' AS "referenceType",
        id::text AS "referenceId",
        storage_uri AS "storageUri",
        content_hash AS "contentHash",
        size_bytes AS "sizeBytes"
      FROM dirizhor.document_versions
      UNION ALL
      SELECT
        'agent_run_result' AS "referenceType",
        id::text AS "referenceId",
        output_storage_uri AS "storageUri",
        content_hash AS "contentHash",
        size_bytes AS "sizeBytes"
      FROM dirizhor.agent_run_results
    `,
  );
  return result.rows;
}

async function verifiedStoragePath(root: string, storageUri: string): Promise<string> {
  const candidate = safeDestination(root, storageUri);
  const resolved = await realpath(candidate);
  if (!insideRoot(root, resolved)) {
    throw new Error('Document Store file resolves outside the configured root.');
  }
  return resolved;
}

function safeDestination(root: string, storageUri: string): string {
  if (storageUri.length === 0 || path.isAbsolute(storageUri) || storageUri.includes('\0')) {
    throw new Error('Document Store storage URI is not a safe relative key.');
  }
  const resolved = path.resolve(root, storageUri);
  if (!insideRoot(root, resolved)) {
    throw new Error('Document Store storage URI escapes the configured root.');
  }
  return resolved;
}

function insideRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative.length === 0 || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function sha256File(filePath: string): Promise<string> {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) {
    digest.update(chunk);
  }
  return `sha256:${digest.digest('hex')}`;
}

function safeSize(value: number | string): number {
  const size = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error('Document Store size is outside the supported range.');
  }
  return size;
}

function safeSum(left: number, right: number): number {
  const total = left + right;
  if (!Number.isSafeInteger(total)) {
    throw new Error('Document Store total size is outside the supported range.');
  }
  return total;
}
