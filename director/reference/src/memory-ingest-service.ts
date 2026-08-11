import { randomUUID } from 'node:crypto';

import { sha256Bytes } from './canonical.js';
import type { IdGenerator, MemoryIngestRepository } from './memory-ports.js';
import type { MemoryObject, MemoryUploadMetadata } from './public-protocol.js';
import type { DocumentStore } from './ports.js';

export interface UploadMemoryObjectInput {
  userId: string;
  requestId: string;
  metadata: MemoryUploadMetadata;
  fileName: string;
  fileType: string;
  content: Uint8Array;
}

export interface MemoryIngestServiceOptions {
  repository: MemoryIngestRepository;
  documentStore: DocumentStore;
  idGenerator?: IdGenerator;
}

const randomIds: IdGenerator = { next: () => randomUUID() };

export class MemoryIngestService {
  private readonly repository: MemoryIngestRepository;
  private readonly documentStore: DocumentStore;
  private readonly idGenerator: IdGenerator;

  constructor(options: MemoryIngestServiceOptions) {
    this.repository = options.repository;
    this.documentStore = options.documentStore;
    this.idGenerator = options.idGenerator ?? randomIds;
  }

  async upload(input: UploadMemoryObjectInput): Promise<MemoryObject> {
    const authorization = {
      userId: input.userId,
      projectId: input.metadata.project_id,
      topicId: input.metadata.topic_id,
    };
    await this.repository.authorizeUpload(authorization);

    const memoryObjectId = this.idGenerator.next();
    const documentVersionId = this.idGenerator.next();
    const contentHash = sha256Bytes(input.content);
    const storageKey = [
      'document-versions',
      input.metadata.project_id,
      memoryObjectId,
      documentVersionId,
    ].join('/');
    const staged = await this.documentStore.stageImmutableDocument(
      storageKey,
      input.content,
      input.fileType,
      contentHash,
    );

    return this.repository.createMemoryObjectWithVersion({
      ...authorization,
      memoryObjectId,
      documentVersionId,
      requestId: input.requestId,
      metadata: input.metadata,
      storageUri: staged.storageUri,
      fileName: input.fileName,
      fileType: input.fileType,
      contentHash,
      sizeBytes: input.content.byteLength,
    });
  }
}
