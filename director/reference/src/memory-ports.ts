import type { MemoryObject, MemoryUploadMetadata } from './public-protocol.js';
import type { ServiceAuthInput } from './ports.js';

export interface AuthenticatedUser {
  userId: string;
  sessionId: string | null;
  authenticationMethod: string;
}

export interface UserAuthenticator {
  readonly cookieOrigin?: string;
  authenticate(input: ServiceAuthInput): Promise<AuthenticatedUser> | AuthenticatedUser;
}

export interface IdGenerator {
  next(): string;
}

export interface MemoryUploadAuthorization {
  userId: string;
  projectId: string;
  topicId: string | null;
}

export interface CreateMemoryObjectWithVersionCommand extends MemoryUploadAuthorization {
  memoryObjectId: string;
  documentVersionId: string;
  requestId: string;
  metadata: MemoryUploadMetadata;
  storageUri: string;
  fileName: string;
  fileType: string;
  contentHash: string;
  sizeBytes: number;
}

export interface MemoryIngestRepository {
  authorizeUpload(input: MemoryUploadAuthorization): Promise<void>;
  createMemoryObjectWithVersion(
    command: CreateMemoryObjectWithVersionCommand,
  ): Promise<MemoryObject>;
}
