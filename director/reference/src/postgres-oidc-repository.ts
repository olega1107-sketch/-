import type {
  ConsumeOidcLoginTransactionCommand,
  CreateOidcLoginTransactionCommand,
  OidcLoginTransaction,
  OidcLoginTransactionRepository,
} from './oidc-ports.js';
import type { SqlDatabase } from './ports.js';

interface OidcTransactionRow {
  id: string;
  nonce: string;
  codeVerifier: string;
}

export class PostgresOidcLoginTransactionRepository
  implements OidcLoginTransactionRepository
{
  constructor(private readonly database: SqlDatabase) {}

  async create(command: CreateOidcLoginTransactionCommand): Promise<void> {
    await this.database.transaction(async (transaction) => {
      await transaction.query(
        `
          DELETE FROM dirizhor.oidc_login_transactions
          WHERE consumed_at IS NULL
            AND expires_at <= $1::timestamptz
        `,
        [command.createdAt],
      );
      await transaction.query(
        `
          DELETE FROM dirizhor.oidc_login_transactions
          WHERE consumed_at <= $1::timestamptz - INTERVAL '24 hours'
        `,
        [command.createdAt],
      );
      await transaction.query(
        `
          INSERT INTO dirizhor.oidc_login_transactions (
            id,
            provider_code,
            browser_token_hash,
            state_hash,
            nonce,
            code_verifier,
            created_at,
            expires_at,
            request_id,
            ip_address
          )
          VALUES (
            $1::uuid,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7::timestamptz,
            $8::timestamptz,
            $9::uuid,
            $10::inet
          )
        `,
        [
          command.id,
          command.providerCode,
          command.browserTokenHash,
          command.stateHash,
          command.nonce,
          command.codeVerifier,
          command.createdAt,
          command.expiresAt,
          command.requestId,
          command.ipAddress,
        ],
      );
    });
  }

  async consume(
    command: ConsumeOidcLoginTransactionCommand,
  ): Promise<OidcLoginTransaction | null> {
    return this.database.transaction(async (transaction) => {
      const result = await transaction.query<OidcTransactionRow>(
        `
          SELECT
            id::text AS id,
            nonce,
            code_verifier AS "codeVerifier"
          FROM dirizhor.oidc_login_transactions
          WHERE provider_code = $1
            AND browser_token_hash = $2
            AND state_hash = $3
            AND created_at <= $4::timestamptz
            AND expires_at > $4::timestamptz
            AND consumed_at IS NULL
          FOR UPDATE
        `,
        [
          command.providerCode,
          command.browserTokenHash,
          command.stateHash,
          command.consumedAt,
        ],
      );
      const login = result.rows[0];
      if (login === undefined) {
        return null;
      }
      const consumed = await transaction.query(
        `
          UPDATE dirizhor.oidc_login_transactions
          SET consumed_at = $2::timestamptz,
              nonce = NULL,
              code_verifier = NULL
          WHERE id = $1::uuid
            AND consumed_at IS NULL
        `,
        [login.id, command.consumedAt],
      );
      if (consumed.rowCount !== 1) {
        throw new Error('OIDC login transaction could not be consumed atomically.');
      }
      return { nonce: login.nonce, codeVerifier: login.codeVerifier };
    });
  }
}
