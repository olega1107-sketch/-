import { Pool, type PoolConfig } from 'pg';

import type { SqlDatabase, SqlQueryable, SqlResult } from './ports.js';

export class PostgresDatabase implements SqlDatabase {
  private readonly pool: Pool;

  constructor(config: PoolConfig | Pool) {
    this.pool = config instanceof Pool ? config : new Pool(config);
  }

  async query<Row>(text: string, parameters?: readonly unknown[]): Promise<SqlResult<Row>> {
    const result = await this.pool.query(text, parameters === undefined ? undefined : [...parameters]);
    return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
  }

  async transaction<T>(operation: (transaction: SqlQueryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const queryable: SqlQueryable = {
        query: async <Row>(text: string, parameters?: readonly unknown[]) => {
          const result = await client.query(
            text,
            parameters === undefined ? undefined : [...parameters],
          );
          return { rows: result.rows as Row[], rowCount: result.rowCount ?? 0 };
        },
      };
      const result = await operation(queryable);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
