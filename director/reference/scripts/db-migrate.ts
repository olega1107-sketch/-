import {
  reportFailure,
  runDatabaseMigrationCli,
} from '../src/db-migrate-cli.js';

void runDatabaseMigrationCli().catch(reportFailure);
