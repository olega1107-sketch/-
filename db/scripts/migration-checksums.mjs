import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const databaseRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifestUrl = pathToFileURL(resolve(databaseRoot, 'migrations/manifest.json'));
const manifest = JSON.parse(await readFile(manifestUrl, 'utf8'));
let valid = true;

for (const migration of manifest.migrations ?? []) {
  const sqlPath = resolve(dirname(fileURLToPath(manifestUrl)), migration.file);
  if (!sqlPath.startsWith(`${databaseRoot}${sep}`)) {
    throw new Error(`Migration ${migration.id} resolves outside the database directory.`);
  }
  const sql = await readFile(sqlPath, 'utf8');
  const checksum = `sha256:${createHash('sha256')
    .update(migration.id)
    .update('\0')
    .update(migration.name)
    .update('\0')
    .update(migration.change)
    .update('\0')
    .update(migration.phase)
    .update('\0')
    .update(migration.transaction)
    .update('\0')
    .update(sql)
    .digest('hex')}`;
  const matches = checksum === migration.checksum;
  process.stdout.write(`${matches ? 'ok' : 'mismatch'} ${migration.id} ${checksum}\n`);
  valid &&= matches;
}

if (!valid) process.exitCode = 1;
