const SSL_CONNECTION_PARAMETERS = [
  'ssl',
  'sslmode',
  'sslrootcert',
  'sslcert',
  'sslkey',
  'sslpassword',
  'uselibpqcompat',
] as const;

/**
 * Removes URI-level SSL settings so the caller's explicit strict TLS options
 * cannot be overridden by the pg connection-string parser.
 */
export function connectionStringForStrictTls(connectionString: string): string {
  const url = new URL(connectionString);
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('PostgreSQL connection string must use postgres or postgresql scheme.');
  }
  for (const parameter of SSL_CONNECTION_PARAMETERS) {
    url.searchParams.delete(parameter);
  }
  return url.toString();
}
