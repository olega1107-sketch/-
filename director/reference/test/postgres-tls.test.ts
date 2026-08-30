import { describe, expect, it } from 'vitest';

import { connectionStringForStrictTls } from '../src/postgres-tls.js';

describe('connectionStringForStrictTls', () => {
  it('removes URI SSL settings without changing credentials or database identity', () => {
    const value = connectionStringForStrictTls(
      'postgresql://user%40example:secret%2Fvalue@db.example:25060/dirizher?sslmode=require&sslrootcert=/tmp/ca&application_name=keep',
    );
    const url = new URL(value);
    expect(url.username).toBe('user%40example');
    expect(url.password).toBe('secret%2Fvalue');
    expect(url.pathname).toBe('/dirizher');
    expect(url.searchParams.get('application_name')).toBe('keep');
    expect(url.searchParams.has('sslmode')).toBe(false);
    expect(url.searchParams.has('sslrootcert')).toBe(false);
  });

  it('rejects a non-PostgreSQL connection scheme', () => {
    expect(() => connectionStringForStrictTls('https://db.example/dirizher')).toThrow(
      /PostgreSQL connection string/,
    );
  });
});
