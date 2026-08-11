import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

const minimumValiditySeconds = positiveInteger(
  process.env.MTLS_PREFLIGHT_MIN_VALIDITY_SECONDS ?? String(7 * 24 * 60 * 60),
  'MTLS_PREFLIGHT_MIN_VALIDITY_SECONDS',
);

const directorServer = identity('director-server', {
  certificatePath: required('DIRECTOR_TLS_CERT_PATH'),
  keyPath: required('DIRECTOR_TLS_KEY_PATH'),
  caPath: optional('GATEWAY_DIRECTOR_CA_PATH') ?? required('GATEWAY_TLS_CA_PATH'),
  purpose: 'sslserver',
  hostname: httpsHostname(required('DIRECTOR_BASE_URL'), 'DIRECTOR_BASE_URL'),
});
const gatewayServer = identity('gateway-server', {
  certificatePath: required('GATEWAY_TLS_CERT_PATH'),
  keyPath: required('GATEWAY_TLS_KEY_PATH'),
  caPath: optional('DIRECTOR_GATEWAY_CA_PATH') ?? required('DIRECTOR_TLS_CA_PATH'),
  purpose: 'sslserver',
  hostname: httpsHostname(required('GATEWAY_BASE_URL'), 'GATEWAY_BASE_URL'),
});
const directorClient = identity('director-client', {
  certificatePath:
    optional('DIRECTOR_GATEWAY_CLIENT_CERT_PATH') ?? required('DIRECTOR_TLS_CERT_PATH'),
  keyPath:
    optional('DIRECTOR_GATEWAY_CLIENT_KEY_PATH') ?? required('DIRECTOR_TLS_KEY_PATH'),
  caPath: required('GATEWAY_TLS_CA_PATH'),
  purpose: 'sslclient',
  allowedCommonNames: commonNames(
    process.env.GATEWAY_ALLOWED_PEER_CNS ?? 'director-api',
    'GATEWAY_ALLOWED_PEER_CNS',
  ),
});
const gatewayClient = identity('gateway-client', {
  certificatePath:
    optional('GATEWAY_DIRECTOR_CLIENT_CERT_PATH') ?? required('GATEWAY_TLS_CERT_PATH'),
  keyPath:
    optional('GATEWAY_DIRECTOR_CLIENT_KEY_PATH') ?? required('GATEWAY_TLS_KEY_PATH'),
  caPath: required('DIRECTOR_TLS_CA_PATH'),
  purpose: 'sslclient',
  allowedCommonNames: commonNames(
    process.env.DIRECTOR_ALLOWED_PEER_CNS ?? 'agent-gateway',
    'DIRECTOR_ALLOWED_PEER_CNS',
  ),
});
const internalProviderClient =
  optional('INTERNAL_PROVIDER_ORIGIN') === undefined
    ? undefined
    : identity('internal-provider-client', {
        certificatePath: required('INTERNAL_PROVIDER_CLIENT_CERT_PATH'),
        keyPath: required('INTERNAL_PROVIDER_CLIENT_KEY_PATH'),
        caPath: required('INTERNAL_PROVIDER_CA_PATH'),
        purpose: 'sslclient',
        allowedCommonNames: commonNames(
          process.env.INTERNAL_PROVIDER_ALLOWED_CLIENT_CNS ??
            'agent-gateway-internal-provider',
          'INTERNAL_PROVIDER_ALLOWED_CLIENT_CNS',
        ),
      });

const reports = [];
for (const profile of [
  directorServer,
  gatewayServer,
  directorClient,
  gatewayClient,
  ...(internalProviderClient === undefined ? [] : [internalProviderClient]),
]) {
  reports.push(await verifyIdentity(profile));
}
process.stdout.write(`${JSON.stringify({ status: 'ok', certificates: reports }, null, 2)}\n`);

function identity(name, options) {
  return { name, ...options };
}

async function verifyIdentity(profile) {
  const [encodedCertificate, encodedKey, keyMetadata] = await Promise.all([
    readFile(profile.certificatePath),
    readFile(profile.keyPath),
    stat(profile.keyPath),
  ]);
  const certificate = new X509Certificate(encodedCertificate);
  const privateKey = createPrivateKey(encodedKey);
  if (!certificate.checkPrivateKey(privateKey)) {
    throw new Error(`${profile.name}: certificate does not match private key.`);
  }
  assertKeyPermissions(profile.name, keyMetadata.mode & 0o777);
  if (certificate.ca) {
    throw new Error(`${profile.name}: leaf certificate must not be a CA.`);
  }

  const expiresAt = new Date(certificate.validTo);
  if (
    !Number.isFinite(expiresAt.getTime()) ||
    expiresAt.getTime() - Date.now() < minimumValiditySeconds * 1_000
  ) {
    throw new Error(`${profile.name}: certificate validity horizon is too short.`);
  }
  const startsAt = new Date(certificate.validFrom);
  if (!Number.isFinite(startsAt.getTime()) || startsAt.getTime() > Date.now()) {
    throw new Error(`${profile.name}: certificate is not valid yet.`);
  }

  if (profile.purpose === 'sslserver') {
    if (
      certificate.checkHost(profile.hostname, { subject: 'never' }) !==
      profile.hostname
    ) {
      throw new Error(`${profile.name}: DNS SAN does not match the configured service host.`);
    }
  } else {
    const commonName = certificateCommonName(certificate);
    if (!profile.allowedCommonNames.includes(commonName)) {
      throw new Error(`${profile.name}: certificate CN is absent from the ingress allowlist.`);
    }
  }

  verifyWithOpenSsl(profile);
  return {
    profile: profile.name,
    purpose: profile.purpose,
    expires_at: expiresAt.toISOString(),
    ...(profile.purpose === 'sslserver'
      ? { dns_name: profile.hostname }
      : { common_name: certificateCommonName(certificate) }),
  };
}

function verifyWithOpenSsl(profile) {
  const args = [
    'verify',
    '-CAfile',
    profile.caPath,
    '-purpose',
    profile.purpose,
    profile.certificatePath,
  ];
  const result = spawnSync('openssl', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error !== undefined) {
    throw new Error(`${profile.name}: openssl could not be executed.`);
  }
  if (result.status !== 0) {
    throw new Error(`${profile.name}: certificate chain or extended key usage is invalid.`);
  }
}

function certificateCommonName(certificate) {
  const commonNames = certificate.subject
    .split(/\n/)
    .filter((field) => field.startsWith('CN='))
    .map((field) => field.slice(3));
  if (commonNames.length !== 1 || commonNames[0].length === 0) {
    throw new Error('Client certificate must contain exactly one Common Name.');
  }
  return commonNames[0];
}

function assertKeyPermissions(profile, mode) {
  if (![0o400, 0o440, 0o600, 0o640].includes(mode)) {
    throw new Error(`${profile}: private key permissions must be 0400, 0440, 0600, or 0640.`);
  }
}

function httpsHostname(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  if (
    url.protocol !== 'https:' ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new Error(`${name} must be an absolute HTTPS URL.`);
  }
  return url.hostname;
}

function commonNames(value, name) {
  const names = [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))];
  if (names.length === 0) {
    throw new Error(`${name} must contain at least one Common Name.`);
  }
  return names;
}

function positiveInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return parsed;
}

function optional(name) {
  const value = process.env[name]?.trim();
  return value === undefined || value.length === 0 ? undefined : value;
}

function required(name) {
  const value = optional(name);
  if (value === undefined) {
    throw new Error(`${name} is required.`);
  }
  return value;
}
