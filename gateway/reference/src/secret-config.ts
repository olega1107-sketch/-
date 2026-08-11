import { readFileSync } from 'node:fs';

export type SecretFileReader = (path: string) => string;

export function requiredSecret(
  env: NodeJS.ProcessEnv,
  name: string,
  reader: SecretFileReader = defaultReader,
): string {
  const value = optionalSecret(env, name, reader);
  if (value === undefined) {
    throw new Error(`${name} or ${name}_FILE is required.`);
  }
  return value;
}

export function optionalSecret(
  env: NodeJS.ProcessEnv,
  name: string,
  reader: SecretFileReader = defaultReader,
): string | undefined {
  const fileName = `${name}_FILE`;
  const directDefined = env[name] !== undefined;
  const fileDefined = env[fileName] !== undefined;
  if (directDefined && fileDefined) {
    throw new Error(`${name} and ${fileName} must not be set together.`);
  }
  if (directDefined) {
    return validSecret(env[name]!, name);
  }
  if (!fileDefined) {
    return undefined;
  }
  const path = env[fileName]!.trim();
  if (path.length === 0) {
    throw new Error(`${fileName} must contain a file path.`);
  }
  let value: string;
  try {
    value = reader(path);
  } catch {
    throw new Error(`${fileName} could not be read.`);
  }
  return validSecret(stripFinalNewline(value), fileName);
}

function defaultReader(path: string): string {
  return readFileSync(path, 'utf8');
}

function stripFinalNewline(value: string): string {
  if (value.endsWith('\r\n')) return value.slice(0, -2);
  if (value.endsWith('\n')) return value.slice(0, -1);
  return value;
}

function validSecret(value: string, name: string): string {
  if (value.trim().length === 0 || /[\0\r\n]/.test(value)) {
    throw new Error(`${name} must contain a non-empty single-line secret.`);
  }
  return value;
}
