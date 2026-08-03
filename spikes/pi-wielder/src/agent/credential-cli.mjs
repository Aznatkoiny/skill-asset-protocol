import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { types as utilTypes } from 'node:util';

import {
  createAgentEnrollmentDescriptor,
  loadOrCreateAgentCredential,
  publishAgentEnrollmentDescriptor,
} from './credential.mjs';

const DESCRIPTOR_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function plainRecord(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('AGENT_CREDENTIAL_CLI_USAGE', `${label} must be one plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !descriptor?.enumerable
        || !Object.hasOwn(descriptor, 'value')) {
      fail('AGENT_CREDENTIAL_CLI_USAGE', `${label} must contain only data fields`);
    }
  }
  return value;
}

function parseArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 5
      || argv[0] !== 'init'
      || argv[1] !== '--credential'
      || argv[3] !== '--enrollment'
      || typeof argv[2] !== 'string'
      || typeof argv[4] !== 'string'
      || argv[2].length === 0
      || argv[4].length === 0) {
    fail(
      'AGENT_CREDENTIAL_CLI_USAGE',
      'usage: credential-cli.mjs init --credential FILE --enrollment FILE',
    );
  }
  return Object.freeze({
    credentialPath: argv[2],
    enrollmentPath: argv[4],
  });
}

export function runAgentCredentialCli(value) {
  const options = plainRecord(value, 'credential CLI options');
  const keys = Reflect.ownKeys(options);
  if (!Object.hasOwn(options, 'argv')
      || keys.some((key) => !['argv', 'writeStdout', 'dependencies'].includes(key))) {
    fail('AGENT_CREDENTIAL_CLI_USAGE', 'credential CLI options are invalid');
  }
  const parsed = parseArguments(options.argv);
  const writeStdout = options.writeStdout ?? ((bytes) => process.stdout.write(bytes));
  if (typeof writeStdout !== 'function' || utilTypes.isProxy(writeStdout)) {
    fail('AGENT_CREDENTIAL_CLI_USAGE', 'stdout writer must be one function');
  }
  const dependencies = plainRecord(options.dependencies ?? {}, 'credential CLI dependencies');
  if (Reflect.ownKeys(dependencies).some(
    (key) => !['pathTrust', 'randomBytes'].includes(key),
  )) {
    fail('AGENT_CREDENTIAL_CLI_USAGE', 'credential CLI dependencies are invalid');
  }

  const credentialOptions = { filePath: parsed.credentialPath };
  if (Object.hasOwn(dependencies, 'pathTrust')) {
    credentialOptions.pathTrust = dependencies.pathTrust;
  }
  if (Object.hasOwn(dependencies, 'randomBytes')) {
    credentialOptions.randomBytes = dependencies.randomBytes;
  }
  const credential = loadOrCreateAgentCredential(credentialOptions);
  const descriptor = createAgentEnrollmentDescriptor({ credential });
  const publicationOptions = {
    filePath: parsed.enrollmentPath,
    credentialPath: parsed.credentialPath,
    descriptor,
  };
  if (Object.hasOwn(dependencies, 'pathTrust')) {
    publicationOptions.pathTrust = dependencies.pathTrust;
  }
  const publication = publishAgentEnrollmentDescriptor(publicationOptions);
  if (!DESCRIPTOR_HASH_PATTERN.test(publication.descriptorHash)) {
    fail('AGENT_DESCRIPTOR_HASH', 'descriptor publication returned an invalid hash');
  }
  writeStdout(`${publication.descriptorHash}\n`);
  return 0;
}

if (process.argv[1]
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    runAgentCredentialCli({ argv: process.argv.slice(2) });
  } catch (error) {
    process.stderr.write(`${typeof error?.code === 'string' ? error.code : 'AGENT_CREDENTIAL_INIT_FAILED'}\n`);
    process.exitCode = 1;
  }
}
