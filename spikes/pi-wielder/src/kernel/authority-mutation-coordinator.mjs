import { types as utilTypes } from 'node:util';

import { KernelError } from './canonical.mjs';

const DEPENDENCY_NAMES = Object.freeze([
  'assertAdmissionOpen',
  'markAuthorityUnhealthy',
]);

function readDependencies(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || utilTypes.isProxy(options) || Object.getPrototypeOf(options) !== Object.prototype) {
    throw new TypeError('authority mutation coordinator options must be one plain object');
  }

  const keys = Reflect.ownKeys(options);
  if (keys.length !== DEPENDENCY_NAMES.length
      || keys.some((key) => typeof key !== 'string' || !DEPENDENCY_NAMES.includes(key))) {
    throw new TypeError('authority mutation coordinator options have an invalid shape');
  }

  const dependencies = {};
  for (const name of DEPENDENCY_NAMES) {
    const descriptor = Object.getOwnPropertyDescriptor(options, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'function') {
      throw new TypeError(`${name} must be an enumerable function data property`);
    }
    dependencies[name] = descriptor.value;
  }
  return dependencies;
}

function isThenable(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return false;
  }
  if (utilTypes.isPromise(value)) return true;
  let subject = value;
  while (subject !== null) {
    // Never execute a caller-controlled proxy trap or `then` getter while
    // deciding whether the synchronous callback escaped its lease.
    if (utilTypes.isProxy(subject)) return true;
    const descriptor = Object.getOwnPropertyDescriptor(subject, 'then');
    if (descriptor) {
      if (!Object.hasOwn(descriptor, 'value')) return true;
      return typeof descriptor.value === 'function';
    }
    subject = Object.getPrototypeOf(subject);
  }
  return false;
}

export function createAuthorityMutationCoordinator(options) {
  if (arguments.length !== 1) {
    throw new TypeError('createAuthorityMutationCoordinator requires exactly one options object');
  }
  const { assertAdmissionOpen, markAuthorityUnhealthy } = readDependencies(options);
  const queue = [];
  let draining = false;
  let asyncInvariantError = null;

  function drain() {
    if (draining) return;
    draining = true;
    try {
      while (queue.length > 0) {
        const { operation, resolve, reject } = queue.shift();
        try {
          assertAdmissionOpen();
          if (asyncInvariantError) throw asyncInvariantError;
          const result = operation();
          if (isThenable(result)) {
            // Keep an internal fail-closed latch as a backstop if the injected
            // process-level marker is faulty and does not close admission.
            asyncInvariantError = new KernelError(
              'AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
              'authority mutation callback must finish synchronously',
            );
            try {
              markAuthorityUnhealthy('AUTHORITY_COORDINATOR_ASYNC_CALLBACK');
            } catch (cause) {
              asyncInvariantError = new KernelError(
                'AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
                'authority mutation callback escaped and its fail-stop hook failed',
                { cause },
              );
            }
            reject(asyncInvariantError);
          } else {
            resolve(result);
          }
        } catch (error) {
          reject(error);
        }
      }
    } finally {
      draining = false;
    }
  }

  function runExclusive(operation) {
    if (arguments.length !== 1 || typeof operation !== 'function') {
      return Promise.reject(new TypeError('runExclusive requires exactly one function'));
    }

    return new Promise((resolve, reject) => {
      queue.push({ operation, resolve, reject });
      drain();
    });
  }

  return Object.freeze({
    runExclusive,
  });
}
