import { deepFreeze, requireExactKeys } from './schema.mjs';

const RECORD_CAS_KEYS = [
  'invocationId', 'expectedInvocationRevision', 'reservationId',
  'expectedReservationRevision', 'executionAttemptId',
];

function requireRevision(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
}

export class InMemoryEngineStore {
  #state;

  #tail = Promise.resolve();

  constructor(initialState) {
    if (initialState === null || typeof initialState !== 'object' || !Object.isFrozen(initialState)) {
      throw new Error('initial engine state must be created and frozen by createEngineState');
    }
    requireRevision(initialState.revision, 'initial engine revision');
    this.#state = initialState;
  }

  snapshot() {
    return this.#state;
  }

  #enqueue(operation) {
    const result = this.#tail.then(operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  transact(expectedRevision, transition) {
    requireRevision(expectedRevision, 'expected engine revision');
    if (typeof transition !== 'function') throw new Error('transition must be a function');
    return this.#enqueue(async () => {
      const current = this.#state;
      if (current.revision !== expectedRevision) {
        throw new Error(`stale engine revision: expected ${expectedRevision}, received ${current.revision}`);
      }
      const next = await transition(current);
      if (next === null || typeof next !== 'object') throw new Error('transition must return engine state');
      if (next.revision !== current.revision + 1) {
        throw new Error('transition must advance engine revision exactly once');
      }
      this.#state = deepFreeze(next);
      return this.#state;
    });
  }

  transactRecord(cas, transition) {
    requireExactKeys(cas, RECORD_CAS_KEYS, 'record CAS');
    requireRevision(cas.expectedInvocationRevision, 'expected Invocation revision');
    requireRevision(cas.expectedReservationRevision, 'expected reservation revision');
    if (typeof transition !== 'function') throw new Error('transition must be a function');
    return this.#enqueue(async () => {
      const current = this.#state;
      const invocation = current.invocations[cas.invocationId];
      const reservation = current.reservations[cas.reservationId];
      if (!invocation) throw new Error('Invocation record does not exist');
      if (!reservation) throw new Error('reservation record does not exist');
      if (invocation.revision !== cas.expectedInvocationRevision) {
        throw new Error(
          `stale Invocation revision: expected ${cas.expectedInvocationRevision}, received ${invocation.revision}`,
        );
      }
      if (reservation.revision !== cas.expectedReservationRevision) {
        throw new Error(
          `stale reservation revision: expected ${cas.expectedReservationRevision}, received ${reservation.revision}`,
        );
      }
      if (typeof cas.executionAttemptId !== 'string' || cas.executionAttemptId.length === 0
          || invocation.executionAttemptId !== cas.executionAttemptId
          || reservation.executionAttemptId !== cas.executionAttemptId) {
        throw new Error('execution attempt does not match current records');
      }
      const next = await transition(current, { invocation, reservation });
      if (next === null || typeof next !== 'object') throw new Error('transition must return engine state');
      if (next.revision !== current.revision + 1) {
        throw new Error('record transition must advance engine revision exactly once');
      }
      this.#state = deepFreeze(next);
      return this.#state;
    });
  }
}
