export class RuntimeBoundaryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RuntimeBoundaryError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new RuntimeBoundaryError(code, message); };

function assertPositiveLimit(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
}

function assertSignal(signal) {
  if (signal === null || signal === undefined) return null;
  if (typeof signal !== 'object'
      || typeof signal.aborted !== 'boolean'
      || typeof signal.addEventListener !== 'function'
      || typeof signal.removeEventListener !== 'function') {
    throw new TypeError('signal must be an AbortSignal or null');
  }
  return signal;
}

export async function withWallClockDeadline({
  signal = null,
  timeoutMs,
  timeoutCode,
  timeoutMessage,
  abortedCode,
  abortedMessage,
}, operation) {
  const callerSignal = assertSignal(signal);
  assertPositiveLimit(timeoutMs, 'timeoutMs');
  if (typeof operation !== 'function') throw new TypeError('deadline operation must be a function');
  for (const [label, value] of Object.entries({
    timeoutCode, timeoutMessage, abortedCode, abortedMessage,
  })) {
    if (typeof value !== 'string' || !value) throw new TypeError(`${label} must be non-empty`);
  }
  if (callerSignal?.aborted) fail(abortedCode, abortedMessage);

  const controller = new AbortController();
  let timer = null;
  let onCallerAbort = null;
  let rejectBoundary;
  let finished = false;
  const boundary = new Promise((resolve, reject) => {
    void resolve;
    rejectBoundary = reject;
  });
  const stop = (error) => {
    if (finished) return;
    if (!controller.signal.aborted) controller.abort(error);
    rejectBoundary(error);
  };

  if (callerSignal) {
    onCallerAbort = () => stop(new RuntimeBoundaryError(abortedCode, abortedMessage));
    callerSignal.addEventListener('abort', onCallerAbort, { once: true });
  }
  timer = setTimeout(() => {
    stop(new RuntimeBoundaryError(timeoutCode, timeoutMessage));
  }, timeoutMs);

  let operationPromise;
  try {
    operationPromise = Promise.resolve(operation(controller.signal));
  } catch (error) {
    operationPromise = Promise.reject(error);
  }
  try {
    return await Promise.race([operationPromise, boundary]);
  } finally {
    finished = true;
    clearTimeout(timer);
    if (callerSignal && onCallerAbort) {
      callerSignal.removeEventListener('abort', onCallerAbort);
    }
  }
}

function contentLength(source) {
  const value = source?.headers?.get?.('content-length');
  if (value === null || value === undefined) return null;
  if (!/^(0|[1-9]\d*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

async function cancelQuietly(readerOrBody, reason) {
  try { await readerOrBody?.cancel?.(reason); } catch { /* bounded failure already owns the result */ }
}

export function cancelResponseBody(source, reason) {
  void cancelQuietly(source?.body, reason);
}

export async function readBodyBytes(source, {
  maxBytes,
  tooLargeCode,
  tooLargeMessage,
  readErrorCode,
  readErrorMessage,
  signal = null,
}) {
  assertPositiveLimit(maxBytes, 'maxBytes');
  const bodySignal = assertSignal(signal);
  if (bodySignal?.aborted) {
    const error = new RuntimeBoundaryError(readErrorCode, readErrorMessage);
    await cancelQuietly(source?.body, error);
    throw error;
  }
  const declared = contentLength(source);
  if (declared !== null && declared > maxBytes) {
    await cancelQuietly(source?.body, new RuntimeBoundaryError(tooLargeCode, tooLargeMessage));
    fail(tooLargeCode, tooLargeMessage);
  }
  if (source?.body == null) return Buffer.alloc(0);
  if (typeof source.body.getReader !== 'function') {
    fail(readErrorCode, readErrorMessage);
  }

  const reader = source.body.getReader();
  const onAbort = bodySignal
    ? () => { void cancelQuietly(reader, bodySignal.reason); }
    : null;
  if (bodySignal && onAbort) bodySignal.addEventListener('abort', onAbort, { once: true });
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) fail(readErrorCode, readErrorMessage);
      total += value.byteLength;
      if (total > maxBytes) {
        const error = new RuntimeBoundaryError(tooLargeCode, tooLargeMessage);
        await cancelQuietly(reader, error);
        throw error;
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } catch (error) {
    if (error instanceof RuntimeBoundaryError) throw error;
    await cancelQuietly(reader, error);
    fail(readErrorCode, readErrorMessage);
  } finally {
    if (bodySignal && onAbort) bodySignal.removeEventListener('abort', onAbort);
    try { reader.releaseLock(); } catch { /* reader may already be released by its source */ }
  }
  return Buffer.concat(chunks, total);
}

export async function readJsonBody(source, options) {
  const bytes = await readBodyBytes(source, options);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(options.jsonErrorCode, options.jsonErrorMessage);
  }
}
