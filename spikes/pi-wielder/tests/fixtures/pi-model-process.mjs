import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

const MAXIMUM_BODY_BYTES = 1_048_576;
const STATE_FILE = process.env.WALLET_KERNEL_FIXTURE_STATE_FILE;

function fatal(code) {
  if (typeof process.send === 'function') process.send({ type: 'fatal', code });
  process.exitCode = 1;
}

function requireStateFile(filePath) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath) {
    throw Object.assign(new Error('model state path is invalid'), { code: 'FIXTURE_CONFIG' });
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
  );
  const stat = fs.fstatSync(descriptor, { bigint: true });
  const uid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : stat.uid;
  if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o7777n) !== 0o600n
      || stat.nlink !== 1n || stat.size > 65_536n) {
    fs.closeSync(descriptor);
    throw Object.assign(new Error('model state authority is invalid'), {
      code: 'FIXTURE_AUTHORITY',
    });
  }
  return descriptor;
}

const stateDescriptor = requireStateFile(STATE_FILE);
let state = Object.freeze({
  requestCount: 0,
  forbiddenAuthorityHeaderCount: 0,
  requestHashes: Object.freeze([]),
  toolResultObserved: false,
});

function persistState() {
  const bytes = Buffer.from(`${JSON.stringify(state)}\n`, 'utf8');
  fs.ftruncateSync(stateDescriptor, 0);
  fs.writeSync(stateDescriptor, bytes, 0, bytes.length, 0);
  fs.fsyncSync(stateDescriptor);
  bytes.fill(0);
}

function forbiddenAuthorityHeaderCount(request) {
  const forbidden = [
    'authorization', 'cookie', 'payment-required', 'payment-signature',
    'payment-response', 'x-approval-id', 'x-idempotency-key', 'x-session-id',
    'x-spend-session', 'x-wallet-address', 'x-wallet-policy',
  ];
  return forbidden.reduce((count, name) => count + (request.headers[name] === undefined ? 0 : 1), 0);
}

async function readBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAXIMUM_BODY_BYTES) {
      throw Object.assign(new Error('model request exceeded its bound'), {
        code: 'FIXTURE_BODY_TOO_LARGE',
      });
    }
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw Object.assign(new Error('model request is malformed'), { code: 'FIXTURE_BODY' });
  }
  return Object.freeze({ bytes, parsed });
}

function chunk(id, delta, finishReason = null) {
  return JSON.stringify({
    id,
    object: 'chat.completion.chunk',
    created: 1_785_600_000,
    model: 'scripted-local',
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  });
}

function sendStreaming(response, ordinal) {
  const id = `chatcmpl-wallet-kernel-${ordinal}`;
  response.writeHead(200, {
    'cache-control': 'no-store',
    connection: 'close',
    'content-type': 'text/event-stream; charset=utf-8',
    'x-content-type-options': 'nosniff',
  });
  if (ordinal === 1) {
    response.write(`data: ${chunk(id, {
      role: 'assistant',
      tool_calls: [{
        index: 0,
        id: 'call_invoke_skill_once',
        type: 'function',
        function: {
          name: 'invoke_skill',
          arguments: '{"input":"commercial acceptance"}',
        },
      }],
    })}\n\n`);
    response.write(`data: ${chunk(id, {}, 'tool_calls')}\n\n`);
  } else {
    response.write(`data: ${chunk(id, { role: 'assistant', content: 'PI_WALLET_OK' })}\n\n`);
    response.write(`data: ${chunk(id, {}, 'stop')}\n\n`);
  }
  response.end('data: [DONE]\n\n');
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json',
    'x-content-type-options': 'nosniff',
  });
  response.end(JSON.stringify(value));
}

const server = http.createServer(async (request, response) => {
  try {
    if (request.method !== 'POST'
        || !new Set(['/chat/completions', '/v1/chat/completions']).has(request.url)) {
      sendJson(response, 404, { error: { code: 'MODEL_ROUTE_NOT_FOUND' } });
      return;
    }
    if (request.headers['content-type'] !== 'application/json') {
      sendJson(response, 415, { error: { code: 'MODEL_CONTENT_TYPE' } });
      return;
    }
    const authorityHeaders = forbiddenAuthorityHeaderCount(request);
    const { bytes, parsed } = await readBody(request);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || parsed.model !== 'scripted-local' || parsed.stream !== true
        || !Array.isArray(parsed.messages)) {
      sendJson(response, 400, { error: { code: 'MODEL_REQUEST_SCHEMA' } });
      return;
    }
    const ordinal = state.requestCount + 1;
    const toolResultObserved = ordinal > 1 && parsed.messages.some((message) => (
      message && typeof message === 'object' && message.role === 'tool'
    ));
    state = Object.freeze({
      requestCount: ordinal,
      forbiddenAuthorityHeaderCount: state.forbiddenAuthorityHeaderCount + authorityHeaders,
      requestHashes: Object.freeze([
        ...state.requestHashes,
        `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
      ]),
      toolResultObserved: state.toolResultObserved || toolResultObserved,
    });
    persistState();
    sendStreaming(response, ordinal);
  } catch (error) {
    sendJson(response, error?.code === 'FIXTURE_BODY_TOO_LARGE' ? 413 : 400, {
      error: { code: typeof error?.code === 'string' ? error.code : 'MODEL_REQUEST_FAILED' },
    });
  }
});

let closing = false;
async function close(code = 0) {
  if (closing) return;
  closing = true;
  await new Promise((resolve) => server.close(resolve));
  fs.closeSync(stateDescriptor);
  if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
  process.exitCode = code;
}

process.on('message', (message) => {
  if (message && typeof message === 'object' && message.type === 'shutdown') {
    void close(0);
  }
});
process.once('SIGINT', () => { void close(0); });
process.once('SIGTERM', () => { void close(0); });

server.once('error', (error) => {
  fatal(typeof error?.code === 'string' ? error.code : 'MODEL_LISTEN_FAILED');
});
server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  if (!address || typeof address === 'string') {
    fatal('MODEL_LISTEN_FAILED');
    return;
  }
  if (typeof process.send === 'function') {
    process.send({ type: 'ready', origin: `http://127.0.0.1:${address.port}` });
  }
});
