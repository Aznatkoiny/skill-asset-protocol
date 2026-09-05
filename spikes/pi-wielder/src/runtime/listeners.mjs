import fs from 'node:fs';
import path from 'node:path';

import { createAdaptorServer } from '@hono/node-server';

import { KernelError } from '../kernel/canonical.mjs';

function refused() {
  return new KernelError('RUNTIME_LISTENER', 'Installed Wallet Kernel listener refused');
}

function socketIdentity(filePath) {
  try {
    const stat = fs.lstatSync(filePath, { bigint: true });
    return stat.isSocket() ? { dev: stat.dev, ino: stat.ino } : null;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw refused();
  }
}

function startListener({ app, listen, expectedAddress, socketPath, kernelUid, kernelGid, onFatal = () => {} }) {
  if (!app || typeof app.fetch !== 'function' || typeof onFatal !== 'function') throw refused();
  // Native fetch and x402 validate against the platform Response constructor.
  // Hono's global shim must never replace it in this process.
  const server = createAdaptorServer({ fetch: app.fetch, overrideGlobalObjects: false });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  let ownSocket = null;
  let closePromise = null;
  const close = () => {
    closePromise ??= new Promise((resolve, reject) => {
      server.close((error) => {
        try {
          if (socketPath && ownSocket) {
            const current = socketIdentity(socketPath);
            if (current?.dev === ownSocket.dev && current?.ino === ownSocket.ino) {
              fs.unlinkSync(socketPath);
            }
          }
          if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(refused());
          else resolve();
        } catch { reject(refused()); }
      });
      server.closeIdleConnections();
    });
    return closePromise;
  };
  return new Promise((resolve, reject) => {
    let reportedFatal = false;
    const failed = () => {
      if (!reportedFatal) {
        reportedFatal = true;
        // Close admission synchronously; never forward a native/provider error.
        try { onFatal('RUNTIME_LISTENER'); } catch {}
      }
      void close().then(() => reject(refused()), () => reject(refused()));
    };
    server.on('error', failed);
    try {
      server.listen(listen, () => {
        try {
          const address = server.address();
          if (expectedAddress && (!address || typeof address === 'string'
              || address.address !== expectedAddress.address
              || (expectedAddress.port !== 0 && address.port !== expectedAddress.port))) throw refused();
          if (socketPath) {
            const stat = fs.lstatSync(socketPath, { bigint: true });
            if (!stat.isSocket() || stat.uid !== BigInt(kernelUid) || stat.gid !== BigInt(kernelGid)) throw refused();
            ownSocket = { dev: stat.dev, ino: stat.ino };
            fs.chmodSync(socketPath, 0o600);
          }
          resolve(Object.freeze({ close, address: Object.freeze(typeof address === 'string'
            ? { socket: true } : { host: address.address, port: address.port }) }));
        } catch { failed(); }
      });
    } catch { failed(); }
  });
}

export function listenLoopback({ app, host, port, onFatal }) {
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 0 || port > 65_535) throw refused();
  return startListener({ app, listen: { host, port }, expectedAddress: { address: host, port }, onFatal });
}

export function listenUnixAdmin({ app, socketPath, kernelUid, kernelGid, onFatal }) {
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath)
      || path.resolve(socketPath) !== socketPath || socketPath.includes('\0')
      || Buffer.byteLength(socketPath) > 103) throw refused();
  const parent = path.dirname(socketPath);
  const stat = fs.lstatSync(parent, { bigint: true });
  if (!stat.isDirectory() || fs.realpathSync(parent) !== parent
      || stat.uid !== BigInt(kernelUid) || stat.gid !== BigInt(kernelGid)
      || (stat.mode & 0o7777n) !== 0o700n) throw refused();
  try { fs.lstatSync(socketPath); throw refused(); } catch (error) {
    if (error.code !== 'ENOENT') throw refused();
  }
  return startListener({ app, listen: { path: socketPath }, socketPath, kernelUid, kernelGid, onFatal });
}

export function listenActivatedConsole({ app, activationName, host, port, activation, onFatal }) {
  if (!activation || Reflect.ownKeys(activation).length !== 4
      || activation.fd !== 3 || activation.name !== 'wallet-kernel-console'
      || activation.address !== '127.0.0.1' || activation.port !== 8405
      || activationName !== activation.name || host !== activation.address || port !== activation.port
      || !fs.fstatSync(activation.fd).isSocket()) throw refused();
  return startListener({ app, listen: { fd: activation.fd }, onFatal,
    expectedAddress: { address: host, port } });
}
