import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { Hono } from 'hono';
import { encodePaymentRequiredHeader } from '@x402/core/http';
import { createX402V2Transport } from '../src/adapters/x402-v2-transport.mjs';
import { listenActivatedConsole, listenLoopback, listenUnixAdmin } from '../src/runtime/listeners.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';

test('actual Agent and Operator adapters preserve native fetch Response compatibility with x402', async () => {
  const native = {Request,Response,Headers};
  const seller = new Hono();
  let origin;
  seller.post('/resource', c => c.body(null,402,{'PAYMENT-REQUIRED':encodePaymentRequiredHeader({
    x402Version:2, resource:{url:`${origin}/resource`,description:'offline listener proof',mimeType:'application/json'},
    accepts:[{scheme:'exact',network:'eip155:84532',asset:'0x036cbd53842c5426634e7929541ec2318f3dcf7e',
      amount:'1',payTo:'0x2000000000000000000000000000000000000000',maxTimeoutSeconds:60,
      extra:{name:'USDC',version:'2'}}],
  })}));
  const sellerListener = await listenLoopback({app:seller,host:'127.0.0.1',port:0});
  origin = `http://127.0.0.1:${sellerListener.address.port}`;
  const transport = createX402V2Transport({fetchImpl:fetch,mode:'deterministic',
    limits:{requestTimeoutMs:1000,maximumResponseBytes:16384,maximumPaymentHeaderBytes:16384}});
  const agent = new Hono();
  agent.post('/agent/probe',async c=>{
    assert.ok(c.req.raw instanceof native.Request);
    const result = await transport.probe({requestUrl:`${origin}/resource`,method:'POST',headers:{},bodyBytes:Buffer.from('{}')});
    return c.json({kind:result.kind});
  });
  const operator = new Hono();
  operator.get('/operator/status', c=>c.json({status:'offline'}));
  const agentListener = await listenLoopback({app:agent,host:'127.0.0.1',port:0});
  const operatorListener = await listenLoopback({app:operator,host:'127.0.0.1',port:0});
  try {
    const agentOrigin = `http://127.0.0.1:${agentListener.address.port}`;
    const operatorOrigin = `http://127.0.0.1:${operatorListener.address.port}`;
    assert.deepEqual({Request,Response,Headers},native);
    const response = await fetch(`${agentOrigin}/agent/probe`,{method:'POST'});
    assert.ok(response instanceof native.Response);
    assert.deepEqual(await response.json(),{kind:'payment_required'});
    assert.equal((await fetch(`${agentOrigin}/operator/status`)).status,404);
    assert.equal((await fetch(`${operatorOrigin}/agent/probe`,{method:'POST'})).status,404);
  } finally {
    await Promise.all([agentListener.close(),operatorListener.close(),sellerListener.close()]);
  }
  await agentListener.close();
  assert.deepEqual({Request,Response,Headers},native);
});

test('Unix Operator socket is private, refuses stale paths, and is cleaned up idempotently', async(t)=>{
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),'kernel-listener-'));
  fs.chmodSync(directory,0o700);
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const socketPath = path.join(directory,'admin.sock');
  const app = new Hono(); app.get('/operator/status',c=>c.json({ok:true}));
  const options = {app,socketPath,kernelUid:process.getuid(),kernelGid:process.getgid()};
  const listener = await listenUnixAdmin(options);
  try {
    assert.equal(fs.statSync(socketPath).mode&0o777,0o600);
    assert.throws(()=>listenUnixAdmin(options),{code:'RUNTIME_LISTENER'});
    const body = await new Promise((resolve,reject)=>{
      const request = http.get({socketPath,path:'/operator/status'},response=>{
        let text='';response.on('data',part=>text+=part);response.on('end',()=>resolve(text));
      });request.on('error',reject);
    });
    assert.deepEqual(JSON.parse(body),{ok:true});
  } finally {await listener.close();}
  await listener.close();
  assert.equal(fs.existsSync(socketPath),false);
});

test('listener rejects wildcard bind and forged activation before serving', ()=>{
  const app = new Hono();
  assert.throws(()=>listenLoopback({app,host:'0.0.0.0',port:8402}),{code:'RUNTIME_LISTENER'});
  assert.throws(()=>listenActivatedConsole({app,activationName:'wallet-kernel-console',host:'127.0.0.1',port:8405,
    activation:{fd:9,name:'wallet-kernel-console',address:'127.0.0.1',port:8405}}),{code:'RUNTIME_LISTENER'});
});

test('native console adapter adopts an inherited loopback fd3 without replacing Response', async (t) => {
  const reserved = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      reserved.once('error', reject);
      reserved.listen({host:'127.0.0.1', port:8405}, resolve);
    });
  } catch (error) {
    if (error.code === 'EADDRINUSE') {t.skip('reserved console port8405 is already in use'); return;}
    throw error;
  }
  // Synthetic inherited FD only; no PID1 configuration, UID changes or mounts.
  const child = fork(fileURLToPath(new URL('./fixtures/runtime-activated-listener-worker.mjs', import.meta.url)), [], {
    execArgv:[], stdio:['ignore', 'ignore', 'pipe', reserved._handle.fd, 'ipc'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => {stderr = `${stderr}${chunk}`.slice(-4096);});
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({code,signal})));
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(()=>reject(Error('inherited listener startup timed out')), 5000);
    child.once('error', reject);
    child.once('message', value=> {clearTimeout(timer); resolve(value);});
  });
  t.after(async()=> {
    if (child.exitCode === null) child.kill('SIGKILL');
    await exited;
    if (reserved.listening) await new Promise(resolve=>reserved.close(resolve));
  });
  await new Promise(resolve=>reserved.close(resolve));
  assert.deepEqual(await ready, {ready:true, address:{host:'127.0.0.1', port:8405}}, stderr);
  const response = await fetch('http://127.0.0.1:8405/operator/probe');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {nativeResponse:true});
  child.send('close');
  assert.deepEqual(await exited, {code:0, signal:null}, stderr);
});

function socketRecoveryFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-socket-recovery-'));
  fs.chmodSync(directory, 0o700);
  const databasePath = path.join(directory, 'kernel.sqlite');
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:directory,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const authorityLock = acquireAuthorityLock({databasePath, role:'kernel', pathTrust});
  t.after(()=> {authorityLock.close(); fs.rmSync(directory, {recursive:true, force:true});});
  const app = new Hono();
  app.get('/operator/probe', context=>context.json({ok:true}));
  return {app, databasePath, authorityLock, socketPath:path.join(directory, 'admin.sock'),
    kernelUid:process.getuid(), kernelGid:process.getgid()};
}

function leaveCrashedSocket(socketPath) {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./fixtures/runtime-stale-socket-worker.mjs', import.meta.url)), socketPath],
    {encoding:'utf8', timeout:5000});
  assert.equal(result.signal, 'SIGKILL', result.stderr);
  assert.equal(fs.lstatSync(socketPath).isSocket(), true);
}

test('a hard-crash Unix socket is recovered only while holding its genuine Kernel authority lock', async (t) => {
  const input = socketRecoveryFixture(t);
  leaveCrashedSocket(input.socketPath);
  assert.throws(()=>listenUnixAdmin({...input,authorityLock:undefined}), {code:'RUNTIME_LISTENER'});
  assert.throws(()=>listenUnixAdmin({...input,authorityLock:{close(){}}}), {code:'RUNTIME_LISTENER'});
  assert.throws(()=>listenUnixAdmin({...input,databasePath:`${input.databasePath}.wrong`}), {code:'RUNTIME_LISTENER'});
  const listener = await listenUnixAdmin(input);
  await listener.close();
  assert.equal(fs.existsSync(input.socketPath), false);
  leaveCrashedSocket(input.socketPath);
  input.authorityLock.close();
  assert.throws(()=>listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
  assert.equal(fs.lstatSync(input.socketPath).isSocket(), true);
});

test('socket recovery refuses a live listener and preserves its inode', async (t) => {
  const input = socketRecoveryFixture(t);
  const listener = await listenUnixAdmin(input);
  const before = fs.lstatSync(input.socketPath, {bigint:true});
  try {
    await assert.rejects(listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
    const after = fs.lstatSync(input.socketPath, {bigint:true});
    assert.equal(after.ino, before.ino);
    assert.equal(after.dev, before.dev);
  } finally {await listener.close();}
});

test('socket recovery rejects symlinks, hard links and unsafe modes without removing them', (t) => {
  const input = socketRecoveryFixture(t);
  leaveCrashedSocket(input.socketPath);
  fs.chmodSync(input.socketPath, 0o666);
  assert.throws(()=>listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
  fs.chmodSync(input.socketPath, 0o600);
  const alias = `${input.socketPath}.alias`;
  fs.linkSync(input.socketPath, alias);
  assert.throws(()=>listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
  fs.unlinkSync(alias);
  fs.renameSync(input.socketPath, alias);
  fs.symlinkSync(alias, input.socketPath);
  assert.throws(()=>listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
  assert.equal(fs.lstatSync(input.socketPath).isSymbolicLink(), true);
});

test('socket replacement during stale probing is refused and the replacement survives', async (t) => {
  const input = socketRecoveryFixture(t);
  leaveCrashedSocket(input.socketPath);
  t.mock.method(net.Socket.prototype, 'connect', function () {
    setImmediate(()=>{
      fs.unlinkSync(input.socketPath);
      fs.writeFileSync(input.socketPath, 'replacement-must-survive', {mode:0o600});
      this.emit('error', Object.assign(Error('synthetic stale probe'), {code:'ECONNREFUSED'}));
    });
    return this;
  });
  await assert.rejects(listenUnixAdmin(input), {code:'RUNTIME_LISTENER'});
  assert.equal(fs.readFileSync(input.socketPath, 'utf8'), 'replacement-must-survive');
});
