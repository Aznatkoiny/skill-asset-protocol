import { Hono } from 'hono';
import { listenActivatedConsole } from '../../src/runtime/listeners.mjs';

const NativeResponse = Response;
let listener;
try {
  const app = new Hono();
  app.get('/operator/probe', (context) => context.json({nativeResponse:Response === NativeResponse}));
  listener = await listenActivatedConsole({app, activationName:'wallet-kernel-console',
    host:'127.0.0.1', port:8405,
    activation:{fd:3, name:'wallet-kernel-console', address:'127.0.0.1', port:8405}});
  process.on('message', async (message) => {
    if (message !== 'close') return;
    await listener.close();
    process.disconnect();
  });
  process.send({ready:true, address:listener.address});
} catch (error) {
  process.send({error:error.code ?? 'WORKER_FAILED'});
  await listener?.close();
  process.exitCode = 1;
  process.disconnect();
}
