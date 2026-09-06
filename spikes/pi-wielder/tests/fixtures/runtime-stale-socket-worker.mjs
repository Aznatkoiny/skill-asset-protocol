import fs from 'node:fs';
import net from 'node:net';

net.createServer().listen(process.argv[2], () => {
  fs.chmodSync(process.argv[2], 0o600);
  process.kill(process.pid, 'SIGKILL');
});
