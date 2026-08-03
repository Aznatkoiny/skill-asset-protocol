import fs from 'node:fs';

import { createInvocationJournal } from '../src/invocation-journal.mjs';

const [filePath, signingKeyPath, idempotencyKey, outputPath] = process.argv.slice(2);
const journal = createInvocationJournal({ filePath, signingKeyPath });
const persisted = journal.getByIdempotencyKey(idempotencyKey)?.quote?.requirements;
if (!persisted) throw new Error('persisted frozen offer is not visible');
fs.writeFileSync(outputPath, JSON.stringify(persisted), { flag: 'wx' });
