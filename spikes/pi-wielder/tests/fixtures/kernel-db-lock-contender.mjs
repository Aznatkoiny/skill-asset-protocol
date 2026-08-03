import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const [databasePath, readyFile, startFile, attemptFile] = process.argv.slice(2);
const database = new DatabaseSync(databasePath, { timeout: 5_000 });
try {
  database.exec('PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;');
  fs.writeFileSync(readyFile, 'ready', { mode: 0o600 });
  while (!fs.existsSync(startFile)) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  fs.writeFileSync(attemptFile, 'attempt', { mode: 0o600 });
  database.exec('BEGIN IMMEDIATE');
  const current = database.prepare(
    'SELECT value FROM metadata WHERE key = ?',
  ).get('claim');
  let outcome = 'already_claimed';
  if (!current) {
    database.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('claim', 'contender');
    outcome = 'claimed';
  }
  database.exec('COMMIT');
  process.stdout.write(`${outcome}\n`);
} catch (error) {
  if (database.isTransaction) database.exec('ROLLBACK');
  throw error;
} finally {
  database.close();
}
