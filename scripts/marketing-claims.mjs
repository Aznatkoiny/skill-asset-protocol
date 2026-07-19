import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLAIM_RULES = [
  { id: 'clone-paid-158', pattern: /(?:paid \$1\.58|\$1\.58 (?:bought|total)|six paid runs)/i },
  { id: 'invalid-clone-conclusion', pattern: /clone failed[\s\S]{0,80}(?:six|6)[\s\S]{0,40}fidelity|clone failed all (?:six|6)/i },
  { id: 'latency-unreproducible', pattern: /p50\s+731\s*ms|p95\s+1206\s*ms|n=48 settled calls/i },
  { id: 'absolute-extraction', pattern: /never (?:get|returns?|leaves|crosses)[\s\S]{0,60}\bskill\b|never (?:the )?skill|\bskill\b[\s\S]{0,40}never (?:leaves|crosses)/i },
  { id: 'txhash-as-retry-credential', pattern: /settlement txHash IS the credential|retries? .*carrying (?:it|the txHash)/i },
  { id: 'wielder-is-server', pattern: /server side.*proxy we call the Wielder|Wielder: enforce 402/i },
  { id: 'split-reconciled-onchain', pattern: /creator .*treasury.*reconciled on-chain|split.*reconciled on-chain/i },
];

export function auditText(file, text) {
  return CLAIM_RULES.flatMap(({ id, pattern }) => {
    const match = text.match(pattern);
    if (!match) return [];
    const line = text.slice(0, match.index).split('\n').length;
    return [{ file, line, rule: id, excerpt: match[0] }];
  });
}

export function auditFiles(repoRoot, relativePaths) {
  return relativePaths.flatMap((file) =>
    auditText(file, fs.readFileSync(path.join(repoRoot, file), 'utf8')),
  );
}

export function readHistoricalTombstone(repoRoot) {
  const file = path.join(
    repoRoot,
    'spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json',
  );
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const invokedAsScript = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = [
    'docs/marketing/linkedin.md',
    'docs/marketing/x.md',
    'docs/marketing/hn-and-demo.md',
    'docs/marketing/2026-07-13-campaign-plan.md',
  ];
  const findings = auditFiles(repoRoot, files);
  if (findings.length > 0) {
    for (const item of findings) {
      console.error(`${item.file}:${item.line} [${item.rule}] ${item.excerpt}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`PASS — ${files.length} publication drafts satisfy claim quarantine.`);
  }
}
