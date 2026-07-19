import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const catalog = JSON.parse(fs.readFileSync(path.join(root, 'fixtures/fixture-catalog-v2.json'), 'utf8'));

function inputFor(template, domain) {
  return `${template.text.replace('{slug}', domain.slug)} Use ${domain.path}; verify with ${domain.command}; ${domain.constraint}.`;
}

const train = catalog.trainDomains.flatMap((domain, domainIndex) =>
  catalog.trainTemplates.map((template, templateIndex) => ({
    id: `tr-v2-${String(domainIndex + 1).padStart(2, '0')}-${String(templateIndex + 1).padStart(2, '0')}`,
    mode: template.mode,
    input: inputFor(template, domain),
    expectedOutput: `${template.mode}\n${domain.path}\n${domain.command}\n${domain.constraint}\nShow the diff`,
  })));

const heldout = catalog.heldoutDomains.flatMap((domain, domainIndex) =>
  catalog.heldoutTemplates.map((template, templateIndex) => ({
    id: `ho-v2-${String(domainIndex + 1).padStart(2, '0')}-${String(templateIndex + 1).padStart(2, '0')}`,
    mode: template.mode,
    input: inputFor(template, domain),
    rubric: {
      expectedMode: template.mode,
      maxQuestions: template.maxQuestions,
      exactPaths: [{ value: domain.path, weight: 2, critical: true }],
      exactCommands: [{ value: domain.command, weight: 2, critical: true }],
      requiredAll: [{ value: domain.constraint, dimension: 'constraints', weight: 2, critical: true }],
      requiredAny: [{ values: ['Show the diff', 'Return the patch'], dimension: 'output', weight: 1, critical: false }],
      forbidden: [{ value: '[', dimension: 'grounding', weight: 1, critical: true }],
    },
  })));

for (const [file, data] of [['train-v2.json', train], ['heldout-v2.json', heldout]]) {
  const output = `${JSON.stringify(data, null, 2)}\n`;
  const target = path.join(root, 'fixtures', file);
  if (process.argv.includes('--check')) {
    if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== output) {
      throw new Error(`Generated fixture drift: ${file}`);
    }
  } else {
    fs.writeFileSync(target, output);
  }
}
