import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runExperiment } from './src/experiment.mjs';

const args = new Map(process.argv.slice(2).map((item) => {
  const [key, value = '1'] = item.replace(/^--/, '').split('=', 2);
  return [key, value];
}));
const live = args.has('live');
const number = (name, fallback) => {
  const raw = args.get(name) ?? process.env[name.toUpperCase().replaceAll('-', '_')];
  return raw === undefined || raw === '' ? fallback : Number(raw);
};
const here = path.dirname(fileURLToPath(import.meta.url));
const mode = live ? 'live' : 'mock';
const outputDir = path.resolve(args.get('output') ?? path.join(here, 'runs', mode));

const result = await runExperiment({
  mode,
  outputDir,
  N: number('n', live ? undefined : 6),
  invocationPriceUsd: number('invocation-price-usd', live ? undefined : 0.25),
  cloneServingCostUsd: number('clone-serving-cost-usd', live ? undefined : 0.05),
  deployCostUsd: number('deploy-cost-usd', live ? undefined : 0.05),
  laborCostUsd: number('labor-cost-usd', live ? undefined : 0),
  apiKey: live ? process.env.ANTHROPIC_API_KEY : undefined,
  model: process.env.MODEL,
  maxInputTokens: number('max-input-tokens'),
  maxTokens: number('max-tokens'),
  inputUsdPerMillion: number('input-usd-per-million'),
  outputUsdPerMillion: number('output-usd-per-million'),
  pricingAsOf: process.env.PRICING_AS_OF,
  pricingSource: process.env.PRICING_SOURCE,
  maxRunCostUsd: number('max-run-cost-usd'),
});

console.log(result.markdownReport);
console.log(`JSON: ${result.outputFiles.json}`);
console.log(`Markdown: ${result.outputFiles.markdown}`);
