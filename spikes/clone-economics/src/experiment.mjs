import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MockLlmAdapter, LiveAnthropicAdapter } from './adapters.mjs';
import { computeEconomics } from './economics.mjs';
import { renderJson, renderMarkdown } from './reports.mjs';
import { FIDELITY_THRESHOLD, RUBRIC_VERSION, scoreEvaluation } from './scoring.mjs';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const spikeRoot = path.resolve(srcDir, '..');
const repoRoot = path.resolve(spikeRoot, '../..');
const fixturePath = (name) => path.join(spikeRoot, 'fixtures', name);
const readJson = (name) => JSON.parse(fs.readFileSync(fixturePath(name), 'utf8'));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const normalizedInputHash = (value) => sha256(value.trim().replace(/\s+/g, ' ').toLowerCase());
const rounded = (value) => Number(value.toFixed(12));

function assertValidClone(skillMd) {
  if (!skillMd.startsWith('---\nname:') || !skillMd.includes('\n---\n') || !skillMd.includes('\n# ')) {
    throw new Error('Distillation did not produce a valid SKILL.md');
  }
}

async function collect(adapter, fixtures, kind, payloadFor) {
  const outputs = {};
  for (const fixture of fixtures) {
    const response = await adapter.invoke({ kind, caseId: fixture.id, payload: payloadFor(fixture) });
    outputs[fixture.id] = response.output;
  }
  return outputs;
}

function sumCosts(records, kinds) {
  const selected = records.filter((item) => kinds.includes(item.kind));
  if (selected.some((item) => item.costUsd === null)) return null;
  return rounded(selected.reduce((sum, item) => sum + item.costUsd, 0));
}

function normalizedUsage(records) {
  const inputKnown = records.every((item) => item.normalizedUsage.inputTokens !== null);
  const outputKnown = records.every((item) => item.normalizedUsage.outputTokens !== null);
  return {
    inputTokens: inputKnown ? records.reduce((sum, item) => sum + item.normalizedUsage.inputTokens, 0) : null,
    outputTokens: outputKnown ? records.reduce((sum, item) => sum + item.normalizedUsage.outputTokens, 0) : null,
    providerCostUsd: records.some((item) => item.costUsd === null) ? null : rounded(records.reduce((sum, item) => sum + item.costUsd, 0)),
  };
}

function buildAdapter(mode, options) {
  if (options.adapter) return options.adapter;
  if (mode === 'mock') {
    return new MockLlmAdapter({
      transcript: options.mockTranscript ?? readJson('mock-transcript.json'),
      cloneSkillMd: fs.readFileSync(fixturePath('good-clone/SKILL.md'), 'utf8'),
    });
  }
  return new LiveAnthropicAdapter({
    mode,
    apiKey: options.apiKey,
    model: options.model,
    N: options.N,
    maxInputTokens: options.maxInputTokens,
    maxTokens: options.maxTokens,
    inputUsdPerMillion: options.inputUsdPerMillion,
    outputUsdPerMillion: options.outputUsdPerMillion,
    pricingAsOf: options.pricingAsOf,
    pricingSource: options.pricingSource,
    maxRunCostUsd: options.maxRunCostUsd,
    estimatedRequests: options.estimatedRequests,
  });
}

export async function runExperiment(options = {}) {
  const mode = options.mode ?? (process.env.MOCK_LLM === '1' ? 'mock' : 'live');
  if (!['mock', 'live'].includes(mode)) throw new Error('mode must be mock or live');
  const trainFixtures = readJson('train.json');
  const heldoutFixtures = readJson('heldout.json');
  const v2Fixtures = readJson('v2-heldout.json');
  const repoInventory = readJson('repo-inventory.json');
  const executorSettings = readJson('executor-settings.json');
  const evolutionOverlay = readJson('evolution-v2.json');
  const N = Number(options.N ?? (mode === 'mock' ? 6 : Number.NaN));
  if (!Number.isInteger(N) || N <= 0 || N > trainFixtures.length) {
    throw new Error(`N must be an integer from 1 to ${trainFixtures.length}`);
  }
  const selectedTrain = trainFixtures.slice(0, N);
  const targetFile = path.join(repoRoot, '.claude/skills/optimizing-claude-code-prompts/SKILL.md');
  const referenceFile = path.join(repoRoot, '.claude/skills/optimizing-claude-code-prompts/references/claude-code-prompting-guide.md');
  const targetText = fs.readFileSync(targetFile, 'utf8');
  const referenceText = fs.readFileSync(referenceFile, 'utf8');
  const badCloneSkillMd = fs.readFileSync(fixturePath('bad-clone/SKILL.md'), 'utf8');
  const datasetTrain = selectedTrain.map((item) => ({ ...item, inputHash: normalizedInputHash(item.input) }));
  const datasetHeldout = heldoutFixtures.map((item) => ({ id: item.id, mode: item.mode, input: item.input, inputHash: normalizedInputHash(item.input) }));
  const trainIds = new Set(datasetTrain.map((item) => item.id));
  const trainHashes = new Set(datasetTrain.map((item) => item.inputHash));
  const disjoint = datasetHeldout.every((item) => !trainIds.has(item.id) && !trainHashes.has(item.inputHash));
  if (!disjoint) throw new Error('Train and heldout fixtures must be disjoint by ID and normalized-input hash');

  const invocationPriceUsd = Number(options.invocationPriceUsd ?? (mode === 'mock' ? 0.25 : Number.NaN));
  const cloneServingCostUsd = Number(options.cloneServingCostUsd ?? (mode === 'mock' ? 0.05 : Number.NaN));
  const deployCostUsd = Number(options.deployCostUsd ?? (mode === 'mock' ? 0.05 : Number.NaN));
  const laborCostUsd = Number(options.laborCostUsd ?? (mode === 'mock' ? 0 : Number.NaN));
  for (const [name, value] of Object.entries({ invocationPriceUsd, cloneServingCostUsd, deployCostUsd, laborCostUsd })) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be supplied explicitly as a non-negative number`);
  }

  const estimatedRequests = N + 1 + heldoutFixtures.length * 3 + v2Fixtures.length * 2;
  const adapter = buildAdapter(mode, { ...options, N, estimatedRequests });
  const sharedExecutor = { repoInventory, executorSettings };
  const acquisitionPairs = [];
  for (const fixture of selectedTrain) {
    const response = await adapter.invoke({
      kind: 'target-train',
      caseId: fixture.id,
      payload: { input: fixture.input, targetSkill: targetText, reference: referenceText, ...sharedExecutor },
    });
    acquisitionPairs.push({ input: fixture.input, output: response.output });
  }

  const distillationPayload = {
    instructions: 'Author one valid SKILL.md that reproduces the demonstrated input-to-output capability. Use only the supplied examples. Return SKILL.md only.',
    pairs: acquisitionPairs,
  };
  const distilled = await adapter.invoke({ kind: 'distill', payload: distillationPayload });
  const cloneSkillMd = distilled.output;
  assertValidClone(cloneSkillMd);

  const targetOutputs = await collect(adapter, heldoutFixtures, 'target-heldout', (fixture) => ({ input: fixture.input, targetSkill: targetText, reference: referenceText, ...sharedExecutor }));
  const cloneOutputs = await collect(adapter, heldoutFixtures, 'clone-heldout', (fixture) => ({ input: fixture.input, cloneSkill: cloneSkillMd, ...sharedExecutor }));
  const badOutputs = await collect(adapter, heldoutFixtures, 'bad-clone-heldout', (fixture) => ({ input: fixture.input, cloneSkill: badCloneSkillMd, ...sharedExecutor }));
  const targetV2Outputs = await collect(adapter, v2Fixtures, 'target-v2-heldout', (fixture) => ({ input: fixture.input, targetSkill: targetText, reference: referenceText, evolutionOverlay, ...sharedExecutor }));
  const cloneV2Outputs = await collect(adapter, v2Fixtures, 'clone-v2-heldout', (fixture) => ({ input: fixture.input, cloneSkill: cloneSkillMd, ...sharedExecutor }));

  const targetScore = scoreEvaluation(targetOutputs, heldoutFixtures);
  const cloneScore = scoreEvaluation(cloneOutputs, heldoutFixtures);
  const badCloneScore = scoreEvaluation(badOutputs, heldoutFixtures);
  const updatedTargetScore = scoreEvaluation(targetV2Outputs, v2Fixtures);
  const frozenCloneScore = scoreEvaluation(cloneV2Outputs, v2Fixtures);
  const scoringA = JSON.stringify({ target: scoreEvaluation(targetOutputs, heldoutFixtures), clone: scoreEvaluation(cloneOutputs, heldoutFixtures) });
  const scoringB = JSON.stringify({ target: scoreEvaluation(targetOutputs, heldoutFixtures), clone: scoreEvaluation(cloneOutputs, heldoutFixtures) });

  const acquisitionProviderUsd = sumCosts(adapter.records, ['target-train']);
  const distillationProviderUsd = sumCosts(adapter.records, ['distill']);
  const evaluationKinds = ['target-heldout', 'clone-heldout', 'bad-clone-heldout', 'target-v2-heldout', 'clone-v2-heldout'];
  const measurementEvaluationUsd = sumCosts(adapter.records, evaluationKinds);
  const economics = computeEconomics({
    N,
    invocationPriceUsd,
    cloneServingCostUsd,
    distillationProviderUsd,
    tuningEvaluationUsd: 0,
    deployCostUsd,
    laborCostUsd,
    measurementEvaluationUsd,
    providerCostBreakdown: {
      acquisitionHarnessProviderUsd: acquisitionProviderUsd,
      distillationProviderUsd,
      benchmarkEvaluationProviderUsd: measurementEvaluationUsd,
    },
  });
  const trainRecords = adapter.records.filter((item) => item.kind === 'target-train');
  const distillRecord = adapter.records.find((item) => item.kind === 'distill');
  const sequentialBuildMs = rounded(trainRecords.reduce((sum, item) => sum + item.latencyMs, 0) + distillRecord.latencyMs);
  const parallelAcquisitionLowerBoundMs = rounded(Math.max(...trainRecords.map((item) => item.latencyMs)) + distillRecord.latencyMs);
  const completeProviderUsage = adapter.records.every((item) => (
    Number.isFinite(item.normalizedUsage.inputTokens)
    && Number.isFinite(item.normalizedUsage.outputTokens)
    && Number.isFinite(item.costUsd)
  ));
  const providerUsageEvidence = completeProviderUsage ? 'measured' : 'measured where returned; unknown otherwise';
  const evidenceLabel = mode === 'mock'
    ? 'SYNTHETIC'
    : `MIXED — provider execution measured; usage/cost ${providerUsageEvidence}; paid-pair acquisition MODELED; fixtures SYNTHETIC`;
  const claimStatus = mode === 'mock'
    ? 'LIVE RUN NOT EXECUTED — no key/explicit opt-in; no measured clone-economics result.'
    : `LIVE RUN EXECUTED — provider calls executed; usage/cost ${providerUsageEvidence}; paid-pair acquisition remains MODELED unless separately settled.`;

  const report = {
    schemaVersion: 1,
    question: 'How cheaply can N paid I/O pairs from the target Skill be distilled into a clone, and how quickly would the original have to evolve to keep a frozen clone stale?',
    mode,
    evidenceLabel,
    claimStatus,
    target: {
      skill: { path: '.claude/skills/optimizing-claude-code-prompts/SKILL.md', sha256: sha256(targetText) },
      reference: { path: '.claude/skills/optimizing-claude-code-prompts/references/claude-code-prompting-guide.md', sha256: sha256(referenceText) },
    },
    dataset: { evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'SYNTHETIC FIXTURES + MEASURED OUTPUTS', N, H: heldoutFixtures.length, train: datasetTrain, heldout: datasetHeldout, disjoint },
    isolation: {
      distillationPairCount: acquisitionPairs.length,
      distillationPayloadSha256: sha256(JSON.stringify(distillationPayload)),
      payloadFields: Object.keys(distillationPayload),
      targetAndCloneSharedContextHash: sha256(JSON.stringify(sharedExecutor)),
    },
    generatedClone: { sha256: sha256(cloneSkillMd), validSkillMd: true },
    fidelity: {
      evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'MEASURED AGAINST DETERMINISTIC RUBRIC',
      rubricVersion: RUBRIC_VERSION,
      threshold: FIDELITY_THRESHOLD,
      target: targetScore,
      clone: cloneScore,
      retention: targetScore.absoluteScore > 0 ? rounded(cloneScore.absoluteScore / targetScore.absoluteScore) : null,
      badClone: badCloneScore,
      scoreDeterminism: { byteIdentical: scoringA === scoringB },
    },
    evolution: {
      evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'SYNTHETIC OVERLAY + MEASURED OUTPUTS',
      overlayVersion: evolutionOverlay.version,
      newRequirement: evolutionOverlay.newRequirement,
      heldoutIds: v2Fixtures.map((item) => item.id),
      updatedTarget: updatedTargetScore,
      frozenClone: frozenCloneScore,
      staleFidelityDelta: rounded(updatedTargetScore.absoluteScore - frozenCloneScore.absoluteScore),
      statement: evolutionOverlay.statement,
    },
    economics: { evidenceLabel: mode === 'mock' ? 'SYNTHETIC + MODELED' : `Provider cost ${providerUsageEvidence}; acquisition MODELED`, ...economics },
    usage: { evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : `Provider usage ${providerUsageEvidence}`, raw: adapter.records, normalized: normalizedUsage(adapter.records) },
    pricing: { evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'OPERATOR-SUPPLIED', ...adapter.pricing },
    timing: {
      evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'MEASURED + DERIVED LOWER BOUND',
      requestLatencies: adapter.records.map((item) => ({ requestId: item.requestId, kind: item.kind, caseId: item.caseId, latencyMs: item.latencyMs, evidenceLabel: item.evidenceLabel })),
      acquisitionSequentialMs: rounded(trainRecords.reduce((sum, item) => sum + item.latencyMs, 0)),
      distillationMs: distillRecord.latencyMs,
      sequentialBuildMs,
      parallelAcquisitionLowerBoundMs,
      evaluationMs: rounded(adapter.records.filter((item) => evaluationKinds.includes(item.kind)).reduce((sum, item) => sum + item.latencyMs, 0)),
      requiredUpdateCadence: {
        label: 'HYPOTHESIS/EXTRAPOLATION',
        statement: 'A static synthetic overlay gives no calendar cadence; dated live Skill revisions and repeated clone freezes are required.',
      },
    },
    limitations: mode === 'mock' ? [
      'All mock outputs, usage, prices, costs, and timings are SYNTHETIC canned evidence.',
      'No API key, model network call, x402 settlement, or live Skill Invocation occurred.',
      'Paid-pair acquisition A is MODELED as N × listed Invocation price.',
      'One static v2 overlay cannot establish Skill half-life or evolution efficacy.',
      'This does not validate the corpus-wide ~30x claim; matched-quality serving cost remains unmeasured.',
    ] : [
      'Provider usage, cost, and latency are measured only when returned; missing values remain unknown.',
      'Paid-pair acquisition A remains MODELED as N × listed Invocation price; this harness does not settle x402 payments.',
      'Deterministic predicates measure contract fidelity, not universal semantic equivalence.',
      'One static v2 overlay cannot establish Skill half-life, evolution efficacy, or a calendar update cadence.',
      'This does not validate the corpus-wide ~30x claim; matched-quality serving cost remains unmeasured.',
    ],
  };
  const jsonReport = renderJson(report);
  const markdownReport = renderMarkdown(report);
  const outputDir = path.resolve(options.outputDir ?? path.join(spikeRoot, 'runs', mode));
  fs.mkdirSync(outputDir, { recursive: true });
  const outputFiles = { json: path.join(outputDir, 'report.json'), markdown: path.join(outputDir, 'report.md') };
  fs.writeFileSync(outputFiles.json, jsonReport);
  fs.writeFileSync(outputFiles.markdown, markdownReport);
  return { report, jsonReport, markdownReport, outputFiles, capturedRequests: adapter.capturedRequests, cloneSkillMd };
}
