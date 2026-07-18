// Offline end-to-end proof through the one public seam: runExperiment().
process.env.MOCK_LLM = '1';
process.env.ALLOW_LIVE_LLM = '0';
delete process.env.ANTHROPIC_API_KEY;
delete process.env.OPENAI_API_KEY;

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

let networkAttempts = 0;
globalThis.fetch = async () => {
  networkAttempts += 1;
  throw new Error('NETWORK FORBIDDEN IN MOCK E2E');
};

const { runExperiment } = await import('./src/experiment.mjs');

let checks = 0;
function ok(condition, label) {
  checks += 1;
  assert.ok(condition, label);
  console.log(`  ✓ ${label}`);
}
function eq(actual, expected, label) {
  checks += 1;
  assert.deepEqual(actual, expected, label);
  console.log(`  ✓ ${label}`);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const targetPath = path.resolve(here, '../../.claude/skills/optimizing-claude-code-prompts/SKILL.md');
const referencePath = path.resolve(here, '../../.claude/skills/optimizing-claude-code-prompts/references/claude-code-prompting-guide.md');
const targetText = fs.readFileSync(targetPath, 'utf8');
const referenceText = fs.readFileSync(referencePath, 'utf8');
function treeSnapshot(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { recursive: true }).map(String).sort();
}
const retainedRuns = path.join(here, 'runs');
const runsBefore = treeSnapshot(retainedRuns);
const outputA = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-economics-a-'));
const outputB = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-economics-b-'));

const config = {
  mode: 'mock',
  N: 6,
  invocationPriceUsd: 0.25,
  cloneServingCostUsd: 0.05,
  deployCostUsd: 0.05,
  laborCostUsd: 0,
};

console.log('\nClone-economics e2e — MOCK_LLM=1, network disabled\n');
try {
  const first = await runExperiment({ ...config, outputDir: outputA });
  const second = await runExperiment({ ...config, outputDir: outputB });
  const report = first.report;

  eq(report.mode, 'mock', 'mock mode recorded');
  eq(report.evidenceLabel, 'SYNTHETIC', 'all mock evidence labeled SYNTHETIC');
  ok([report.dataset, report.fidelity, report.economics, report.usage, report.pricing, report.timing].every((section) => section.evidenceLabel.includes('SYNTHETIC')), 'every numeric mock report section carries a SYNTHETIC label');
  ok(report.claimStatus.includes('LIVE RUN NOT EXECUTED'), 'report denies a live run');
  ok(report.claimStatus.includes('no measured clone-economics result'), 'report denies measured economics');

  eq(report.dataset.N, 6, 'exactly N acquisition pairs');
  eq(report.dataset.H, 6, 'heldout count recorded');
  eq(new Set(report.dataset.train.map((item) => item.id)).size, 6, 'train fixture IDs unique');
  eq(new Set(report.dataset.heldout.map((item) => item.id)).size, 6, 'heldout fixture IDs unique');
  ok(report.dataset.disjoint, 'train and heldout IDs/hashes are disjoint');
  ok(report.dataset.train.concat(report.dataset.heldout).every((item) => /^sha256:[0-9a-f]{64}$/.test(item.inputHash)), 'normalized-input hashes recorded');

  const acquisition = first.capturedRequests.filter((request) => request.kind === 'target-train');
  const evaluations = first.capturedRequests.filter((request) => request.kind.endsWith('-heldout'));
  eq(acquisition.length, 6, 'target Skill invoked exactly N times for acquisition');
  ok(evaluations.every((request) => report.dataset.heldout.some((item) => item.id === request.caseId) || report.evolution.heldoutIds.includes(request.caseId)), 'evaluation uses heldout only');
  ok(acquisition.every((request) => !evaluations.some((evaluation) => evaluation.caseId === request.caseId)), 'train cases never enter evaluation');
  const targetHeldout = first.capturedRequests.find((request) => request.kind === 'target-heldout');
  const cloneHeldout = first.capturedRequests.find((request) => request.kind === 'clone-heldout' && request.caseId === targetHeldout.caseId);
  eq(targetHeldout.payload.repoInventory, cloneHeldout.payload.repoInventory, 'target and clone receive identical synthetic repo context');
  eq(targetHeldout.payload.executorSettings, cloneHeldout.payload.executorSettings, 'target and clone receive identical executor settings');

  const distill = first.capturedRequests.find((request) => request.kind === 'distill');
  ok(distill, 'distillation request captured');
  eq(Object.keys(distill.payload).sort(), ['instructions', 'pairs'], 'distillation payload has only generic instructions and pairs');
  eq(distill.payload.pairs.length, 6, 'distillation receives exactly N pairs');
  ok(distill.payload.pairs.every((pair) => Object.keys(pair).sort().join(',') === 'input,output'), 'each distillation pair contains input/output only');
  const distillBytes = JSON.stringify(distill.payload);
  ok(!distillBytes.includes('The one rule that makes this skill worth invoking'), 'distinctive target fingerprint excluded');
  ok(!distillBytes.includes('The seven ingredients'), 'second target fingerprint excluded');
  ok(!distillBytes.includes(targetText), 'target Skill text excluded');
  ok(!distillBytes.includes(referenceText), 'target reference text excluded');
  ok(!report.dataset.heldout.some((item) => distillBytes.includes(item.id) || distillBytes.includes(item.input)), 'heldout IDs and requests excluded');
  ok(!/requiredAll|requiredAny|forbidden|rubric|toolTrace/i.test(distillBytes), 'rubric and tool traces excluded');
  const heldoutFixtures = JSON.parse(fs.readFileSync(path.join(here, 'fixtures/heldout.json'), 'utf8'));
  const heldoutAnswerFeatures = heldoutFixtures.flatMap((fixture) => [
    ...fixture.rubric.exactPaths.map((item) => item.value),
    ...fixture.rubric.exactCommands.map((item) => item.value),
    ...fixture.rubric.requiredAll.map((item) => item.value),
  ]);
  const acquiredAnswers = distill.payload.pairs.map((pair) => pair.output).join('\n');
  ok(heldoutAnswerFeatures.every((feature) => !acquiredAnswers.includes(feature)), 'heldout path/command/constraint answer features are absent from acquired outputs');

  ok(first.cloneSkillMd.startsWith('---\nname:'), 'valid clone SKILL.md produced');
  ok(first.cloneSkillMd.includes('\n# '), 'clone SKILL.md has a body');
  ok(!first.cloneSkillMd.includes('The one rule that makes this skill worth invoking'), 'clone does not copy target fingerprint');
  ok(/^sha256:[0-9a-f]{64}$/.test(report.generatedClone.sha256), 'clone hash recorded');
  eq(report.target.skill.path, '.claude/skills/optimizing-claude-code-prompts/SKILL.md', 'target path recorded without content');
  eq(report.target.reference.path, '.claude/skills/optimizing-claude-code-prompts/references/claude-code-prompting-guide.md', 'reference path recorded without content');
  ok(!first.jsonReport.includes(targetText.slice(0, 300)), 'report does not copy target text');

  eq(report.fidelity.rubricVersion, 'contract-v1', 'versioned deterministic rubric recorded');
  eq(report.fidelity.target.absoluteScore, 1, 'known literal target score');
  eq(report.fidelity.clone.absoluteScore, 0.9, 'known literal good-clone score');
  eq(report.benchmark.verdict, 'VALID_BENCHMARK', 'passing target admits interpretation');
  ok(report.fidelity.clone.passedThreshold && report.fidelity.clone.criticalGatePass, 'good clone clears 0.80 and critical gates');
  eq(report.fidelity.retention, 0.9, 'clone/target retention secondary metric');
  eq(report.fidelity.badClone.absoluteScore, 0.2, 'known literal bad-clone score');
  ok(!report.fidelity.badClone.criticalGatePass && !report.fidelity.badClone.passedThreshold, 'bad clone fails a critical gate');
  ok(report.fidelity.scoreDeterminism.byteIdentical, 'repeated deterministic scoring is byte-identical');
  eq(report.fidelity.target.cases.length, 6, 'per-case target scores reported');
  ok(report.fidelity.clone.cases.every((item) => item.dimensions && typeof item.score === 'number'), 'per-case and dimension clone scores reported');

  eq(report.evolution.evidenceLabel, 'SYNTHETIC', 'v2 overlay labeled SYNTHETIC');
  eq(report.evolution.updatedTarget.absoluteScore, 1, 'known literal v2 target score');
  eq(report.evolution.frozenClone.absoluteScore, 0.75, 'known literal frozen-clone v2 score');
  eq(report.evolution.staleFidelityDelta, 0.25, 'known literal stale-fidelity delta');
  ok(report.evolution.statement.includes('cannot establish Skill half-life'), 'single overlay limitation explicit');

  eq(report.economics.acquisitionModeledUsd, 1.5, 'A = N × listed Invocation price');
  eq(report.economics.distillationProviderUsd, 0.3, 'D literal');
  eq(report.economics.tuningEvaluationUsd, 0, 'E_tune is zero because no tuning occurred');
  eq(report.economics.attackerBuildUsd, 1.85, 'B excludes benchmark evaluation');
  eq(report.economics.distillationToAcquisition, 0.2, 'D/A literal ratio');
  eq(report.economics.buildToAcquisition, 1.233333333333, 'B/A literal ratio');
  eq(report.economics.breakEvenInvocations, 10, 'break-even literal');
  eq(report.economics.measurementEvaluationUsd, 0.126, 'E_measure reported separately');
  eq(report.economics.zeroPriceProbe.distillationToAcquisition, null, 'D/A undefined when P=0');
  eq(report.economics.zeroPriceProbe.buildToAcquisition, null, 'B/A undefined when P=0');
  eq(report.economics.zeroPriceProbe.breakEvenInvocations, null, 'break-even undefined without positive margin');
  ok(report.economics.providerCostsNotAddedToAcquisition, 'provider costs not double-counted into modeled acquisition');

  ok(report.usage.raw.every((item) => item.evidenceLabel === 'SYNTHETIC'), 'raw usage tagged SYNTHETIC');
  ok(report.usage.raw.every((item) => {
    if (item.costUsd === null) return true;
    const expected = (
      item.rawUsage.input_tokens * report.pricing.inputUsdPerMillion
      + item.rawUsage.output_tokens * report.pricing.outputUsdPerMillion
    ) / 1_000_000;
    return Math.abs(item.costUsd - expected) < 1e-12;
  }), 'every mock provider cost equals usage × supplied pricing');
  ok(report.usage.normalized.inputTokens > 0 && report.usage.normalized.outputTokens > 0, 'normalized usage totals reported');
  ok(report.pricing.asOf && report.pricing.source && report.pricing.inputUsdPerMillion > 0, 'pricing snapshot/as-of/source reported');
  eq(report.timing.sequentialBuildMs, 1000, 'sequential build time literal');
  eq(report.timing.parallelAcquisitionLowerBoundMs, 500, 'parallel-acquisition lower bound literal');
  ok(report.timing.requiredUpdateCadence.label === 'HYPOTHESIS/EXTRAPOLATION', 'update cadence labeled hypothesis/extrapolation');

  ok(first.jsonReport.includes('SYNTHETIC') && first.markdownReport.includes('SYNTHETIC'), 'JSON and Markdown reports carry evidence labels');
  ok(first.markdownReport.includes('no measured clone-economics result'), 'Markdown preserves honesty verdict');
  ok(!first.markdownReport.split('\n').some((line) => /[ \t]+$/.test(line)), 'Markdown report contains no trailing whitespace');
  eq(fs.readFileSync(first.outputFiles.json, 'utf8'), fs.readFileSync(second.outputFiles.json, 'utf8'), 'two JSON report runs are byte-identical');
  eq(fs.readFileSync(first.outputFiles.markdown, 'utf8'), fs.readFileSync(second.outputFiles.markdown, 'utf8'), 'two Markdown report runs are byte-identical');
  eq(treeSnapshot(retainedRuns), runsBefore, 'e2e leaves pre-existing run artifacts unchanged');

  const unknownTranscript = JSON.parse(fs.readFileSync(path.join(here, 'fixtures/mock-transcript.json'), 'utf8'));
  unknownTranscript.usageProfiles.distill.inputTokens = null;
  unknownTranscript.usageProfiles.distill.costUsd = null;
  for (const outputs of Object.values(unknownTranscript.heldoutOutputs)) outputs.target = 'Wrong [placeholder]???';
  const unknown = await runExperiment({ ...config, outputDir: outputA, mockTranscript: unknownTranscript });
  eq(unknown.report.economics.distillationProviderUsd, null, 'missing provider usage keeps D unknown, never zero');
  eq(unknown.report.economics.attackerBuildUsd, null, 'unknown D propagates to B');
  eq(unknown.report.economics.distillationToAcquisition, null, 'unknown D propagates to D/A');
  eq(unknown.report.economics.buildToAcquisition, null, 'unknown B propagates to B/A');
  eq(unknown.report.usage.normalized.inputTokens, null, 'missing raw input usage keeps normalized input total unknown');
  eq(unknown.report.usage.normalized.providerCostUsd, null, 'missing request cost keeps normalized provider total unknown');
  eq(unknown.report.benchmark.verdict, 'INVALID_BENCHMARK_TARGET_FAILED', 'failed target invalidates benchmark');
  eq(unknown.report.fidelity.retention, null, 'invalid target suppresses retention');
  eq(unknown.report.economics.breakEvenInvocations, null, 'invalid target suppresses break-even');
  ok(unknown.markdownReport.includes('Clone quality, fidelity defense, moat, and break-even conclusions are suppressed'), 'invalid report states suppression');
  ok(unknown.markdownReport.includes('unknown'), 'Markdown renders unknown values without crashing');

  const replayTranscript = JSON.parse(fs.readFileSync(path.join(here, 'fixtures/mock-transcript.json'), 'utf8'));
  const replayCloneSkill = fs.readFileSync(path.join(here, 'fixtures/good-clone/SKILL.md'), 'utf8');
  const missingUsageReplayAdapter = {
    pricing: replayTranscript.pricing,
    capturedRequests: [],
    records: [],
    async invoke(request) {
      this.capturedRequests.push(structuredClone(request));
      let output;
      if (request.kind === 'distill') output = replayCloneSkill;
      else if (request.kind === 'target-train') output = replayTranscript.trainOutputs[request.caseId];
      else if (request.kind.endsWith('-v2-heldout')) {
        output = replayTranscript.v2Outputs[request.caseId][request.kind.startsWith('target-') ? 'target' : 'clone'];
      } else {
        const profile = request.kind === 'target-heldout' ? 'target' : request.kind === 'clone-heldout' ? 'clone' : 'bad';
        output = replayTranscript.heldoutOutputs[request.caseId][profile];
      }
      const record = {
        requestId: `replay-${String(this.records.length + 1).padStart(3, '0')}`,
        kind: request.kind,
        caseId: request.caseId ?? null,
        evidenceLabel: 'MEASURED WHERE RETURNED; UNKNOWN OTHERWISE',
        model: 'offline-missing-usage-replay',
        rawUsage: null,
        normalizedUsage: { inputTokens: null, outputTokens: null },
        costUsd: null,
        latencyMs: 1,
      };
      this.records.push(record);
      return { output, ...record };
    },
  };
  const missingLiveUsage = await runExperiment({
    ...config,
    mode: 'live',
    outputDir: outputA,
    adapter: missingUsageReplayAdapter,
  });
  ok(missingLiveUsage.report.evidenceLabel.includes('measured where returned; unknown otherwise'), 'live summary labels incomplete usage as measured where returned and unknown otherwise');
  ok(missingLiveUsage.report.economics.evidenceLabel.includes('measured where returned; unknown otherwise'), 'live economics labels incomplete cost as measured where returned and unknown otherwise');
  ok(missingLiveUsage.report.usage.evidenceLabel.includes('measured where returned; unknown otherwise'), 'live usage labels incomplete fields as measured where returned and unknown otherwise');
  eq(missingLiveUsage.report.economics.distillationProviderUsd, null, 'stubbed-live missing usage keeps D unknown');
  eq(missingLiveUsage.report.economics.attackerBuildUsd, null, 'stubbed-live unknown D propagates to B');
  eq(missingLiveUsage.report.economics.distillationToAcquisition, null, 'stubbed-live unknown D propagates to D/A');
  eq(missingLiveUsage.report.economics.buildToAcquisition, null, 'stubbed-live unknown B propagates to B/A');
  eq(missingLiveUsage.report.usage.normalized.inputTokens, null, 'stubbed-live missing usage remains null in JSON');
  ok(missingLiveUsage.markdownReport.includes('Normalized usage: unknown input tokens, unknown output tokens.'), 'stubbed-live Markdown renders missing usage as unknown');
  eq(missingLiveUsage.report.economics.laborCostTreatment, 'Explicitly excluded from this run.', 'labor exclusion wording is mode-neutral');
  eq(networkAttempts, 0, 'stubbed-live report regression performs no fetch');

  const liveConfig = {
    mode: 'live', outputDir: outputA, N: 6,
    invocationPriceUsd: 0.25, cloneServingCostUsd: 0.05, deployCostUsd: 0, laborCostUsd: 0,
    apiKey: 'synthetic-never-used', model: 'synthetic-live-guard-probe',
    maxInputTokens: 4096, maxTokens: 1024,
    inputUsdPerMillion: 3, outputUsdPerMillion: 15,
    pricingAsOf: '2026-07-12', pricingSource: 'synthetic guard probe', maxRunCostUsd: 100,
  };
  process.env.MOCK_LLM = '0';
  process.env.ALLOW_LIVE_LLM = '0';
  checks += 1;
  await assert.rejects(runExperiment(liveConfig), /ALLOW_LIVE_LLM=1/, 'explicit live opt-in blocks a fully configured run');
  console.log('  ✓ explicit live opt-in blocks a fully configured run');
  eq(networkAttempts, 0, 'opt-in rejection occurs before fetch');

  process.env.ALLOW_LIVE_LLM = '1';
  checks += 1;
  await assert.rejects(
    runExperiment({ ...liveConfig, maxInputTokens: 1 }),
    /input token upper bound/i,
    'configured input-token bound aborts before fetch',
  );
  console.log('  ✓ configured input-token bound aborts before fetch');
  eq(networkAttempts, 0, 'input-bound rejection occurs before fetch');
  process.env.MOCK_LLM = '1';
  process.env.ALLOW_LIVE_LLM = '0';

  console.log(`\nPASS — ${checks} checks green.`);
} finally {
  fs.rmSync(outputA, { recursive: true, force: true });
  fs.rmSync(outputB, { recursive: true, force: true });
}
