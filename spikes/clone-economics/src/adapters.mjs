import { performance } from 'node:perf_hooks';

const clone = (value) => structuredClone(value);
const rounded = (value) => Number(value.toFixed(12));

const LIVE_KIND_INSTRUCTIONS = {
  'target-train': 'Apply the supplied target Skill and reference to the supplied request and synthetic repository context. Return only the resulting response.',
  'target-heldout': 'Apply the supplied target Skill and reference to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'clone-heldout': 'Apply the supplied clone Skill to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'bad-clone-heldout': 'Apply the supplied clone Skill to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'target-v2-heldout': 'Apply the supplied target Skill, reference, and evolution overlay to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'clone-v2-heldout': 'Apply the frozen supplied clone Skill to the supplied v2 heldout request and synthetic repository context. Do not infer target or reference content that was not supplied. Return only the resulting response.',
  distill: 'Using only payload.instructions and payload.pairs, author one valid SKILL.md that reproduces the demonstrated capability. Return SKILL.md only.',
};

export class MockLlmAdapter {
  constructor({ transcript, cloneSkillMd }) {
    this.transcript = transcript;
    this.cloneSkillMd = cloneSkillMd;
    this.capturedRequests = [];
    this.records = [];
    this.pricing = transcript.pricing;
  }

  async invoke(request) {
    this.capturedRequests.push(clone(request));
    let output;
    if (request.kind === 'distill') output = this.cloneSkillMd;
    else if (request.kind === 'target-train') output = this.transcript.trainOutputs[request.caseId];
    else if (request.kind.endsWith('-v2-heldout')) {
      const profile = request.kind.startsWith('target-') ? 'target' : 'clone';
      output = this.transcript.v2Outputs[request.caseId]?.[profile];
    } else {
      const profile = request.kind === 'target-heldout' ? 'target' : request.kind === 'clone-heldout' ? 'clone' : 'bad';
      output = this.transcript.heldoutOutputs[request.caseId]?.[profile];
    }
    if (typeof output !== 'string') throw new Error(`Missing SYNTHETIC transcript output for ${request.kind}:${request.caseId ?? 'distill'}`);
    const profile = this.transcript.usageProfiles[request.kind];
    if (!profile) throw new Error(`Missing SYNTHETIC usage profile for ${request.kind}`);
    const derivedCostUsd = Number.isFinite(profile.inputTokens) && Number.isFinite(profile.outputTokens)
      ? rounded((
        profile.inputTokens * this.pricing.inputUsdPerMillion
        + profile.outputTokens * this.pricing.outputUsdPerMillion
      ) / 1_000_000)
      : null;
    if (profile.costUsd !== null && (!Number.isFinite(derivedCostUsd) || Math.abs(profile.costUsd - derivedCostUsd) > 1e-12)) {
      throw new Error(`SYNTHETIC cost does not reconcile with usage and pricing for ${request.kind}`);
    }
    const record = {
      requestId: `mock-${String(this.records.length + 1).padStart(3, '0')}`,
      kind: request.kind,
      caseId: request.caseId ?? null,
      evidenceLabel: 'SYNTHETIC',
      model: 'mock-canned-model',
      rawUsage: { input_tokens: profile.inputTokens, output_tokens: profile.outputTokens },
      normalizedUsage: { inputTokens: profile.inputTokens, outputTokens: profile.outputTokens },
      costUsd: derivedCostUsd,
      latencyMs: profile.latencyMs,
    };
    this.records.push(record);
    return { output, ...record };
  }
}

function requiredString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} is required for a live run`);
  return value;
}

function requiredPositive(value, name) {
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number for a live run`);
  return value;
}

export class LiveAnthropicAdapter {
  constructor(config) {
    if (config.mode !== 'live' || process.env.MOCK_LLM === '1') throw new Error('Live adapter requires non-mock live mode');
    if (process.env.ALLOW_LIVE_LLM !== '1') throw new Error('ALLOW_LIVE_LLM=1 is required before any live adapter construction');
    this.apiKey = requiredString(config.apiKey, 'ANTHROPIC_API_KEY');
    this.model = requiredString(config.model, 'MODEL');
    this.N = requiredPositive(config.N, 'N');
    this.maxInputTokens = requiredPositive(config.maxInputTokens, 'MAX_INPUT_TOKENS');
    this.maxTokens = requiredPositive(config.maxTokens, 'MAX_TOKENS');
    this.pricing = {
      inputUsdPerMillion: requiredPositive(config.inputUsdPerMillion, 'INPUT_USD_PER_MILLION'),
      outputUsdPerMillion: requiredPositive(config.outputUsdPerMillion, 'OUTPUT_USD_PER_MILLION'),
      asOf: requiredString(config.pricingAsOf, 'PRICING_AS_OF'),
      source: requiredString(config.pricingSource, 'PRICING_SOURCE'),
    };
    this.maxRunCostUsd = requiredPositive(config.maxRunCostUsd, 'MAX_RUN_COST_USD');
    const perRequestCap = (
      this.maxInputTokens * this.pricing.inputUsdPerMillion
      + this.maxTokens * this.pricing.outputUsdPerMillion
    ) / 1_000_000;
    this.conservativeMaxCostUsd = perRequestCap * requiredPositive(config.estimatedRequests, 'estimatedRequests');
    if (this.conservativeMaxCostUsd > this.maxRunCostUsd) {
      throw new Error(`Conservative maximum $${this.conservativeMaxCostUsd.toFixed(6)} exceeds MAX_RUN_COST_USD $${this.maxRunCostUsd.toFixed(6)}`);
    }
    this.capturedRequests = [];
    this.records = [];
    this.measuredSpendUsd = 0;
  }

  async invoke(request) {
    this.capturedRequests.push(clone(request));
    const instruction = LIVE_KIND_INSTRUCTIONS[request.kind];
    if (!instruction) throw new Error(`Unsupported live request kind: ${request.kind}`);
    const prompt = JSON.stringify({ instruction, payload: request.payload });
    // UTF-8 bytes are a deliberately conservative upper bound for tokenizer
    // units: abort before fetch if even that bound exceeds the operator cap.
    const inputTokenUpperBound = Buffer.byteLength(prompt, 'utf8');
    if (inputTokenUpperBound > this.maxInputTokens) {
      throw new Error(`Input token upper bound ${inputTokenUpperBound} exceeds MAX_INPUT_TOKENS ${this.maxInputTokens}`);
    }
    const started = performance.now();
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'anthropic-version': '2023-06-01',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: this.maxTokens,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!response.ok) throw new Error(`Anthropic request failed with HTTP ${response.status}`);
    const json = await response.json();
    const inputTokens = json.usage?.input_tokens;
    const outputTokens = json.usage?.output_tokens;
    const costUsd = Number.isFinite(inputTokens) && Number.isFinite(outputTokens)
      ? inputTokens * this.pricing.inputUsdPerMillion / 1_000_000 + outputTokens * this.pricing.outputUsdPerMillion / 1_000_000
      : null;
    const usageEvidenceLabel = costUsd === null
      ? 'PROVIDER RESPONSE MEASURED; USAGE/COST UNKNOWN'
      : 'MEASURED';
    if (costUsd !== null) {
      this.measuredSpendUsd += costUsd;
      if (this.measuredSpendUsd > this.maxRunCostUsd) throw new Error('Cumulative measured spend exceeded MAX_RUN_COST_USD');
    }
    const record = {
      requestId: json.id ?? `live-${this.records.length + 1}`,
      kind: request.kind,
      caseId: request.caseId ?? null,
      evidenceLabel: usageEvidenceLabel,
      model: this.model,
      rawUsage: json.usage ?? null,
      normalizedUsage: {
        inputTokens: Number.isFinite(inputTokens) ? inputTokens : null,
        outputTokens: Number.isFinite(outputTokens) ? outputTokens : null,
      },
      costUsd,
      latencyMs: performance.now() - started,
    };
    this.records.push(record);
    return { output: json.content?.find((item) => item.type === 'text')?.text ?? '', ...record };
  }
}
