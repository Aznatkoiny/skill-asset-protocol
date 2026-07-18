import { performance } from 'node:perf_hooks';

import {
  calculateProviderCostMicroUsd,
  createAttemptBudget,
  exceedsCommittedTokenCaps,
} from './budget.mjs';

const clone = (value) => structuredClone(value);
const rounded = (value) => Number(value.toFixed(12));
const DEFAULT_LIVE_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_LIVE_RESPONSE_BYTES = 1_048_576;

async function withWallClockDeadline(timeoutMs, operation) {
  const controller = new AbortController();
  const timeoutError = new Error('Anthropic request timed out');
  let timeoutId;
  const deadline = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort(timeoutError);
      reject(timeoutError);
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      deadline,
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}

function cancelReader(reader, reason) {
  try {
    const cancellation = reader.cancel(reason);
    void Promise.resolve(cancellation).catch(() => {});
  } catch {
    // The boundary error remains authoritative even if cancellation itself fails.
  }
}

async function readBoundedJson(response, { maxBytes, signal }) {
  let body;
  try {
    body = response?.body;
  } catch {
    throw new Error('Anthropic response body is unavailable');
  }
  if (!body || typeof body.getReader !== 'function') {
    throw new Error('Anthropic response body is unavailable');
  }
  let reader;
  try {
    reader = body.getReader();
  } catch {
    throw new Error('Anthropic response body is unavailable');
  }
  const cancelOnAbort = () => cancelReader(reader, signal.reason);
  if (signal.aborted) {
    cancelOnAbort();
    if (signal.reason instanceof Error) throw signal.reason;
    throw new Error('Anthropic request timed out');
  }
  signal.addEventListener('abort', cancelOnAbort, { once: true });
  try {
    const chunks = [];
    let totalBytes = 0;
    while (true) {
      let result;
      try {
        result = await reader.read();
      } catch {
        if (signal.aborted && signal.reason instanceof Error) throw signal.reason;
        throw new Error('Anthropic response could not be read');
      }
      if (result.done) break;
      if (!(result.value instanceof Uint8Array)) {
        const error = new Error('Anthropic response could not be read');
        cancelReader(reader, error);
        throw error;
      }
      if (result.value.byteLength > maxBytes - totalBytes) {
        const error = new Error('Anthropic response exceeded byte limit');
        cancelReader(reader, error);
        throw error;
      }
      chunks.push(result.value);
      totalBytes += result.value.byteLength;
    }
    try {
      return JSON.parse(Buffer.concat(chunks, totalBytes).toString('utf8'));
    } catch {
      throw new Error('Anthropic response was not valid JSON');
    }
  } finally {
    signal.removeEventListener('abort', cancelOnAbort);
  }
}

const LIVE_KIND_INSTRUCTIONS = {
  'target-train': 'Apply the supplied target Skill and reference to the supplied request and synthetic repository context. Return only the resulting response.',
  'target-heldout': 'Apply the supplied target Skill and reference to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'clone-heldout': 'Apply the supplied clone Skill to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'bad-clone-heldout': 'Apply the supplied clone Skill to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'target-v2-heldout': 'Apply the supplied target Skill, reference, and evolution overlay to the supplied heldout request and synthetic repository context. Return only the resulting response.',
  'clone-v2-heldout': 'Apply the frozen supplied clone Skill to the supplied v2 heldout request and synthetic repository context. Do not infer target or reference content that was not supplied. Return only the resulting response.',
  distill: 'Using only payload.instructions and payload.pairs, author one valid SKILL.md that reproduces the demonstrated capability. Return SKILL.md only.',
};

function seedEvidence(request, mode) {
  const requestedSeed = request.kind === 'distill'
    ? request.requestedDistillationSeed ?? null
    : null;
  if (requestedSeed !== null && !Number.isSafeInteger(requestedSeed)) {
    throw new Error('Requested distillation seed must be a safe integer');
  }
  if (requestedSeed === null) {
    return {
      requestedSeed: null,
      appliedSeed: null,
      status: 'not_requested',
      mechanism: 'no_seed_requested',
    };
  }
  if (mode === 'mock') {
    return {
      requestedSeed,
      appliedSeed: requestedSeed,
      status: 'synthetic_honored',
      mechanism: 'deterministic_mock_fixture_selection',
    };
  }
  return {
    requestedSeed,
    appliedSeed: null,
    status: 'unsupported',
    mechanism: 'provider_seed_not_supported_by_adapter',
  };
}

export class MockLlmAdapter {
  constructor({ transcript, cloneSkillMd, outputFor = null }) {
    this.transcript = transcript;
    this.cloneSkillMd = cloneSkillMd;
    this.outputFor = outputFor;
    this.capturedRequests = [];
    this.records = [];
    this.attempts = [];
    this.pricing = transcript.pricing;
  }

  async invoke(request) {
    this.capturedRequests.push(clone(request));
    const requestIdentifier = {
      kind: request.kind,
      caseId: request.caseId ?? null,
      requestedDistillationSeed: request.requestedDistillationSeed ?? null,
    };
    const customOutput = this.outputFor?.(requestIdentifier);
    let output = typeof customOutput === 'string' ? customOutput : undefined;
    if (output === undefined) {
      if (request.kind === 'distill') output = this.cloneSkillMd;
      else if (request.kind === 'target-train') output = this.transcript.trainOutputs[request.caseId];
      else if (request.kind.endsWith('-v2-heldout')) {
        const profile = request.kind.startsWith('target-') ? 'target' : 'clone';
        output = this.transcript.v2Outputs[request.caseId]?.[profile];
      } else {
        const profile = request.kind === 'target-heldout'
          ? 'target'
          : request.kind === 'clone-heldout' ? 'clone' : 'bad';
        output = this.transcript.heldoutOutputs[request.caseId]?.[profile];
      }
    }
    if (typeof output !== 'string') {
      throw new Error(`Missing SYNTHETIC transcript output for ${request.kind}:${request.caseId ?? 'distill'}`);
    }
    const profile = this.transcript.usageProfiles[request.kind];
    if (!profile) throw new Error(`Missing SYNTHETIC usage profile for ${request.kind}`);
    const derivedCostUsd = Number.isFinite(profile.inputTokens) && Number.isFinite(profile.outputTokens)
      ? rounded((
        profile.inputTokens * this.pricing.inputUsdPerMillion
        + profile.outputTokens * this.pricing.outputUsdPerMillion
      ) / 1_000_000)
      : null;
    if (profile.costUsd !== null && (!Number.isFinite(derivedCostUsd)
        || Math.abs(profile.costUsd - derivedCostUsd) > 1e-12)) {
      throw new Error(`SYNTHETIC cost does not reconcile with usage and pricing for ${request.kind}`);
    }
    const seed = seedEvidence(request, 'mock');
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
    this.attempts.push({
      attemptId: `${request.kind}:${request.caseId ?? 'distill'}:${this.attempts.length + 1}`,
      budgetAttemptId: null,
      kind: request.kind,
      caseId: request.caseId ?? null,
      success: true,
      providerRequestId: record.requestId,
      latencyMs: record.latencyMs,
      inputTokens: record.normalizedUsage.inputTokens,
      outputTokens: record.normalizedUsage.outputTokens,
      providerCostMicroUsd: derivedCostUsd === null
        ? null
        : String(Math.round(derivedCostUsd * 1_000_000)),
      providerCostUsd: derivedCostUsd,
      failureClass: null,
      ...seed,
    });
    return { output, ...record, seed };
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

function legacySnapshot(config) {
  return {
    schemaVersion: 1,
    experimentFamily: 'legacy-single-clone-run',
    approvalStatus: 'approved',
    provider: 'anthropic',
    model: requiredString(config.model, 'MODEL'),
    pricing: {
      currency: 'USD',
      unit: 'per_million_tokens',
      inputUsdPerMillionTokens: String(requiredPositive(config.inputUsdPerMillion, 'INPUT_USD_PER_MILLION')),
      outputUsdPerMillionTokens: String(requiredPositive(config.outputUsdPerMillion, 'OUTPUT_USD_PER_MILLION')),
      asOf: requiredString(config.pricingAsOf, 'PRICING_AS_OF'),
      source: requiredString(config.pricingSource, 'PRICING_SOURCE'),
    },
    tokenCaps: {
      maxInputTokens: requiredPositive(config.maxInputTokens, 'MAX_INPUT_TOKENS'),
      maxOutputTokens: requiredPositive(config.maxTokens, 'MAX_TOKENS'),
    },
  };
}

export class LiveAnthropicAdapter {
  constructor(config) {
    if (config.mode !== 'live' || process.env.MOCK_LLM === '1') {
      throw new Error('Live adapter requires non-mock live mode');
    }
    const syntheticTestTransport = config.testOnlyNoNetwork === true
      && typeof config.fetchImpl === 'function'
      && String(config.apiKey).startsWith('synthetic-');
    if (process.env.ALLOW_LIVE_LLM !== '1' && !syntheticTestTransport) {
      throw new Error('ALLOW_LIVE_LLM=1 is required before any live adapter construction');
    }
    this.apiKey = requiredString(config.apiKey, 'ANTHROPIC_API_KEY');
    this.snapshot = config.snapshot ?? legacySnapshot(config);
    this.model = requiredString(this.snapshot.model, 'MODEL');
    this.maxInputTokens = requiredPositive(this.snapshot.tokenCaps.maxInputTokens, 'MAX_INPUT_TOKENS');
    this.maxTokens = requiredPositive(this.snapshot.tokenCaps.maxOutputTokens, 'MAX_TOKENS');
    this.pricing = {
      inputUsdPerMillion: Number(this.snapshot.pricing.inputUsdPerMillionTokens),
      outputUsdPerMillion: Number(this.snapshot.pricing.outputUsdPerMillionTokens),
      asOf: this.snapshot.pricing.asOf,
      source: this.snapshot.pricing.source,
    };
    const legacyCapMicroUsd = config.maxRunCostUsd === undefined
      ? null
      : BigInt(Math.round(requiredPositive(config.maxRunCostUsd, 'MAX_RUN_COST_USD') * 1_000_000));
    const legacyWorstCaseMicroUsd = calculateProviderCostMicroUsd({
      inputTokens: this.maxInputTokens,
      outputTokens: this.maxTokens,
      snapshot: this.snapshot,
    });
    if (!config.budget) {
      const requests = requiredPositive(config.estimatedRequests, 'estimatedRequests');
      const conservative = legacyWorstCaseMicroUsd * BigInt(requests);
      if (conservative > legacyCapMicroUsd) {
        throw new Error(`Conservative maximum $${(Number(conservative) / 1_000_000).toFixed(6)} exceeds MAX_RUN_COST_USD $${(Number(legacyCapMicroUsd) / 1_000_000).toFixed(6)}`);
      }
    }
    this.budget = config.budget ?? createAttemptBudget({
      capMicroUsd: legacyCapMicroUsd,
      worstCaseCallMicroUsd: legacyWorstCaseMicroUsd,
    });
    this.fetchImpl = config.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') throw new Error('A fetch implementation is required');
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_LIVE_REQUEST_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.requestTimeoutMs) || this.requestTimeoutMs <= 0) {
      throw new Error('requestTimeoutMs must be a positive safe integer');
    }
    this.maxResponseBytes = config.maxResponseBytes ?? DEFAULT_LIVE_RESPONSE_BYTES;
    if (!Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes <= 0) {
      throw new Error('maxResponseBytes must be a positive safe integer');
    }
    this.capturedRequests = [];
    this.records = [];
    this.attempts = [];
  }

  async invoke(request) {
    this.capturedRequests.push(clone(request));
    const instruction = LIVE_KIND_INSTRUCTIONS[request.kind];
    if (!instruction) throw new Error(`Unsupported live request kind: ${request.kind}`);
    const seed = seedEvidence(request, 'live');
    const prompt = JSON.stringify({ instruction, payload: request.payload });
    const inputTokenUpperBound = Buffer.byteLength(prompt, 'utf8');
    if (inputTokenUpperBound > this.maxInputTokens) {
      throw new Error(`Input token upper bound ${inputTokenUpperBound} exceeds MAX_INPUT_TOKENS ${this.maxInputTokens}`);
    }

    const started = performance.now();
    let reservationId = null;
    let observedUsage = null;
    let knownCostMicroUsd = null;
    let providerRequestId = null;
    let originalError = null;
    let capError = null;
    try {
      reservationId = this.budget.reserveNextAttempt({ kind: request.kind, caseId: request.caseId ?? null });
      const { response, json } = await withWallClockDeadline(
        this.requestTimeoutMs,
        async (signal) => {
          let providerResponse;
          try {
            providerResponse = await this.fetchImpl('https://api.anthropic.com/v1/messages', {
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
              redirect: 'error',
              signal,
            });
          } catch {
            if (signal.aborted && signal.reason instanceof Error) throw signal.reason;
            throw new Error('Anthropic request failed');
          }
          const providerJson = await readBoundedJson(providerResponse, {
            maxBytes: this.maxResponseBytes,
            signal,
          });
          return { response: providerResponse, json: providerJson };
        },
      );
      providerRequestId = typeof json.id === 'string' ? json.id : null;
      const inputTokens = json.usage?.input_tokens;
      const outputTokens = json.usage?.output_tokens;
      if (Number.isSafeInteger(inputTokens) && inputTokens >= 0
          && Number.isSafeInteger(outputTokens) && outputTokens >= 0) {
        observedUsage = { inputTokens, outputTokens };
        knownCostMicroUsd = calculateProviderCostMicroUsd({ inputTokens, outputTokens, snapshot: this.snapshot });
      }
      if (!response.ok) throw new Error(`Anthropic request failed with HTTP ${response.status}`);
      if (!observedUsage) throw new Error('Anthropic response omitted valid usage');
      const tokenCapExceeded = exceedsCommittedTokenCaps({ ...observedUsage, snapshot: this.snapshot });
      if (tokenCapExceeded) capError = new Error('Observed provider usage exceeded committed token cap');
      this.budget.settleAttempt(reservationId, {
        knownCostMicroUsd,
        success: !tokenCapExceeded,
        budgetViolation: tokenCapExceeded ? 'token_cap_exceeded' : null,
      });
      const latencyMs = performance.now() - started;
      const costUsd = Number(knownCostMicroUsd) / 1_000_000;
      const record = {
        requestId: providerRequestId ?? `live-${this.records.length + 1}`,
        kind: request.kind,
        caseId: request.caseId ?? null,
        evidenceLabel: 'MEASURED',
        model: this.model,
        rawUsage: { input_tokens: observedUsage.inputTokens, output_tokens: observedUsage.outputTokens },
        normalizedUsage: { ...observedUsage },
        costUsd,
        latencyMs,
      };
      this.records.push(record);
      this.attempts.push({
        attemptId: `${request.kind}:${request.caseId ?? 'distill'}:${this.attempts.length + 1}`,
        budgetAttemptId: reservationId,
        kind: request.kind,
        caseId: request.caseId ?? null,
        success: true,
        providerRequestId,
        latencyMs,
        inputTokens: observedUsage.inputTokens,
        outputTokens: observedUsage.outputTokens,
        providerCostMicroUsd: knownCostMicroUsd.toString(),
        providerCostUsd: costUsd,
        failureClass: null,
        ...seed,
      });
      return {
        output: json.content?.find((item) => item.type === 'text')?.text ?? '',
        ...record,
        seed,
      };
    } catch (error) {
      originalError = error;
      // A refusal before reservation means no provider attempt occurred. Keep
      // adapter attempt accounting exactly aligned with budget reservations.
      if (reservationId === null) throw originalError;
      let settlementError = null;
      const currentLock = this.budget.state().lock;
      if (currentLock?.attemptId === reservationId) {
        settlementError = error;
        originalError = capError ?? originalError;
      } else {
        try {
          const tokenCapExceeded = observedUsage
            ? exceedsCommittedTokenCaps({ ...observedUsage, snapshot: this.snapshot })
            : false;
          this.budget.settleAttempt(reservationId, {
            knownCostMicroUsd,
            success: false,
            budgetViolation: tokenCapExceeded ? 'token_cap_exceeded' : null,
          });
        } catch (settleError) {
          settlementError = settleError;
        }
      }
      const latencyMs = performance.now() - started;
      this.attempts.push({
        attemptId: `${request.kind}:${request.caseId ?? 'distill'}:${this.attempts.length + 1}`,
        budgetAttemptId: reservationId,
        kind: request.kind,
        caseId: request.caseId ?? null,
        success: false,
        providerRequestId: null,
        latencyMs,
        inputTokens: observedUsage?.inputTokens ?? null,
        outputTokens: observedUsage?.outputTokens ?? null,
        providerCostMicroUsd: knownCostMicroUsd?.toString() ?? null,
        providerCostUsd: knownCostMicroUsd === null
          ? null
          : Number(knownCostMicroUsd) / 1_000_000,
        failureClass: error instanceof Error ? error.name : 'UnknownError',
        ...seed,
      });
      if (settlementError) {
        throw new AggregateError(
          [settlementError, originalError],
          `${settlementError instanceof Error ? settlementError.message : 'Budget lock'}; ${originalError instanceof Error ? originalError.message : 'provider failure'}`,
        );
      }
      throw originalError;
    }
  }
}
