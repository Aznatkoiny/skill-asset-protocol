#!/usr/bin/env node
// cma-latency-bench.mjs
//
// Benchmark for Anthropic Managed Agents (CMA) interactive latency.
// Measures the two latency profiles that matter for an interactive Wielder gate:
//   (a) COLD: sessions.create -> stream open + first user.message send -> first
//       agent token (first agent.message text delta).
//   (b) WARM: reuse an already-created session, send a new user.message, measure
//       send -> first agent token (no sessions.create on the hot path).
// Prints p50/p95 for each phase over N trials.
//
// ============================================================================
//  WE CANNOT RUN THIS HERE. There is no API key and no CMA beta access in this
//  environment. Run it yourself with your own key + managed-agents beta access.
// ============================================================================
//
// Prerequisites:
//   npm install @anthropic-ai/sdk    (a version with client.beta.{agents,
//                                      environments,sessions} CMA support)
//   export ANTHROPIC_API_KEY=sk-ant-...
//   Your org/key must be enabled for the managed-agents-2026-04-01 beta.
//
// Usage:
//   node cma-latency-bench.mjs [--trials=10] [--model=claude-opus-4-8]
//        [--reuse-agent=agent_xxx] [--reuse-env=env_xxx] [--cold-only] [--warm-only]
//
// Notes:
//   * The SDK sets `managed-agents-2026-04-01` automatically on
//     client.beta.{agents,environments,sessions}.* calls.
//   * "First token" = first agent.message text delta. CMA streams thinking as
//     agent.thinking events; with adaptive thinking the first VISIBLE answer
//     token can lag stream-open while the model thinks. We measure BOTH
//     time-to-first-event (any agent/span/status event) and
//     time-to-first-answer-token. For an interactive gate, first-event is what
//     you surface as 'working...' immediately.
//   * Re-create the agent with a different model/effort to compare configs;
//     effort lives on the model/agent config, low + no-thinking is the floor,
//     and adaptive-thinking configurations must be measured rather than assumed.

import Anthropic from "@anthropic-ai/sdk";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, v] = a.replace(/^--/, "").split("=");
    return [k, v === undefined ? true : v];
  }),
);
const trialsArg = args.trials ?? "10";
const TRIALS = typeof trialsArg === "string" && trialsArg.trim() !== ""
  ? Number(trialsArg)
  : NaN;
const MODEL = args.model ?? "claude-opus-4-8";
const COLD_ONLY = !!args["cold-only"];
const WARM_ONLY = !!args["warm-only"];
const REUSE_AGENT = args["reuse-agent"] ?? process.env.CMA_AGENT_ID ?? null;
const REUSE_ENV = args["reuse-env"] ?? process.env.CMA_ENV_ID ?? null;

if (!Number.isInteger(TRIALS) || TRIALS <= 0) {
  console.error("ERROR: --trials must be a positive integer.");
  process.exit(1);
}
if (COLD_ONLY && WARM_ONLY) {
  console.error("ERROR: --cold-only and --warm-only are mutually exclusive.");
  process.exit(1);
}
if (!process.env.ANTHROPIC_API_KEY) {
  console.error("ERROR: set ANTHROPIC_API_KEY in your environment.");
  process.exit(1);
}
const client = new Anthropic();
const PROMPT = "Reply with exactly the word: ack";

const ms = () => Number(process.hrtime.bigint() / 1000000n);
function pct(arr, p) {
  if (arr.length === 0) return NaN;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}
function report(label, samples) {
  const c = samples.filter((x) => Number.isFinite(x));
  if (c.length === 0) return console.log(`  ${label.padEnd(34)} no data`);
  console.log(
    `  ${label.padEnd(34)} p50=${String(pct(c,50)).padStart(7)}ms  ` +
    `p95=${String(pct(c,95)).padStart(7)}ms  min=${Math.min(...c)}ms  max=${Math.max(...c)}ms  n=${c.length}`,
  );
}

function requireSampleCount(label, samplesByMetric) {
  for (const [metric, samples] of Object.entries(samplesByMetric)) {
    if (samples.length !== TRIALS) {
      throw new Error(`${label} ${metric} has ${samples.length}/${TRIALS} required samples`);
    }
  }
}

function requireFiniteTurnMarks(marks, cold) {
  const required = ["tStreamSetup", "tSendFirstEvent", "tSendFirstAnswerToken", "tSendIdle"];
  if (cold) required.push("tSessionCreated", "tStreamOpen", "tFirstEvent", "tFirstAnswerToken", "tIdle");
  for (const name of required) {
    if (!Number.isFinite(marks[name])) throw new Error(`turn completed without finite ${name}`);
  }
}

async function ensureAgentAndEnv() {
  let agentId = REUSE_AGENT, envId = REUSE_ENV;
  if (!envId) {
    const env = await client.beta.environments.create({
      name: `bench-env-${Date.now()}`,
      config: { type: "cloud", networking: { type: "unrestricted" } },
    });
    envId = env.id; console.log(`created environment ${envId}`);
  }
  if (!agentId) {
    const agent = await client.beta.agents.create({
      name: `bench-agent-${Date.now()}`,
      model: MODEL,
      system: "You are a latency benchmark target. Answer in one short word. Do not use tools.",
      tools: [{ type: "agent_toolset_20260401", default_config: { enabled: true } }],
    });
    agentId = agent.id; console.log(`created agent ${agentId}`);
  }
  return { agentId, envId };
}

async function runTurn({ agentId, envId, existingSessionId }) {
  const marks = {};
  const coldStarted = existingSessionId ? null : ms();
  let sessionId = existingSessionId;
  if (!sessionId) {
    const session = await client.beta.sessions.create({
      agent: { type: "agent", id: agentId }, environment_id: envId,
    });
    sessionId = session.id; marks.tSessionCreated = ms() - coldStarted;
  }
  const streamSetupStarted = ms();
  const stream = await client.beta.sessions.events.stream(sessionId);
  marks.tStreamSetup = ms() - streamSetupStarted;
  if (coldStarted !== null) marks.tStreamOpen = ms() - coldStarted;
  const sendStarted = ms();
  const sendP = client.beta.sessions.events.send(sessionId, {
    events: [{ type: "user.message", content: [{ type: "text", text: PROMPT }] }],
  });
  const eventsP = (async () => {
    let gotFirstEvent = false, gotAnswer = false;
    for await (const event of stream) {
      const eventAt = ms();
      if (!gotFirstEvent && event.type !== "user.message" && event.type !== "user.custom_tool_result") {
        marks.tSendFirstEvent = eventAt - sendStarted;
        if (coldStarted !== null) marks.tFirstEvent = eventAt - coldStarted;
        gotFirstEvent = true;
      }
      if (!gotAnswer && event.type === "agent.message") {
        for (const block of event.content ?? []) {
          if (block.type === "text" && block.text?.length > 0) {
            marks.tSendFirstAnswerToken = eventAt - sendStarted;
            if (coldStarted !== null) marks.tFirstAnswerToken = eventAt - coldStarted;
            gotAnswer = true;
            break;
          }
        }
      }
      if (event.type === "session.status_terminated") break;
      if (event.type === "session.status_idle" && event.stop_reason?.type !== "requires_action") {
        marks.tSendIdle = eventAt - sendStarted;
        if (coldStarted !== null) marks.tIdle = eventAt - coldStarted;
        break;
      }
    }
  })();
  await Promise.all([sendP, eventsP]);
  requireFiniteTurnMarks(marks, coldStarted !== null);
  return { sessionId, marks };
}

async function main() {
  console.log(`CMA latency benchmark — model=${MODEL} trials=${TRIALS}`);
  const { agentId, envId } = await ensureAgentAndEnv();
  const cold = { sessionCreate: [], streamOpen: [], firstEvent: [], firstAnswer: [], total: [] };
  const sessionsForWarm = [];
  if (!WARM_ONLY) {
    console.log(`\n=== COLD (sessions.create on hot path) ===`);
    for (let i = 0; i < TRIALS; i++) {
      const { sessionId, marks } = await runTurn({ agentId, envId });
      cold.sessionCreate.push(marks.tSessionCreated);
      cold.streamOpen.push(marks.tStreamOpen);
      cold.firstEvent.push(marks.tFirstEvent);
      cold.firstAnswer.push(marks.tFirstAnswerToken);
      cold.total.push(marks.tIdle);
      sessionsForWarm.push(sessionId);
      process.stdout.write(`  trial ${i+1}/${TRIALS}: create=${marks.tSessionCreated}ms firstEvent(cumulative)=${marks.tFirstEvent}ms firstAnswer(cumulative)=${marks.tFirstAnswerToken}ms\n`);
    }
    requireSampleCount("COLD", cold);
  }
  const warm = { streamSetup: [], firstEvent: [], firstAnswer: [], total: [] };
  if (!COLD_ONLY) {
    console.log(`\n=== WARM (reuse existing session, no sessions.create) ===`);
    let pool = sessionsForWarm;
    if (pool.length === 0) {
      for (let i = 0; i < Math.min(TRIALS, 3); i++) {
        const s = await client.beta.sessions.create({ agent: { type: "agent", id: agentId }, environment_id: envId });
        pool.push(s.id);
      }
    }
    for (let i = 0; i < TRIALS; i++) {
      const sessionId = pool[i % pool.length];
      const { marks } = await runTurn({ agentId, envId, existingSessionId: sessionId });
      warm.streamSetup.push(marks.tStreamSetup);
      warm.firstEvent.push(marks.tSendFirstEvent);
      warm.firstAnswer.push(marks.tSendFirstAnswerToken);
      warm.total.push(marks.tSendIdle);
      process.stdout.write(`  trial ${i+1}/${TRIALS}: streamSetup(pre-send)=${marks.tStreamSetup}ms firstEvent(from-send)=${marks.tSendFirstEvent}ms firstAnswer(from-send)=${marks.tSendFirstAnswerToken}ms\n`);
    }
    requireSampleCount("WARM", warm);
  }
  console.log(`\n================ SUMMARY (p50 / p95) ================`);
  if (!WARM_ONLY) {
    console.log("COLD path:");
    report("sessions.create", cold.sessionCreate);
    report("-> stream open (cumulative)", cold.streamOpen);
    report("-> first event (cumulative)", cold.firstEvent);
    report("-> first ANSWER token (cumulative)", cold.firstAnswer);
    report("-> idle/end_turn (cumulative)", cold.total);
  }
  if (!COLD_ONLY) {
    console.log("WARM path (reused session):");
    report("stream setup (pre-send)", warm.streamSetup);
    report("send -> first event", warm.firstEvent);
    report("send -> first ANSWER token", warm.firstAnswer);
    report("send -> idle/end_turn", warm.total);
  }
  console.log(`\nInterpretation: use only the observed sample distributions. For an interactive Wielder gate, 'first event' is when the UI can render 'working…', while 'first answer token' is when visible answer content begins. No latency range is assumed; compare measured model/effort configurations directly. Archive/delete the bench agent+env afterward (archiving an agent is PERMANENT); delete sessions with client.beta.sessions.delete(id).`);
}
main().catch((e) => { console.error(e); process.exit(1); });
