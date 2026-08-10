// Load test — plan §7 "Load" + §8 capacity target. Run: `node loadtest.js`
// (or `LOAD_N=900 node loadtest.js`). Deliberately OUTSIDE test/ so `node --test`
// doesn't run 450 sessions on every unit run. Uses only node:assert — no framework.
//
// What this asserts (the §7 claims that are testable in-process against the store):
//   1. Grading is fully INDEPENDENT per participant — participant i's score depends
//      only on participant i's answers, no shared-state bleed across N sessions.
//   2. Submit is race-safe at scale — two concurrent submits per participant resolve
//      to exactly ONE 200 + one graded result + one 409 (RULES #4, plan §4.3).
//
// What it does NOT cover (needs real infra, out of scope here — see GO_LIVE.md):
//   network throughput/latency, Postgres connection-pool contention, TLS/cold-start.
//   Those are the dry-run's job; single-threaded Node's event loop is not where the
//   real 450-concurrent contention lives — that's the DB adapter's (plan §8).
import assert from "node:assert/strict";
import { createStore } from "./src/store.js";
import { createQuestionBank, loadBank } from "./src/questions.js";
import { createExam } from "./src/exam.js";
import { config } from "./src/config.js";

const N = Number.parseInt(process.env.LOAD_N || "450", 10); // 3× the 150 peak (plan §8)

// Minimal res double — submit() only needs writeHead + end (mirrors the test doubles).
function res() {
  return {
    statusCode: null,
    body: null,
    writeHead(s) { this.statusCode = s; return this; },
    end(p) { if (p) this.body = JSON.parse(p); },
  };
}

const raw = loadBank(); // raw bank = knows the answer key, so we can build known scores
const bank = createQuestionBank(raw);
const store = createStore();
const exam = createExam(store, bank, config);

// Seed N participants and answer each with a KNOWN score: participant i answers the
// first (i mod bankSize+1) questions correctly, the rest with a wrong option. If any
// participant's result != its own expected score, grading leaked across sessions.
const expected = new Array(N);
const ids = new Array(N);
for (let i = 0; i < N; i++) {
  const pid = store.addParticipant({ username: `load${i}`, passwordHash: "x" });
  ids[i] = pid;
  store.startExam(pid);
  const k = i % (raw.length + 1); // 0..bankSize correct answers
  expected[i] = k;
  raw.forEach((q, qi) => {
    const wrong = q.options.find((o) => o.id !== q.correct_option_id).id;
    const chosen = qi < k ? q.correct_option_id : wrong;
    store.upsertResponse(pid, q.id, { option_id: chosen, answered: true });
  });
}

// Fire two concurrent submits per participant across all N — the submit-race claim at
// scale. Interleaved on the microtask queue (single-threaded Node's real concurrency).
const t0 = Date.now();
const outcomes = await Promise.all(
  ids.flatMap((pid) => {
    const a = Promise.resolve().then(() => { const r = res(); exam.submit({}, r, { sub: pid }); return r; });
    const b = Promise.resolve().then(() => { const r = res(); exam.submit({}, r, { sub: pid }); return r; });
    return [a, b];
  }),
);
const ms = Date.now() - t0;

// --- assertions (throw => nonzero exit => CI fails) -------------------------
let wins = 0, dupes = 0;
for (const r of outcomes) {
  if (r.statusCode === 200) wins += 1;
  else if (r.statusCode === 409) dupes += 1;
  else assert.fail(`unexpected submit status ${r.statusCode}`);
}
assert.equal(wins, N, "exactly one winning submit per participant (no lost/extra grading run)");
assert.equal(dupes, N, "the duplicate submit loses cleanly with 409 (idempotent, no re-grade)");

for (let i = 0; i < N; i++) {
  const result = store.getResult(ids[i]);
  assert.ok(result, `participant ${ids[i]} has exactly one graded result`);
  assert.equal(result.total, bank.size, "graded against the full bank");
  assert.equal(result.correct, expected[i], `participant ${i} score is its own (grading independence)`);
}

console.log(
  `load OK: ${N} participants, ${outcomes.length} concurrent submits in ${ms}ms — ` +
  `${wins} graded once, ${dupes} idempotent 409s, all scores independent.`,
);
