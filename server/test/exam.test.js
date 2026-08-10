// Phase 2 tests (RULES #10) — map to plan §7 / GUIDE Phase 2:
//   payload inspection (no correct_option_id), shuffle refresh-stability +
//   position-independence, illegal state transitions, seeded review counts.
// node --test. No framework beyond node:test / node:assert.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { createQuestionBank, loadBank } from "../src/questions.js";
import { seededShuffle } from "../src/shuffle.js";
import { config } from "../src/config.js";

// --- request/response doubles (same shape as auth.test.js) ---
function mockReq({ method = "GET", url = "/", headers = {}, body } = {}) {
  const listeners = {};
  const req = {
    method,
    url,
    headers,
    socket: { remoteAddress: headers["x-ip"] || "127.0.0.1" },
    on(ev, fn) {
      listeners[ev] = fn;
      return req;
    },
    destroy() {},
    _emit() {
      if (body !== undefined) listeners.data?.(Buffer.from(JSON.stringify(body)));
      listeners.end?.();
    },
  };
  return req;
}
function mockRes() {
  return {
    statusCode: null,
    headers: {},
    bodyRaw: "",
    headersSent: false,
    setHeader(k, v) {
      this.headers[k.toLowerCase()] = v;
    },
    writeHead(status, hdrs) {
      this.statusCode = status;
      this.headersSent = true;
      if (hdrs) for (const k in hdrs) this.headers[k.toLowerCase()] = hdrs[k];
      return this;
    },
    end(payload) {
      if (payload) this.bodyRaw += payload;
    },
    get body() {
      return this.bodyRaw ? JSON.parse(this.bodyRaw) : null;
    },
  };
}
async function call(app, opts) {
  const headers = { ...(opts.headers || {}) };
  const isWrite = ["POST", "PATCH", "PUT", "DELETE"].includes(opts.method);
  if (isWrite && headers[config.csrfHeader] === undefined && !opts.noCsrf) {
    headers[config.csrfHeader] = "1";
  }
  const req = mockReq({ ...opts, headers });
  const res = mockRes();
  const p = app.handle(req, res);
  req._emit();
  await p;
  return res;
}
function cookieFrom(res) {
  return res.headers["set-cookie"].split(";")[0].split("=").slice(1).join("=");
}
function freshApp() {
  const store = seedStore(createStore());
  return createApp(store, createRateLimiter());
}
async function loginParticipant(app) {
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  const cookie = cookieFrom(res);
  return { cookie: `${config.cookie.name}=${cookie}` };
}

// --- shuffle: determinism, refresh-stability, position-independence (plan §3.1) ---
test("seededShuffle is deterministic for a given seed and varies across seeds", () => {
  const items = [1, 2, 3, 4, 5, 6, 7, 8];
  assert.deepEqual(seededShuffle(items, "seedA"), seededShuffle(items, "seedA"), "same seed => same order");
  assert.notDeepEqual(seededShuffle(items, "seedA"), seededShuffle(items, "seedB"), "diff seed => diff order");
  assert.deepEqual(items, [1, 2, 3, 4, 5, 6, 7, 8], "input not mutated");
});

test("participant view: same seed is refresh-stable, different seeds differ (plan §3.1)", () => {
  const bank = createQuestionBank();
  const a1 = bank.forParticipant("seed-A");
  const a2 = bank.forParticipant("seed-A");
  assert.deepEqual(a1, a2, "refresh (same seed) is byte-identical");
  const b1 = bank.forParticipant("seed-B");
  // Question order OR option order should differ across participants.
  const orderA = a1.map((q) => q.id).join(",");
  const orderB = b1.map((q) => q.id).join(",");
  const optsA = a1.map((q) => q.options.map((o) => o.id).join("")).join("|");
  const optsB = b1.map((q) => q.options.map((o) => o.id).join("")).join("|");
  assert.ok(orderA !== orderB || optsA !== optsB, "different participants see different arrangement");
});

test("grading matches on option_id, unaffected by shuffled position (plan §3.1, RULES #3)", () => {
  const raw = loadBank();
  const bank = createQuestionBank();
  for (const q of raw) {
    // Correct id grades true regardless of where the shuffle placed it.
    assert.ok(bank.isCorrect(q.id, q.correct_option_id), `${q.id} correct id grades true`);
    const wrong = q.options.find((o) => o.id !== q.correct_option_id).id;
    assert.ok(!bank.isCorrect(q.id, wrong), `${q.id} wrong id grades false`);
  }
});

// --- payload inspection: correct_option_id absent from 100% of responses (RULES #2, §6) ---
test("participant question payload never contains correct_option_id (RULES #2)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const res = await call(app, { method: "GET", url: "/api/exam/questions", headers: { cookie } });
  assert.equal(res.statusCode, 200);
  assert.ok(!res.bodyRaw.includes("correct_option_id"), "raw payload must not mention the key");
  for (const q of res.body.questions) {
    assert.ok(!("correct_option_id" in q), `${q.id} object must not carry the answer`);
    assert.equal(q.options.length, 4);
    for (const o of q.options) assert.deepEqual(Object.keys(o).sort(), ["id", "text"]);
  }
});

// --- state machine: illegal transitions rejected (plan §4) ---
test("questions/answer/review before start return 409 exam_not_started (plan §4)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  for (const [method, url, body] of [
    ["GET", "/api/exam/questions"],
    ["PATCH", "/api/exam/answer", { questionId: "c-01", optionId: "a" }],
    ["GET", "/api/exam/review"],
  ]) {
    const res = await call(app, { method, url, headers: { cookie }, body });
    assert.equal(res.statusCode, 409, `${url} before start`);
    assert.equal(res.body.error, "exam_not_started");
  }
});

// The other end of the one-way machine: SUBMITTED → * is illegal (plan §7 "PATCH after
// SUBMITTED, double-submit"). Writes are refused and a repeat submit is idempotent, never
// a second grading run. The before-start case above covers NOT_STARTED; this covers after.
test("PATCH after SUBMITTED and double-submit are rejected (plan §4, §7)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const first = await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } });
  assert.equal(first.statusCode, 200);
  assert.equal(first.body.status, "submitted");

  // Any write after SUBMITTED is refused — the row is terminal (one-way machine).
  for (const [method, url, body] of [
    ["PATCH", "/api/exam/answer", { questionId: "c-01", optionId: "a" }],
    ["POST", "/api/exam/start"],
  ]) {
    const res = await call(app, { method, url, headers: { cookie }, body });
    assert.equal(res.statusCode, 409, `${url} after submit`);
    assert.equal(res.body.error, "exam_not_in_progress");
    assert.equal(res.body.status, "SUBMITTED");
  }

  // Reads that require IN_PROGRESS are refused too (no seed to serve past terminal state).
  for (const url of ["/api/exam/questions", "/api/exam/review"]) {
    const res = await call(app, { method: "GET", url, headers: { cookie } });
    assert.equal(res.statusCode, 409, `${url} after submit`);
    assert.equal(res.body.error, "exam_not_in_progress");
  }

  // Double-submit is idempotent: 409, not a 200 that would re-run grading (plan §4.3).
  const dup = await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } });
  assert.equal(dup.statusCode, 409);
  assert.equal(dup.body.error, "already_submitted");
});

test("start is idempotent: same seed/clock on re-start (plan §3.1 refresh-stability)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  const first = await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const second = await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  assert.equal(first.body.startedAt, second.body.startedAt, "clock unchanged on re-start");
  const q1 = await call(app, { method: "GET", url: "/api/exam/questions", headers: { cookie } });
  const q2 = await call(app, { method: "GET", url: "/api/exam/questions", headers: { cookie } });
  assert.deepEqual(q1.body.questions, q2.body.questions, "order stable across fetches");
});

// --- autosave upsert + validation at the trust boundary (plan §4.2, RULES #1) ---
test("answer rejects unknown question and option not on the question (RULES #1)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const bad = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "nope", optionId: "a" },
  });
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.body.error, "unknown_question");
  const badOpt = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "zzz" },
  });
  assert.equal(badOpt.statusCode, 400);
  assert.equal(badOpt.body.error, "invalid_option");
});

test("autosave upsert collapses re-clicks; review counts are server-computed (plan §4, §4.2)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  // Answer c-01 three times (indecisive), flag py-01 — should be 1 answered + 1 flagged.
  for (const optionId of ["a", "b", "b"]) {
    await call(app, {
      method: "PATCH",
      url: "/api/exam/answer",
      headers: { cookie },
      body: { questionId: "c-01", optionId },
    });
  }
  await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "py-01", flagged: true },
  });
  const rev = await call(app, { method: "GET", url: "/api/exam/review", headers: { cookie } });
  assert.equal(rev.statusCode, 200);
  assert.equal(rev.body.total, createQuestionBank().size);
  assert.equal(rev.body.answered, 1, "three re-clicks collapse to one answered row");
  assert.equal(rev.body.flagged, 1, "py-01 is flag-only");
  assert.equal(rev.body.responses.find((r) => r.questionId === "c-01").optionId, "b");
  // flag-only py-01 is still unanswered: unanswered counts questions with no selected option.
  assert.equal(rev.body.unanswered, rev.body.total - 1);
  assert.ok(!rev.bodyRaw.includes("correct_option_id"), "review must not leak the key (RULES #2)");
});

// --- answered + flagged are orthogonal: flagging must not drop the answer (audit fix) ---
test("answering then flagging a question keeps it answered AND flagged (plan §4)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  // Answer c-01, then flag it to revisit — the two are independent.
  await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "b" },
  });
  const flagRes = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", flagged: true },
  });
  assert.equal(flagRes.body.answered, true, "flagging must not clear the stored answer");
  assert.equal(flagRes.body.flagged, true);
  const rev = await call(app, { method: "GET", url: "/api/exam/review", headers: { cookie } });
  assert.equal(rev.body.answered, 1, "still answered after being flagged");
  assert.equal(rev.body.flagged, 1, "and flagged");
});
