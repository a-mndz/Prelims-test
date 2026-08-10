// Phase 3 tests (RULES #10) — map to plan §7 / GUIDE Phase 3:
//   scripted full-bank grading, atomic CAS submit (exactly one grading run under a
//   concurrent race and a submit-vs-sweep race), expiry check on every write, the
//   expiry-boundary PATCH definition (§4.1), sweep auto-submit, and the admin-only
//   results endpoint (participant token can never reach a score, plan §6).
// node --test. No framework beyond node:test / node:assert.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { createQuestionBank, loadBank } from "../src/questions.js";
import { config } from "../src/config.js";

// --- request/response doubles (same shape as exam.test.js / auth.test.js) ---
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
  return { cookie: `${config.cookie.name}=${cookieFrom(res)}` };
}
async function loginAdmin(app) {
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/admin/login",
    body: { username: "admin1", password: "change-me-admin" },
  });
  return { cookie: `${config.cookie.name}=${cookieFrom(res)}` };
}
// Seeded participant is id 1; the exam-session row is a live reference we can backdate
// to simulate elapsed time — the server has no client-supplied clock to feed (RULES #1).
const P1 = 1;
const cutoffMs = (config.examDurationSec + config.graceSec) * 1000;

// --- scripted full-bank grading (plan §7: do not hand-verify) --------------------
test("grade scores every correct option to full and each wrong option to zero (RULES #3)", () => {
  const raw = loadBank();
  const bank = createQuestionBank();
  // All-correct → full marks.
  const allCorrect = raw.map((q) => ({
    question_id: q.id,
    option_id: q.correct_option_id,
    answered: true,
    flagged: false,
  }));
  assert.deepEqual(bank.grade(allCorrect), { correct: raw.length, total: raw.length });
  // Each wrong option for a question → that question scores 0 (position-independent).
  for (const q of raw) {
    for (const wrong of q.options.filter((o) => o.id !== q.correct_option_id)) {
      const responses = [{ question_id: q.id, option_id: wrong.id, answered: true, flagged: false }];
      assert.equal(bank.grade(responses).correct, 0, `${q.id}=${wrong.id} must score 0`);
    }
  }
  // Flag-only (no answer) never counts, even if option_id happens to be the right one.
  const flagOnly = [{ question_id: raw[0].id, option_id: raw[0].correct_option_id, answered: false, flagged: true }];
  assert.equal(bank.grade(flagOnly).correct, 0, "flag without a selected answer is not a submission");
  // But a CORRECT answer that is ALSO flagged for review MUST still count (the audit bug).
  const answeredAndFlagged = [{ question_id: raw[0].id, option_id: raw[0].correct_option_id, answered: true, flagged: true }];
  assert.equal(bank.grade(answeredAndFlagged).correct, 1, "flagging an answered question must not drop the point");
});

// --- atomic CAS submit: exactly one grading run under a concurrent race (plan §4.3) ---
test("N concurrent submits: exactly one 200/grading run, the rest 409 (RULES #4)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "b" }, // the correct option for c-01
  });
  // Fire 5 submits at once (RL_SUBMIT=5, so all clear the rate limit and reach the
  // atomic transition) — they all race the same session row; row-count picks the winner.
  const results = await Promise.all(
    Array.from({ length: config.rateLimits.submit }, () =>
      call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } }),
    ),
  );
  const won = results.filter((r) => r.statusCode === 200);
  const lost = results.filter((r) => r.statusCode === 409);
  assert.equal(won.length, 1, "exactly one submit wins the atomic transition");
  assert.equal(lost.length, config.rateLimits.submit - 1, "every other submit is 409, no re-grade");
  assert.deepEqual(Object.keys(won[0].body).sort(), ["status", "timestamp"], "submit body is status+timestamp only (plan §6)");
  // Grading ran once by side effect: one result row, score reflects the one right answer.
  const result = app.store.getResult(P1);
  assert.equal(result.correct, 1);
  assert.equal(result.total, createQuestionBank().size);
});

// --- expiry check on every write (plan §4.1, RULES #5) ---------------------------
test("writes past duration+grace return 403 exam_expired (plan §4.1)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  // Backdate the session well past the deadline (server clock is the only clock).
  app.store.getExamSession(P1).exam_started_at = Date.now() - (cutoffMs + 60_000);
  const ans = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "a" },
  });
  assert.equal(ans.statusCode, 403);
  assert.equal(ans.body.error, "exam_expired");
  // Read-with-status paths that route through the same choke-point also reject.
  const rev = await call(app, { method: "GET", url: "/api/exam/review", headers: { cookie } });
  assert.equal(rev.statusCode, 403);
});

// --- expiry boundary: arrival time is the sole criterion (plan §4.1) -------------
test("PATCH just inside grace accepted, just outside rejected (plan §4.1 boundary)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const s = app.store.getExamSession(P1);

  // Arrives 1s inside the deadline → accepted.
  s.exam_started_at = Date.now() - (cutoffMs - 1000);
  const inside = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "a" },
  });
  assert.equal(inside.statusCode, 200, "inside grace is accepted");

  // Arrives 1s past the deadline → rejected. (Session still IN_PROGRESS; only time moved.)
  s.exam_started_at = Date.now() - (cutoffMs + 1000);
  const outside = await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "a" },
  });
  assert.equal(outside.statusCode, 403, "past grace is rejected");
  assert.equal(outside.body.error, "exam_expired");
});

// --- sweep auto-submits + grades exactly the autosaved answers (plan §4.1) -------
test("sweep transitions expired IN_PROGRESS to SUBMITTED and grades autosaved answers", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie },
    body: { questionId: "c-01", optionId: "b" }, // correct
  });
  // Not yet expired → sweep is a no-op.
  assert.equal(app.exam.sweepExpired(), 0, "in-window session is not swept");
  // Backdate past the deadline → sweep submits it (client never called /submit).
  app.store.getExamSession(P1).exam_started_at = Date.now() - (cutoffMs + 1000);
  assert.equal(app.exam.sweepExpired(), 1, "expired session is swept once");
  assert.equal(app.store.getExamSession(P1).status, "SUBMITTED");
  const result = app.store.getResult(P1);
  assert.equal(result.correct, 1, "graded the one autosaved correct answer");
  assert.equal(result.submitted_by, "sweep");
  // Sweep is idempotent — a second pass finds nothing IN_PROGRESS.
  assert.equal(app.exam.sweepExpired(), 0, "second sweep is a no-op");
});

// --- sweep-vs-submit race: one submission, one grading run (plan §4.1 + §4.3) ----
test("manual submit racing the sweep yields exactly one SUBMITTED transition", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  app.store.getExamSession(P1).exam_started_at = Date.now() - (cutoffMs + 1000);
  // Fire both against the same expired session. Both route through casSubmit; row-count
  // decides the single winner regardless of ordering.
  const [submitRes] = await Promise.all([
    call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } }),
    Promise.resolve(app.exam.sweepExpired()),
  ]);
  // Whichever won, the session is SUBMITTED exactly once and there is exactly one result.
  assert.equal(app.store.getExamSession(P1).status, "SUBMITTED");
  assert.ok([200, 409].includes(submitRes.statusCode), "submit either wins (200) or loses cleanly (409)");
  assert.ok(app.store.getResult(P1), "exactly one graded result exists");
  // A follow-up submit must be a clean 409 (no second grading run).
  const again = await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } });
  assert.equal(again.statusCode, 409);
});

// --- results are admin-only; a participant token never reaches a score (plan §6) --
test("results endpoint: participant 403, admin gets the score after submit", async () => {
  const app = freshApp();
  const { cookie: pCookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie: pCookie } });
  await call(app, {
    method: "PATCH",
    url: "/api/exam/answer",
    headers: { cookie: pCookie },
    body: { questionId: "c-01", optionId: "b" },
  });
  await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie: pCookie } });

  // Participant token against the admin results path → 403 (role middleware, plan §6).
  const forbidden = await call(app, {
    method: "GET",
    url: `/api/admin/results/${P1}`,
    headers: { cookie: pCookie },
  });
  assert.equal(forbidden.statusCode, 403);

  // Admin token → the score.
  const { cookie: aCookie } = await loginAdmin(app);
  const ok = await call(app, {
    method: "GET",
    url: `/api/admin/results/${P1}`,
    headers: { cookie: aCookie },
  });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.body.correct, 1);
  assert.equal(ok.body.total, createQuestionBank().size);
});
