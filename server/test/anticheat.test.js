// Phase 4 tests (RULES #10) — map to plan §5, §5.1, §2.3 / GUIDE Phase 4:
//   tab-blur event persisted SERVER-SIDE (not just browser console), event flood
//   coalesced (row count stops growing, flood still visible), threshold consequence
//   (never on the first blur), desktop-only block at start (§5.1), and the admin-only
//   violation log (participant token can never reach it, plan §5 review is admin-scoped).
// node --test. No framework beyond node:test / node:assert.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { config } from "../src/config.js";

// --- request/response doubles (same shape as submit.test.js) ---
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
async function loginParticipant(app, headers = {}) {
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
    headers,
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
const P1 = 1;
const cutoffMs = (config.examDurationSec + config.graceSec) * 1000;

// --- tab_blur is persisted SERVER-SIDE, not trusted from the client (plan §5) ------
test("tab_blur event is logged server-side under an in-progress exam", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const res = await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie },
    body: { type: "tab_blur" },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.strikes, 1);
  const blurs = app.store.getViolations(P1).filter((v) => v.type === "tab_blur");
  assert.equal(blurs.length, 1, "persisted one coalesced tab_blur row");
  assert.equal(blurs[0].count, 1);
});

// --- write gauntlet: an event needs an in-progress, non-expired exam (RULES #5) ----
test("event before start is 409; event past expiry is 403", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  // Before start → no session row → 409 (requireInProgress).
  const early = await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie },
    body: { type: "tab_blur" },
  });
  assert.equal(early.statusCode, 409);
  // Start, then backdate past the deadline → 403 exam_expired.
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  app.store.getExamSession(P1).exam_started_at = Date.now() - (cutoffMs + 1000);
  const late = await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie },
    body: { type: "tab_blur" },
  });
  assert.equal(late.statusCode, 403);
  assert.equal(late.body.error, "exam_expired");
});

// --- unknown event types are rejected at the trust boundary (RULES #1) -------------
test("unknown event type is 400, never logged", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const res = await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie },
    body: { type: "keystroke_log" },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(app.store.getViolations(P1).length, 0, "nothing logged for an unknown type");
});

// --- event flood is COALESCED: row count stops growing, flood stays visible (§2.3) --
test("flooding /api/exam/event past the cap coalesces instead of inserting rows", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  // Fire well past the event cap. Under the cap each blur coalesces into ONE tab_blur row;
  // over the cap the overflow coalesces into ONE rate_flood row. Either way the DB row
  // count for this participant is bounded (≤ 2), not one row per hostile request.
  const flood = config.rateLimits.event + 20;
  for (let i = 0; i < flood; i++) {
    await call(app, {
      method: "POST",
      url: "/api/exam/event",
      headers: { cookie },
      body: { type: "tab_blur" },
    });
  }
  const rows = app.store.getViolations(P1);
  assert.ok(rows.length <= 2, `row count bounded despite ${flood} events, got ${rows.length}`);
  const flood_row = rows.find((v) => v.type === "rate_flood");
  assert.ok(flood_row, "the flood itself is recorded as a rate_flood row (still visible)");
  assert.ok(flood_row.count >= 1, "flood overage is counted");
});

// --- threshold consequence: never on the first blur; fires at the threshold (§5) ---
test("consequence does not fire before the threshold and does fire at it", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const thr = config.antiCheat.blurThreshold;
  // The first (threshold-1) blurs report no applied consequence (false positives, §5).
  for (let i = 1; i < thr; i++) {
    const r = await call(app, {
      method: "POST",
      url: "/api/exam/event",
      headers: { cookie },
      body: { type: "tab_blur" },
    });
    assert.equal(r.body.consequence, null, `blur ${i} < threshold: no consequence`);
  }
  // The threshold-th blur applies the configured consequence.
  const at = await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie },
    body: { type: "tab_blur" },
  });
  assert.equal(at.body.strikes, thr);
  assert.equal(at.body.consequence, config.antiCheat.consequence);
});

// --- strikes are SHARED across violation types: blur + paste + fullscreen exit -----
// The policy is "N violations total", not "N of each" — otherwise a participant gets
// (threshold-1) free passes per type. Each type still keeps its own admin-log row.
test("copy_paste and fullscreen_exit count toward the same threshold as tab_blur", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const types = ["tab_blur", "copy_paste", "fullscreen_exit"];
  let last;
  for (let i = 0; i < config.antiCheat.blurThreshold; i++) {
    last = await call(app, {
      method: "POST",
      url: "/api/exam/event",
      headers: { cookie },
      body: { type: types[i % types.length] },
    });
    assert.equal(last.statusCode, 200);
    assert.equal(last.body.strikes, i + 1, "each type increments the shared counter");
  }
  assert.equal(last.body.consequence, config.antiCheat.consequence, "mixed types cross the threshold");
  // Distinct types persist as distinct rows — the admin log can tell a paste from a blur.
  const loggedTypes = new Set(app.store.getViolations(P1).map((v) => v.type));
  for (const t of types.slice(0, config.antiCheat.blurThreshold)) {
    assert.ok(loggedTypes.has(t), `${t} persisted as its own row`);
  }
});

// --- auto_submit consequence routes through the SAME atomic submit (§4.3) ----------
test("auto_submit consequence submits exactly once via casSubmit", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const saved = config.antiCheat.consequence;
  config.antiCheat.consequence = "auto_submit";
  try {
    for (let i = 0; i < config.antiCheat.blurThreshold; i++) {
      await call(app, {
        method: "POST",
        url: "/api/exam/event",
        headers: { cookie },
        body: { type: "tab_blur" },
      });
    }
    assert.equal(app.store.getExamSession(P1).status, "SUBMITTED", "threshold auto-submitted");
    const result = app.store.getResult(P1);
    assert.ok(result, "graded exactly once");
    assert.equal(result.submitted_by, "blur_threshold");
  } finally {
    config.antiCheat.consequence = saved;
  }
});

// --- kick out on abort: the session is revoked at the threshold ---------------------
// "kicked out" = the active session is invalidated server-side, so every request the
// aborted client makes after the threshold event 401s (session_superseded) — not just
// blocked writes on a SUBMITTED exam. A re-login can only land on the locked screen.
test("auto_submit threshold revokes the session: next request is 401", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const saved = config.antiCheat.consequence;
  config.antiCheat.consequence = "auto_submit";
  try {
    for (let i = 0; i < config.antiCheat.blurThreshold; i++) {
      const r = await call(app, {
        method: "POST",
        url: "/api/exam/event",
        headers: { cookie },
        body: { type: "tab_blur" },
      });
      assert.equal(r.statusCode, 200, "the threshold-crossing request itself completes");
    }
    // Session revoked: any subsequent call on the old token is rejected up front.
    const after = await call(app, { method: "GET", url: "/api/exam/status", headers: { cookie } });
    assert.equal(after.statusCode, 401);
    assert.equal(after.body.error, "session_superseded");
  } finally {
    config.antiCheat.consequence = saved;
  }
});

// --- admin leaderboard: score + malpractice flag, admin-only (plan §6) ---------------
test("leaderboard: participant 403; admin sees score and malpractice flag", async () => {
  const app = freshApp();
  const { cookie: pCookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie: pCookie } });
  await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie: pCookie },
    body: { type: "copy_paste" },
  });
  await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie: pCookie } });
  // Participant token → 403 (scores never reach a participant, plan §6).
  const forbidden = await call(app, {
    method: "GET",
    url: "/api/admin/leaderboard",
    headers: { cookie: pCookie },
  });
  assert.equal(forbidden.statusCode, 403);
  const { cookie: aCookie } = await loginAdmin(app);
  const res = await call(app, {
    method: "GET",
    url: "/api/admin/leaderboard",
    headers: { cookie: aCookie },
  });
  assert.equal(res.statusCode, 200);
  const entry = res.body.leaderboard.find((e) => e.participant_id === P1);
  assert.ok(entry, "seeded participant appears");
  assert.equal(entry.username, "participant1");
  assert.equal(entry.status, "SUBMITTED");
  assert.equal(typeof entry.correct, "number", "graded score present");
  assert.equal(typeof entry.total, "number");
  assert.equal(entry.malpractice, true, "anticheat violation flags malpractice");
  assert.ok(entry.strikes >= 1);
});

test("leaderboard: clean not-started participant shows no score, no malpractice", async () => {
  const app = freshApp();
  const { cookie: aCookie } = await loginAdmin(app);
  const res = await call(app, {
    method: "GET",
    url: "/api/admin/leaderboard",
    headers: { cookie: aCookie },
  });
  assert.equal(res.statusCode, 200);
  const entry = res.body.leaderboard.find((e) => e.participant_id === P1);
  assert.equal(entry.status, "NOT_STARTED");
  assert.equal(entry.correct, null);
  assert.equal(entry.malpractice, false);
  assert.equal(entry.strikes, 0);
});

// --- desktop-only: mobile UA is blocked at the START transition only (plan §5.1) ---
test("mobile UA is blocked at exam start with a clear message", async () => {
  const app = freshApp();
  const mobileUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148";
  const { cookie } = await loginParticipant(app);
  const res = await call(app, {
    method: "POST",
    url: "/api/exam/start",
    headers: { cookie, "user-agent": mobileUA },
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, "mobile_not_allowed");
  assert.ok(!app.store.getExamSession(P1), "no exam session created for a blocked mobile start");
});

test("desktop UA starts normally", async () => {
  const app = freshApp();
  const desktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120";
  const { cookie } = await loginParticipant(app);
  const res = await call(app, {
    method: "POST",
    url: "/api/exam/start",
    headers: { cookie, "user-agent": desktopUA },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(app.store.getExamSession(P1).status, "IN_PROGRESS");
});

// --- admin violation log is admin-only (plan §5 review scope) ----------------------
test("violations endpoint: participant 403, admin sees the log", async () => {
  const app = freshApp();
  const { cookie: pCookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie: pCookie } });
  await call(app, {
    method: "POST",
    url: "/api/exam/event",
    headers: { cookie: pCookie },
    body: { type: "tab_blur" },
  });
  // Participant token → 403 (role middleware, the access boundary is the /admin/* prefix).
  const forbidden = await call(app, {
    method: "GET",
    url: "/api/admin/violations",
    headers: { cookie: pCookie },
  });
  assert.equal(forbidden.statusCode, 403);
  // Admin token → the log, including the per-participant scoped view.
  const { cookie: aCookie } = await loginAdmin(app);
  const all = await call(app, { method: "GET", url: "/api/admin/violations", headers: { cookie: aCookie } });
  assert.equal(all.statusCode, 200);
  assert.ok(all.body.violations.some((v) => v.type === "tab_blur" && v.participant_id === P1));
  const scoped = await call(app, {
    method: "GET",
    url: `/api/admin/violations/${P1}`,
    headers: { cookie: aCookie },
  });
  assert.equal(scoped.statusCode, 200);
  assert.ok(scoped.body.violations.every((v) => v.participant_id === P1));
});

// --- static deterrent assets are served (public/), traversal is refused ------------
test("deterrent assets serve; path traversal is refused", async () => {
  const app = freshApp();
  const js = await call(app, { method: "GET", url: "/anticheat.js" });
  assert.equal(js.statusCode, 200);
  assert.match(js.headers["content-type"], /javascript/);
  // A traversal attempt must not escape public/ (404, not the file).
  const escape = await call(app, { method: "GET", url: "/../src/config.js" });
  assert.equal(escape.statusCode, 404);
});
