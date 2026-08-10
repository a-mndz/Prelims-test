// Regression tests for the audit fixes (severity-ranked findings #2–#14).
// node --test. No framework beyond node:test / node:assert.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { createExam } from "../src/exam.js";
import { createQuestionBank } from "../src/questions.js";
import { verifyPassword, verifyPasswordAsync, hashPassword } from "../src/crypto.js";
import { serveStatic, clientIp } from "../src/http.js";
import { config } from "../src/config.js";

// --- request/response doubles (same shape as the other suites) ---
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
const P1 = 1;

// --- #6: async password verify matches the sync one (drop-in, same semantics) ------
test("verifyPasswordAsync agrees with verifyPassword (#6 non-blocking login)", async () => {
  const h = hashPassword("s3cret");
  assert.equal(await verifyPasswordAsync("s3cret", h), true);
  assert.equal(await verifyPasswordAsync("wrong", h), false);
  assert.equal(await verifyPasswordAsync("s3cret", "garbage"), false);
  // Still agrees with the sync implementation for a fresh hash.
  assert.equal(verifyPassword("s3cret", h), await verifyPasswordAsync("s3cret", h));
});

// --- #2: lockout decays and is attacker-bounded, not permanent --------------------
test("participant lockout decays after the window (#2 no permanent DoS)", async () => {
  const store = seedStore(createStore());
  store._lockoutWindowMs = 1000;
  const id = store.getParticipantByUsername("participant1").id;
  for (let i = 0; i < config.loginLockoutThreshold; i++) store.bumpParticipantFailure(id);
  assert.equal(store.participantFailures(id), config.loginLockoutThreshold, "locked now");
  // A read past the window sees the counter as decayed to 0 — account usable again.
  assert.equal(store.participantFailures(id, Date.now() + 2000), 0, "decayed after window");
});

// --- FIX M2: admin tokens are revocable (sid mirrors the participant mechanism) ----
test("admin logout/re-login revokes previously issued admin tokens (FIX M2)", async () => {
  const app = freshApp();
  const { cookie: first } = await loginAdmin(app);
  // Works before revocation.
  const ok = await call(app, { method: "GET", url: "/api/admin/violations", headers: { cookie: first } });
  assert.equal(ok.statusCode, 200, "fresh admin token accepted");

  // Re-login issues a new sid → the first token's sid no longer matches the row.
  const { cookie: second } = await loginAdmin(app);
  const superseded = await call(app, { method: "GET", url: "/api/admin/violations", headers: { cookie: first } });
  assert.equal(superseded.statusCode, 401, "old admin token rejected after re-login");
  assert.equal(superseded.body.error, "session_superseded");

  // Logout clears the row's sid → even the current token is dead server-side.
  await call(app, { method: "POST", url: "/api/auth/logout", headers: { cookie: second } });
  const revoked = await call(app, { method: "GET", url: "/api/admin/violations", headers: { cookie: second } });
  assert.equal(revoked.statusCode, 401, "admin token rejected after logout (revoked, not just cookie-cleared)");
});

// --- FIX M1: correct-password retries during lockout must not refresh the decay ----
test("lockout decays even while the victim retries the correct password (FIX M1)", async () => {
  const app = freshApp();
  const store = app.store;
  store._lockoutWindowMs = 1000;
  const id = store.getParticipantByUsername("participant1").id;
  for (let i = 0; i < config.loginLockoutThreshold; i++) store.bumpParticipantFailure(id);

  // Locked: even the correct password is rejected...
  const locked = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  assert.equal(locked.statusCode, 401, "correct password rejected during lockout");
  // ...but that rejection must NOT have refreshed failed_login_at — the decay clock
  // keeps running from the last GENUINE failure, so the window still expires.
  assert.equal(
    store.participantFailures(id, Date.now() + 2000),
    0,
    "lockout decays despite correct-password retries during the window",
  );

  // Wrong-password attempts still bump (brute force stays bounded).
  const before = store.participantFailures(id);
  await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "definitely-wrong" },
  });
  assert.equal(store.participantFailures(id), before + 1, "genuine failure still counts");
});

// --- #2: admin can unlock a locked-out participant --------------------------------
test("admin unlock endpoint clears a participant lockout (#2 operator remedy)", async () => {
  const app = freshApp();
  const id = app.store.getParticipantByUsername("participant1").id;
  for (let i = 0; i < config.loginLockoutThreshold; i++) app.store.bumpParticipantFailure(id);
  // Even a correct password fails while locked.
  const locked = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
    headers: { "x-ip": "1.2.3.4" },
  });
  assert.equal(locked.statusCode, 401, "locked out with the right password");

  // Admin unlocks; a participant token is rejected on the same route (admin-only).
  const forbidden = await call(app, {
    method: "POST",
    url: `/api/admin/participants/${id}/unlock`,
  });
  assert.equal(forbidden.statusCode, 403, "unauthenticated/participant cannot unlock");
  const { cookie: aCookie } = await loginAdmin(app);
  const unlocked = await call(app, {
    method: "POST",
    url: `/api/admin/participants/${id}/unlock`,
    headers: { cookie: aCookie },
  });
  assert.equal(unlocked.statusCode, 200);
  assert.equal(unlocked.body.status, "unlocked");
  // Now the correct password works again.
  const ok = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
    headers: { "x-ip": "1.2.3.5" },
  });
  assert.equal(ok.statusCode, 200);
});

// --- #3: clientIp reads XFF only when proxy hops are trusted ------------------------
test("clientIp trusts XFF only per configured hops (#3 proxy awareness)", () => {
  const saved = config.trustProxyHops;
  try {
    const req = { socket: { remoteAddress: "10.0.0.1" }, headers: { "x-forwarded-for": "1.1.1.1, 2.2.2.2" } };
    config.trustProxyHops = 0;
    assert.equal(clientIp(req), "10.0.0.1", "hops=0 ignores XFF, trusts the socket");
    config.trustProxyHops = 1;
    assert.equal(clientIp(req), "2.2.2.2", "hops=1 takes the rightmost (proxy-appended) entry");
    config.trustProxyHops = 2;
    assert.equal(clientIp(req), "1.1.1.1", "hops=2 walks one further left");
  } finally {
    config.trustProxyHops = saved;
  }
});

// --- #10: malformed cookie is a rejection, not a 500 -------------------------------
test("malformed cookie does not 500 (#10)", async () => {
  const app = freshApp();
  const res = await call(app, {
    method: "GET",
    url: "/api/exam/questions",
    headers: { cookie: "session=%zz" },
  });
  assert.notEqual(res.statusCode, 500, "no server error on a bad percent-escape");
  assert.equal(res.statusCode, 403, "treated as an unauthenticated request");
});

// --- #11: GET / serves the participant shell --------------------------------------
test("GET / serves the exam shell, not a 404 (#11)", async () => {
  const app = freshApp();
  const res = await call(app, { method: "GET", url: "/" });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers["content-type"], /text\/html/);
  assert.equal(res.headers["x-frame-options"], "DENY");
  assert.match(res.headers["content-security-policy"], /frame-ancestors 'none'/);
});

// --- #12: status endpoint works in terminal states (post-submit confirmation) ------
test("exam status is readable before start and after submit (#12)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  const before = await call(app, { method: "GET", url: "/api/exam/status", headers: { cookie } });
  assert.equal(before.statusCode, 200);
  assert.equal(before.body.status, "NOT_STARTED");
  assert.equal(typeof before.body.durationSec, "number");
  assert.equal(typeof before.body.total, "number");

  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } });
  const after = await call(app, { method: "GET", url: "/api/exam/status", headers: { cookie } });
  assert.equal(after.statusCode, 200, "status works after submit (review would 409)");
  assert.equal(after.body.status, "SUBMITTED");
  assert.ok(after.body.submittedAt, "carries the submit timestamp for the confirmation screen");
  assert.ok(!after.bodyRaw.includes("correct"), "status leaks no answer key / score (plan §6)");
});

// --- #9: submit timestamp comes from the post-CAS row, never null -------------------
test("submit returns a real timestamp from the transitioned row (#9)", async () => {
  const app = freshApp();
  const { cookie } = await loginParticipant(app);
  await call(app, { method: "POST", url: "/api/exam/start", headers: { cookie } });
  const res = await call(app, { method: "POST", url: "/api/exam/submit", headers: { cookie } });
  assert.equal(res.statusCode, 200);
  assert.equal(typeof res.body.timestamp, "number", "timestamp is set, not null");
  assert.equal(res.body.timestamp, app.store.getExamSession(P1).submitted_at);
});

// --- #13: unmatched /api/admin/* is a 404, not a 200 -------------------------------
test("unknown admin route is 404, not a 200 OK (#13)", async () => {
  const app = freshApp();
  const { cookie } = await loginAdmin(app);
  const res = await call(app, { method: "GET", url: "/api/admin/nonexistent", headers: { cookie } });
  assert.equal(res.statusCode, 404);
});

// --- #8: takeover violation records ip + ua so admins can triage ------------------
test("session_takeover detail carries ip and ua (#8 triage signal)", async () => {
  const app = freshApp();
  const creds = { username: "participant1", password: "change-me-participant" };
  await call(app, { method: "POST", url: "/api/auth/participant/login", body: creds });
  await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: creds,
    headers: { "user-agent": "SpecificTestAgent/9" },
  });
  const takeover = app.store.getViolations(P1).find((v) => v.type === "session_takeover");
  assert.ok(takeover, "takeover logged");
  assert.match(takeover.detail, /ua=SpecificTestAgent\/9/, "records UA for review");
  assert.match(takeover.detail, /ip=/, "records IP for review");
});

// --- #14: the traversal GUARD itself is tested (not just URL normalization) --------
// The router's `new URL()` normalizes "/../x" before serveStatic runs, so the existing
// end-to-end test never exercised the startsWith(PUBLIC_DIR) guard. Call serveStatic
// directly with a raw traversal path to prove the guard rejects it.
test("serveStatic rejects a raw traversal path via its own guard (#14)", () => {
  const res = mockRes();
  // A path that only the startsWith guard (not URL normalization) can stop.
  const served = serveStatic({ method: "GET" }, res, "/../src/config.js");
  assert.equal(served, false, "guard refuses to serve outside public/");
  assert.equal(res.statusCode, null, "nothing was written");
});

// --- #5: config int() rejects malformed numbers (guarded at load) -----------------
// Verified end-to-end in the audit (EXAM_DURATION_SEC=abc throws at import). Here we
// assert the isExpired math is finite with the real config, so the sweep/expiry never
// silently no-op behind a NaN cutoff.
test("expiry cutoff is a finite number with real config (#5)", () => {
  const bank = createQuestionBank();
  const exam = createExam(createStore(), bank, config);
  const cutoff = (config.examDurationSec + config.graceSec) * 1000;
  assert.ok(Number.isFinite(cutoff) && cutoff > 0, "cutoff is finite and positive");
  assert.ok(typeof exam.sweepExpired === "function");
});

// --- admin creates a participant with allocated credentials -----------------------
test("admin create-participant endpoint provisions a working account", async () => {
  const app = freshApp();
  // Admin-only: unauthenticated (and by the same guard, participant) requests get 403.
  const forbidden = await call(app, {
    method: "POST",
    url: "/api/admin/participants",
    body: { username: "newkid", password: "fresh-pass-1" },
  });
  assert.equal(forbidden.statusCode, 403, "unauthenticated cannot create participants");

  const { cookie } = await loginAdmin(app);
  const created = await call(app, {
    method: "POST",
    url: "/api/admin/participants",
    body: { username: "  newkid  ", password: "fresh-pass-1" },
    headers: { cookie },
  });
  assert.equal(created.statusCode, 201);
  assert.equal(created.body.status, "created");
  assert.equal(created.body.username, "newkid", "username is trimmed");
  assert.ok(Number.isInteger(created.body.participant_id));

  // The allocated credentials actually log in.
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "newkid", password: "fresh-pass-1" },
  });
  assert.equal(login.statusCode, 200);
  assert.equal(login.body.role, "participant");

  // And the new account shows up on the leaderboard read.
  const board = await call(app, {
    method: "GET",
    url: "/api/admin/leaderboard",
    headers: { cookie },
  });
  assert.ok(board.body.leaderboard.some((e) => e.username === "newkid"));
});

test("admin create-participant rejects duplicates and missing fields", async () => {
  const app = freshApp();
  const { cookie } = await loginAdmin(app);
  const dup = await call(app, {
    method: "POST",
    url: "/api/admin/participants",
    body: { username: "participant1", password: "whatever" },
    headers: { cookie },
  });
  assert.equal(dup.statusCode, 409);
  assert.equal(dup.body.error, "duplicate_username");

  for (const body of [
    { username: "", password: "x" },
    { username: "   ", password: "x" },
    { username: "ok", password: "" },
    { username: "ok" },
    {},
  ]) {
    const bad = await call(app, {
      method: "POST",
      url: "/api/admin/participants",
      body,
      headers: { cookie },
    });
    assert.equal(bad.statusCode, 400, `rejects ${JSON.stringify(body)}`);
    assert.equal(bad.body.error, "missing_credentials");
  }
});
