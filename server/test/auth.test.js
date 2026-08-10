// Phase 1 tests (RULES #10) — map to plan §7 cases:
//   cookie posture, cross-role 403, forged JWT, session exclusivity, rate limits.
// node --test. No framework beyond node:test / node:assert.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { hashPassword, verifyPassword, signJwt, verifyJwt } from "../src/crypto.js";
import { config, tokenTtlSec } from "../src/config.js";

// --- minimal req/res doubles so we can drive app.handle without a socket ---
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

// Drive one request through the app. Adds the CSRF header by default for writes.
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
  const sc = res.headers["set-cookie"];
  return sc.split(";")[0].split("=").slice(1).join("=");
}

function freshApp() {
  const store = seedStore(createStore());
  return createApp(store, createRateLimiter());
}

// --- crypto units ---
test("password hash round-trips and rejects wrong password", () => {
  const h = hashPassword("s3cret");
  assert.ok(verifyPassword("s3cret", h));
  assert.ok(!verifyPassword("wrong", h));
  assert.ok(!verifyPassword("s3cret", "garbage"));
});

test("JWT verify rejects forged/expired/tampered tokens (plan §7 forged-JWT)", () => {
  const t = signJwt({ sub: 1, role: "admin" }, "secretA", 60);
  assert.equal(verifyJwt(t, "secretA").role, "admin");
  assert.equal(verifyJwt(t, "wrong-secret"), null, "wrong signing secret rejected");
  const tampered = t.slice(0, -2) + (t.endsWith("a") ? "bb" : "aa");
  assert.equal(verifyJwt(tampered, "secretA"), null, "tampered signature rejected");
  const expired = signJwt({ sub: 1, role: "admin" }, "secretA", -1);
  assert.equal(verifyJwt(expired, "secretA"), null, "expired token rejected");
});

// --- cookie posture (plan §7 cookie posture) ---
test("login sets httpOnly + Secure + SameSite=Strict cookie", async () => {
  const app = freshApp();
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  assert.equal(res.statusCode, 200);
  const sc = res.headers["set-cookie"];
  assert.match(sc, /HttpOnly/);
  assert.match(sc, /Secure/);
  assert.match(sc, /SameSite=Strict/);
});

test("state-changing request without CSRF header is rejected (plan §2.1)", async () => {
  const app = freshApp();
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
    noCsrf: true,
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, "csrf");
});

// --- role enforcement (plan §7 cross-role) ---
test("participant token gets 403 on every /api/admin/* route", async () => {
  const app = freshApp();
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  const cookie = cookieFrom(login);
  for (const url of ["/api/admin/results/1", "/api/admin/violations", "/api/admin/anything"]) {
    const res = await call(app, { method: "GET", url, headers: { cookie: `${config.cookie.name}=${cookie}` } });
    assert.equal(res.statusCode, 403, `expected 403 on ${url}`);
  }
});

test("admin token gets 403 on /api/exam/*", async () => {
  const app = freshApp();
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/admin/login",
    body: { username: "admin1", password: "change-me-admin" },
  });
  const cookie = cookieFrom(login);
  const res = await call(app, {
    method: "GET",
    url: "/api/exam/questions",
    headers: { cookie: `${config.cookie.name}=${cookie}` },
  });
  assert.equal(res.statusCode, 403);
});

test("forged admin JWT (wrong secret) is rejected by /api/admin/*", async () => {
  const app = freshApp();
  const forged = signJwt({ sub: 1, role: "admin" }, "not-the-real-secret", 3600);
  const res = await call(app, {
    method: "GET",
    url: "/api/admin/results/1",
    headers: { cookie: `${config.cookie.name}=${forged}` },
  });
  assert.equal(res.statusCode, 403);
});

// --- single active session (plan §7 session exclusivity) ---
test("new login supersedes old session: old cookie -> 401, takeover logged", async () => {
  const app = freshApp();
  const creds = { username: "participant1", password: "change-me-participant" };
  const loginA = await call(app, { method: "POST", url: "/api/auth/participant/login", body: creds });
  const cookieA = cookieFrom(loginA);

  // A works before B logs in — session not superseded (401 is the exclusivity signal;
  // exam-flow status like 409 not-started is irrelevant here).
  const beforeB = await call(app, {
    method: "GET",
    url: "/api/exam/questions",
    headers: { cookie: `${config.cookie.name}=${cookieA}` },
  });
  assert.notEqual(beforeB.statusCode, 401);

  // B logs in on the same account.
  const loginB = await call(app, { method: "POST", url: "/api/auth/participant/login", body: creds });
  const cookieB = cookieFrom(loginB);

  // A's next request is now superseded.
  const afterB = await call(app, {
    method: "GET",
    url: "/api/exam/questions",
    headers: { cookie: `${config.cookie.name}=${cookieA}` },
  });
  assert.equal(afterB.statusCode, 401);

  // B still works (not superseded).
  const bWorks = await call(app, {
    method: "GET",
    url: "/api/exam/questions",
    headers: { cookie: `${config.cookie.name}=${cookieB}` },
  });
  assert.notEqual(bWorks.statusCode, 401);

  // Takeover was logged (plan §2.2).
  const pid = app.store.getParticipantByUsername("participant1").id;
  assert.equal(app.store.getViolations(pid).filter((v) => v.type === "session_takeover").length, 1);
});

test("session bootstrap restores role and logout revokes participant session", async () => {
  const app = freshApp();
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  const cookie = `${config.cookie.name}=${cookieFrom(login)}`;

  const session = await call(app, { method: "GET", url: "/api/auth/session", headers: { cookie } });
  assert.equal(session.statusCode, 200);
  assert.equal(session.body.role, "participant");

  const logout = await call(app, { method: "POST", url: "/api/auth/logout", headers: { cookie } });
  assert.equal(logout.statusCode, 200);

  const revoked = await call(app, { method: "GET", url: "/api/exam/status", headers: { cookie } });
  assert.equal(revoked.statusCode, 401);
});

// Unknown username and wrong password return the SAME generic 401 (no field disclosure);
// the dummy-hash path (crypto.DUMMY_PASSWORD_HASH) also equalizes timing to close the
// username-enumeration oracle. We assert the observable half: identical status + body.
test("unknown user and wrong password are indistinguishable (no enumeration)", async () => {
  const app = freshApp();
  const noUser = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "does-not-exist", password: "whatever" },
    headers: { "x-ip": "7.7.7.1" },
  });
  const wrongPw = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "wrong" },
    headers: { "x-ip": "7.7.7.2" },
  });
  assert.equal(noUser.statusCode, 401);
  assert.equal(wrongPw.statusCode, 401);
  assert.deepEqual(noUser.body, wrongPw.body, "both return the same generic error, no field disclosure");
});

// --- rate limits (plan §7 event-flood / §2.3) ---
test("participant login is rate-limited per IP", async () => {
  const app = freshApp();
  const bad = { username: "participant1", password: "wrong" };
  let last;
  for (let i = 0; i < config.rateLimits.participantLogin + 2; i++) {
    last = await call(app, {
      method: "POST",
      url: "/api/auth/participant/login",
      body: bad,
      headers: { "x-ip": "9.9.9.9" },
    });
  }
  assert.equal(last.statusCode, 429);
});

test("participant write endpoint is rate-limited per participant", async () => {
  const app = freshApp();
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  const cookie = cookieFrom(login);
  let last;
  for (let i = 0; i < config.rateLimits.answer + 2; i++) {
    last = await call(app, {
      method: "PATCH",
      url: "/api/exam/answer",
      headers: { cookie: `${config.cookie.name}=${cookie}` },
      body: { questionId: 1, optionId: "a" },
    });
  }
  assert.equal(last.statusCode, 429);
});

test("account locks out after threshold consecutive failures", async () => {
  const app = freshApp();
  const pid = app.store.getParticipantByUsername("participant1").id;
  // Force the counter to the threshold, then a correct password must still fail.
  for (let i = 0; i < config.loginLockoutThreshold; i++) app.store.bumpParticipantFailure(pid);
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
    headers: { "x-ip": "5.5.5.5" },
  });
  assert.equal(res.statusCode, 401);
});

// Admin lockout is IP-scoped, not account-scoped (audit fix): an attacker flooding bad
// admin passwords locks only their own IP, never the legitimate admin from elsewhere.
test("admin lockout is scoped to the source IP, not the account", async () => {
  const app = freshApp();
  const attackerIp = "6.6.6.6";
  // Drive the attacker IP to the threshold, then a CORRECT password from that IP still fails.
  for (let i = 0; i < config.loginLockoutThreshold; i++) app.store.bumpAdminFailure(attackerIp);
  const locked = await call(app, {
    method: "POST",
    url: "/api/auth/admin/login",
    body: { username: "admin1", password: "change-me-admin" },
    headers: { "x-ip": attackerIp },
  });
  assert.equal(locked.statusCode, 401, "attacker IP is locked out even with the right password");
  // The real admin, from a different IP, logs in fine — not collateral-damaged.
  const admin = await call(app, {
    method: "POST",
    url: "/api/auth/admin/login",
    body: { username: "admin1", password: "change-me-admin" },
    headers: { "x-ip": "10.0.0.1" },
  });
  assert.equal(admin.statusCode, 200, "legitimate admin from another IP is unaffected");
  assert.equal(admin.body.role, "admin");
});
