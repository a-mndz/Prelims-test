// Admin self-service credentials: PATCH /api/admin/credentials (admin portal).
// node --test. Same request/response doubles as the other suites.
import { test } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../src/server.js";
import { createStore } from "../src/store.js";
import { createRateLimiter } from "../src/ratelimit.js";
import { seedStore } from "../src/seed.js";
import { hashPassword } from "../src/crypto.js";
import { config } from "../src/config.js";

function mockReq({ method = "GET", url = "/", headers = {}, body } = {}) {
  const listeners = {};
  let emitted = false;
  let flushed = false;
  // Real http.IncomingMessage buffers the body until a consumer attaches. The router
  // awaits auth (async store) before readJsonBody, so emitting eagerly dropped the body
  // and the request hung forever. Deliver it whenever the listeners actually show up.
  const flush = () => {
    if (!emitted || flushed || !listeners.end) return;
    flushed = true;
    if (body !== undefined) listeners.data?.(Buffer.from(JSON.stringify(body)));
    listeners.end();
  };
  const req = {
    method,
    url,
    headers,
    socket: { remoteAddress: headers["x-ip"] || "127.0.0.1" },
    on(ev, fn) {
      listeners[ev] = fn;
      flush();
      return req;
    },
    destroy() {},
    pause() {},
    _emit() {
      emitted = true;
      flush();
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
async function freshApp() {
  const store = await seedStore(createStore());
  return createApp(store, createRateLimiter());
}
// Each login gets its own source IP: admin login is capped at 3/IP/min and some tests
// below log in more than that while checking old versus new credentials.
let ipSeq = 0;
async function adminLogin(app, username = "admin1", password = "change-me-admin") {
  const res = await call(app, {
    method: "POST",
    url: "/api/auth/admin/login",
    headers: { "x-ip": `10.1.0.${++ipSeq}` },
    body: { username, password },
  });
  const cookie = res.statusCode === 200 ? `${config.cookie.name}=${cookieFrom(res)}` : null;
  return { status: res.statusCode, cookie };
}
function patch(app, cookie, body) {
  return call(app, {
    method: "PATCH",
    url: "/api/admin/credentials",
    headers: { cookie, "x-ip": `10.2.0.${++ipSeq}` },
    body,
  });
}

test("GET credentials reports the caller's own username", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await call(app, { method: "GET", url: "/api/admin/credentials", headers: { cookie } });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.username, "admin1");
  assert.equal(res.body.min_password_length, 8);
});

test("wrong current password is rejected and changes nothing", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await patch(app, cookie, {
    currentPassword: "not-the-password",
    username: "hijacked",
    newPassword: "attacker-chosen-pw",
  });
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, "invalid_credentials");
  // Neither field moved: the original credentials still work, the attacker's do not.
  assert.equal((await adminLogin(app)).status, 200, "original admin login still works");
  assert.equal((await adminLogin(app, "hijacked", "attacker-chosen-pw")).status, 401);
});

test("a short new password is rejected", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await patch(app, cookie, { currentPassword: "change-me-admin", newPassword: "short12" });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, "weak_password");
  assert.equal((await adminLogin(app)).status, 200, "old password untouched");
});

test("taking another admin's username is rejected", async () => {
  const app = await freshApp();
  await app.store.addAdmin({ username: "admin2", passwordHash: hashPassword("second-admin-pw") });
  const { cookie } = await adminLogin(app);
  const res = await patch(app, cookie, { currentPassword: "change-me-admin", username: "admin2" });
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error, "duplicate_username");
  // The other admin's own login is intact.
  assert.equal((await adminLogin(app, "admin2", "second-admin-pw")).status, 200);
});

test("submitting no change is a 400, not a silent no-op", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  // Username prefilled with the current name and no new password = nothing to do.
  const res = await patch(app, cookie, {
    currentPassword: "change-me-admin",
    username: "admin1",
    newPassword: "",
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, "nothing_to_update");
});

test("username and password change together; old credentials stop working", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await patch(app, cookie, {
    currentPassword: "change-me-admin",
    username: "round-admin",
    newPassword: "brand-new-admin-pw",
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.username, "round-admin");

  // The caller's session survives: the token carries the admin id and sid, not the name.
  const still = await call(app, { method: "GET", url: "/api/admin/violations", headers: { cookie } });
  assert.equal(still.statusCode, 200, "session survives a credential change");

  assert.equal((await adminLogin(app, "admin1", "change-me-admin")).status, 401, "old username gone");
  assert.equal((await adminLogin(app, "round-admin", "change-me-admin")).status, 401, "old password gone");
  assert.equal((await adminLogin(app, "round-admin", "brand-new-admin-pw")).status, 200, "new credentials work");
});

test("password-only change keeps the username", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await patch(app, cookie, { currentPassword: "change-me-admin", newPassword: "another-admin-pw" });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.username, "admin1");
  assert.equal((await adminLogin(app, "admin1", "another-admin-pw")).status, 200);
});

test("a participant token cannot reach the admin credentials endpoint", async () => {
  const app = await freshApp();
  const login = await call(app, {
    method: "POST",
    url: "/api/auth/participant/login",
    body: { username: "participant1", password: "change-me-participant" },
  });
  const cookie = `${config.cookie.name}=${cookieFrom(login)}`;
  const res = await patch(app, cookie, {
    currentPassword: "change-me-participant",
    newPassword: "escalate-me-now",
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, "forbidden");
});

test("credential changes are rate limited per source IP", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const statuses = [];
  for (let i = 0; i < config.rateLimits.adminLogin + 1; i++) {
    const res = await call(app, {
      method: "PATCH",
      url: "/api/admin/credentials",
      headers: { cookie, "x-ip": "10.9.9.9" },
      body: { currentPassword: "wrong-again", newPassword: "guess-guess-guess" },
    });
    statuses.push(res.statusCode);
  }
  assert.equal(statuses.at(-1), 429, `last attempt limited, saw ${statuses.join(",")}`);
});

test("CSRF header is required for a credential change", async () => {
  const app = await freshApp();
  const { cookie } = await adminLogin(app);
  const res = await call(app, {
    method: "PATCH",
    url: "/api/admin/credentials",
    headers: { cookie },
    noCsrf: true,
    body: { currentPassword: "change-me-admin", newPassword: "brand-new-admin-pw" },
  });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, "csrf");
});
