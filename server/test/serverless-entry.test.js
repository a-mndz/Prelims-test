// Regression guard for the deployed crash mode this file is named after.
//
// server/src/config.js validates the environment while its module body runs, so importing it
// throws when a required variable is missing. api/index.js must therefore never reach it
// through a *static* import: on Vercel that throw happens while the entry module is being
// evaluated, before the handler's try/catch exists, and the platform can only report
// FUNCTION_INVOCATION_FAILED — an opaque 500 on every route, /health included, naming
// neither the variable nor the fix.
//
// This file relies on `node --test` giving each test file its own process: config.js is
// evaluated once per process and then cached, so the environment below has to be in place
// before the entry point is imported, and no other suite may have imported it first.
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "production";
process.env.VERCEL = "1";
process.env.VERCEL_ENV = "production";
delete process.env.JWT_SECRET;
delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;
delete process.env.POSTGRES_URL_NON_POOLING;

const ENTRY = new URL("../../api/index.js", import.meta.url);

function fakeReq(method, url) {
  return { method, url, headers: {}, socket: { remoteAddress: "127.0.0.1" }, on() {}, pause() {} };
}

function fakeRes() {
  return {
    headersSent: false,
    statusCode: 0,
    body: "",
    setHeader() {},
    writeHead(status) {
      this.statusCode = status;
      this.headersSent = true;
      return this;
    },
    end(payload) {
      this.body = payload === undefined ? "" : String(payload);
    },
    on() {},
  };
}

// Swallow the entry point's operator-facing console.error so a passing run stays readable.
async function quietly(fn) {
  const original = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = original;
  }
}

test("the entry point imports cleanly in a production env that is missing JWT_SECRET", async () => {
  const mod = await import(ENTRY);
  assert.equal(typeof mod.default, "function", "handler must be exported after a clean import");
});

test("a missing env var answers 503 and names the variable, instead of crashing the function", async () => {
  const { default: handler } = await import(ENTRY);
  const res = fakeRes();
  await quietly(() => handler(fakeReq("GET", "/api/auth/session"), res));

  assert.equal(res.statusCode, 503);
  const body = JSON.parse(res.body);
  assert.equal(body.error, "env_not_configured");
  assert.match(body.detail, /JWT_SECRET/);
});

test("/health stays up while the environment is broken (GO_LIVE.md §2: no DB dependency)", async () => {
  const { default: handler } = await import(ENTRY);
  const res = fakeRes();
  await handler(fakeReq("GET", "/health"), res);

  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { status: "ok" });
});
