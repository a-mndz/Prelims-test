// Vercel serverless entry point.
//
// Only ./errors.js is imported statically, and only because it imports nothing itself and
// so cannot fail. Everything else is imported lazily inside getApp(), which runs inside the
// handler's try/catch. That is not a style preference:
//
//   server/src/config.js validates the environment while its module body executes, so a
//   missing JWT_SECRET throws during *import*. Under static imports that throw happens
//   while this module is being evaluated — before the handler below exists — and Vercel can
//   only report it as FUNCTION_INVOCATION_FAILED: an opaque 500 on every route, naming
//   neither the variable nor the fix. Deferring the imports moves the identical failure
//   inside the catch, where it becomes 503 {"error":"env_not_configured","detail":...}.
import { isConfigError } from "../server/src/errors.js";

let appPromise;

async function buildApp() {
  const { createConfiguredStore } = await import("../server/src/bootstrap.js");
  const { createApp } = await import("../server/src/server.js");
  const { createRateLimiter } = await import("../server/src/ratelimit.js");
  const { createQuestionBank } = await import("../server/src/questions.js");

  const { store, mode } = await createConfiguredStore(process.env);
  console.log(`[prelims] store=${mode}`);
  return createApp(store, createRateLimiter(), createQuestionBank());
}

function getApp() {
  if (appPromise) return appPromise;

  appPromise = buildApp().catch((err) => {
    // Do not cache a failed boot: a paused Supabase project or a missing env var would
    // otherwise keep this warm instance broken until the next deploy. Clearing the memo
    // lets the next request retry once the database or the configuration is fixed.
    appPromise = undefined;
    throw err;
  });

  return appPromise;
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

export default async function handler(req, res) {
  // Liveness is answered before the app boots. GO_LIVE.md §2 wires a 30s uptime check to
  // /health and documents it as having no DB dependency; routing it through getApp() would
  // break that on Vercel, because an unreachable database or a missing env var would fail
  // the liveness probe too. Keeping it ahead of the boot distinguishes "the function is
  // down" from "the function is up and cannot reach its store" — the two have different
  // runbook entries (GO_LIVE.md §5.1 vs §5.4).
  if (req.method === "GET" && new URL(req.url, "http://localhost").pathname === "/health") {
    return sendJson(res, 200, { status: "ok" });
  }

  try {
    const appInstance = await getApp();
    await appInstance.handle(req, res);
  } catch (err) {
    // A misconfigured environment is an operator problem with a known fix, so say so out
    // loud instead of returning an opaque 500. The previous behaviour — quietly serving
    // from an in-memory store — made every write look like it succeeded and then lost it.
    const misconfigured = isConfigError(err);
    if (misconfigured) console.error(`[prelims] not configured (${err.code}):`, err.message);
    else console.error("[prelims] unhandled error", err);
    if (!res.headersSent) {
      sendJson(
        res,
        misconfigured ? 503 : 500,
        misconfigured ? { error: err.code, detail: err.message } : { error: "internal" }
      );
    }
  }
}
