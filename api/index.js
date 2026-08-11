// Vercel serverless entry point — wraps the raw node:http createApp as a Vercel handler.
// State lives in module-level singletons, so it persists across warm invocations on the
// same function instance. Cold starts (after idle) reseed the store — acceptable for the
// demo/dry-run use case this entry point is designed for. For a real competition with
// persistent state, wire the Postgres adapter in store.js and deploy on Railway/Render.

import { createApp } from "../server/src/server.js";
import { createStore } from "../server/src/store.js";
import { createRateLimiter } from "../server/src/ratelimit.js";
import { createQuestionBank } from "../server/src/questions.js";
import { seedStore } from "../server/src/seed.js";

// Singleton — initialized once per function instance (warm start reuse).
let app;

function getApp() {
  if (app) return app;
  const store = createStore();
  // Seed from SEED_* env vars (set in Vercel dashboard → Environment Variables).
  // Defaults: participant1 / change-me-participant, admin1 / change-me-admin.
  // Change these before sharing the URL with participants.
  seedStore(store);
  const rl = createRateLimiter();
  const bank = createQuestionBank();
  app = createApp(store, rl, bank);
  console.log("[prelims] app initialized on cold start — store seeded");
  return app;
}

// Vercel calls this with Node-compatible IncomingMessage / ServerResponse.
export default async function handler(req, res) {
  try {
    await getApp().handle(req, res);
  } catch (err) {
    console.error("[prelims] unhandled error", err);
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal" }));
    }
  }
}
