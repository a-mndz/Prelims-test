import { createApp } from "../server/src/server.js";
import { createStore } from "../server/src/store.js";
import { createPgStore } from "../server/src/pgStore.js";
import { createRateLimiter } from "../server/src/ratelimit.js";
import { createQuestionBank } from "../server/src/questions.js";
import { seedStore } from "../server/src/seed.js";
import { config } from "../server/src/config.js";

let appPromise;

async function getApp() {
  if (appPromise) return appPromise;

  appPromise = (async () => {
    let store;
    if (config.dbUrl) {
      console.log("[prelims] initializing persistent Postgres store via dbUrl");
      store = createPgStore(config.dbUrl);
    } else {
      console.log("[prelims] fallback to in-memory store");
      store = createStore();
    }

    try {
      await seedStore(store);
    } catch (e) {
      console.warn("[prelims] seed warning:", e.message);
    }

    const rl = createRateLimiter();
    const bank = createQuestionBank();
    const application = createApp(store, rl, bank);
    return application;
  })();

  return appPromise;
}

export default async function handler(req, res) {
  try {
    const appInstance = await getApp();
    await appInstance.handle(req, res);
  } catch (err) {
    console.error("[prelims] unhandled error", err);
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal" }));
    }
  }
}
