// Store selection, shared by every entry point (the Vercel function in api/index.js and
// `npm start` in server.js). It lives here rather than inline in the handlers so the one
// decision that determines whether data survives a request — Postgres or a per-process
// Map — is testable without a database or an HTTP server.
import { resolveDbUrls } from "./config.js";
import { createStore } from "./store.js";
import { createPgStore } from "./pgStore.js";
import { seedStore } from "./seed.js";
import { ConfigError } from "./errors.js";

// Distinguishable from a runtime failure so the caller can answer 503 + a fix-it message
// instead of a bare 500. Shares ConfigError's `code` contract with the missing-env-var
// errors from config.js and seed.js, so one check at the entry point covers all of them.
export class StoreConfigError extends ConfigError {
  constructor(message) {
    super(message, "store_not_configured");
    this.name = "StoreConfigError";
  }
}

// A deployed environment must have a durable store. The in-memory mirror is a dev/test
// convenience: it lives in one process's heap, so on Vercel each concurrent or recycled
// lambda instance starts with nothing but the seed rows. Falling back to it silently is
// what turns "POSTGRES_URL is not set" into "the admin portal says Created and the
// participant is gone on the next request" — a config mistake that looks like data loss.
export function resolveStoreMode(env = process.env) {
  const { pooled, direct } = resolveDbUrls(env);
  if (pooled) return { mode: "postgres", url: pooled, directUrl: direct };

  const requiresDurable = env.NODE_ENV === "production" || !!env.VERCEL;
  if (requiresDurable) {
    throw new StoreConfigError(
      "No Postgres connection string is configured: set DATABASE_URL, or connect the " +
        "Supabase store to this Vercel project so POSTGRES_URL is injected, then redeploy. " +
        "Refusing to serve from the in-memory store, whose contents are discarded on every " +
        "cold start — participants created in the admin portal would silently disappear."
    );
  }
  return { mode: "memory" };
}

export async function createConfiguredStore(env = process.env) {
  const resolved = resolveStoreMode(env);

  if (resolved.mode === "memory") {
    return { mode: "memory", store: await seedStore(createStore()) };
  }

  const store = createPgStore(resolved.url, { directConnectionString: resolved.directUrl });
  // Schema first: seeding is itself an INSERT and fails on a database with no tables.
  await store.init();
  // Seeding is idempotent against Postgres (ON CONFLICT DO NOTHING), so it is safe on
  // every cold start. Errors are NOT swallowed: the only reason this throws is that the
  // database is unreachable or the schema is wrong, and both must surface immediately
  // rather than leave the app running against a store it cannot write to.
  await seedStore(store);
  return { mode: "postgres", store };
}
