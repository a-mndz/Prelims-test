import { hashPassword } from "./crypto.js";
import { createStore } from "./store.js";
import { ConfigError } from "./errors.js";

// Seeding runs on every cold start (it is idempotent against Postgres via ON CONFLICT DO
// NOTHING), which means the defaults below are not a dev convenience in a deployed
// environment — they are live credentials. `admin1` / `change-me-admin` published in this
// repo was enough to log into the deployed admin portal, so a deployed environment must
// supply its own values or refuse to boot (RULES #7).
function requiredSeed(env, name, fallback, requiresRealSeeds) {
  const v = env[name];
  if (v) return v;
  if (requiresRealSeeds) {
    throw new ConfigError(
      `Missing required env var ${name}. A deployed environment must not fall back to the ` +
        `well-known default seed credentials; set SEED_ADMIN_USER and SEED_ADMIN_PASS in the ` +
        `Vercel project (Settings -> Environment Variables) or the server .env, then redeploy.`,
      "env_not_configured"
    );
  }
  return fallback;
}

export async function seedStore(store = createStore(), env = process.env) {
  const requiresRealSeeds = env.NODE_ENV === "production" || !!env.VERCEL;

  // The demo participant exists so `npm start` and the test suite have somebody to log in
  // as. In a deployed environment participants come from the admin portal, so it is only
  // seeded when explicitly asked for.
  if (env.SEED_PARTICIPANT_USER || !requiresRealSeeds) {
    await store.addParticipant({
      username: env.SEED_PARTICIPANT_USER || "participant1",
      passwordHash: hashPassword(env.SEED_PARTICIPANT_PASS || "change-me-participant"),
      competitionId: "prelim",
    });
  }

  // The admin account cannot be skipped: without it nobody can reach the portal to create
  // participants in the first place.
  await store.addAdmin({
    username: requiredSeed(env, "SEED_ADMIN_USER", "admin1", requiresRealSeeds),
    passwordHash: hashPassword(
      requiredSeed(env, "SEED_ADMIN_PASS", "change-me-admin", requiresRealSeeds)
    ),
  });

  return store;
}
