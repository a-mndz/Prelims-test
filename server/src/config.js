// Config — all secrets/tunables from env (RULES #7). No hardcoded secrets.
// competition-system-plan-v2.md §2, §2.3, §4.1
//
// NOTE: this module validates the environment in its module body, so importing it can
// throw. Entry points must therefore import it (or anything that imports it) lazily,
// inside a try/catch — see api/index.js. A static import that throws on Vercel is reported
// as FUNCTION_INVOCATION_FAILED, which names neither the missing variable nor the fix.
import { ConfigError } from "./errors.js";

const env = process.env;
const isProd = env.NODE_ENV === "production";

// A deployed environment must never run on placeholder secrets. Vercel sets
// NODE_ENV=production for every deployment, so `isProd` alone already covers it;
// VERCEL_ENV is kept as an explicit second signal for clarity.
const requiresRealSecrets = isProd || env.VERCEL_ENV === "production";

function required(name, fallbackName = null) {
  const v = env[name] || (fallbackName ? env[fallbackName] : undefined);
  if (v) return v;
  if (requiresRealSecrets) {
    // Previously this returned `dev-only-insecure-JWT_SECRET` on Vercel, which meant the
    // live deployment signed session cookies with a constant published in this repo —
    // anyone could mint an admin JWT. Refusing to boot is the only safe answer.
    throw new ConfigError(
      `Missing required env var ${name} (RULES #7). Set it in the Vercel project ` +
        `(Settings -> Environment Variables) or the server .env, then redeploy.`,
      "env_not_configured"
    );
  }
  return `dev-only-insecure-${name}`;
}

// Connection strings, in precedence order. The Vercel Supabase integration injects
// POSTGRES_URL (pooled, pgbouncer) and POSTGRES_URL_NON_POOLING (direct); a
// self-managed Postgres is passed as DATABASE_URL. DDL prefers the direct URL
// because pgbouncer's transaction pooling is a poor fit for schema changes.
export function resolveDbUrls(source = env) {
  const pooled =
    source.DATABASE_URL || source.POSTGRES_URL || source.POSTGRES_URL_NON_POOLING || null;
  const direct = source.POSTGRES_URL_NON_POOLING || null;
  return { pooled, direct: direct && direct !== pooled ? direct : null };
}

function int(name, def) {
  const v = env[name];
  if (v === undefined) return def;
  // Fail loudly on a malformed number rather than returning NaN: a NaN duration makes
  // isExpired always false (exam never times out) and a NaN rate limit 429s everything.
  // A one-char typo in prod env must not silently un-time the exam (plan §4.1).
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) {
    throw new ConfigError(`Env var ${name}=${v} is not a valid integer`, "env_not_configured");
  }
  return n;
}

export const config = {
  isProd,
  port: int("PORT", 3000),

  // Database Connection URL (supports DATABASE_URL or Vercel Supabase POSTGRES_URL)
  dbUrl: resolveDbUrls().pooled,
  // Direct (non-pooled) URL, used only for the one-time schema bootstrap.
  dbUrlDirect: resolveDbUrls().direct,

  // Secrets (RULES #7 — different per environment)
  jwtSecret: required("JWT_SECRET", "SUPABASE_JWT_SECRET"),

  // Cookie posture (plan §2.1) — httpOnly + Secure + SameSite=Strict is mandatory.
  // Secure defaults on; only a non-prod override can turn it off (local http dev).
  cookie: {
    name: "session",
    secure: isProd ? true : env.COOKIE_SECURE !== "false",
    sameSite: "Strict",
    httpOnly: true,
    path: "/",
  },

  // CSRF belt-and-suspenders (plan §2.1): custom header required on state-changing requests.
  csrfHeader: "x-requested-with",

  // Timing (plan §4.1) — mechanism here, numbers are config. Session token expiry is
  // scoped to the exam window so a token can't outlive the exam (plan §2).
  examDurationSec: int("EXAM_DURATION_SEC", 60 * 60),
  graceSec: int("GRACE_SEC", 5),

  // Rate limits (plan §2.3) — fixed 60s windows.
  rateLimits: {
    participantLogin: int("RL_PARTICIPANT_LOGIN", 5), // per IP / min (plan §2.3)
    adminLogin: int("RL_ADMIN_LOGIN", 3), //             stricter than participant
    answer: int("RL_ANSWER", 60), //                     per participant / min
    event: int("RL_EVENT", 30), //                       per participant / min, overflow coalesced
    submit: int("RL_SUBMIT", 5), //                      per participant / min
  },

  // Account lockout after N consecutive failed logins (plan §2.3). The lockout DECAYS:
  // after loginLockoutWindowSec of no new failures the counter is considered stale and a
  // fresh attempt is allowed. Without decay, anyone who knows a participant username can
  // send N bad passwords and permanently lock that account out of the round (no unlock
  // path existed) — a trivial attacker-triggered DoS. Admins can also unlock manually.
  loginLockoutThreshold: int("LOGIN_LOCKOUT", 10),
  loginLockoutWindowSec: int("LOGIN_LOCKOUT_WINDOW_SEC", 15 * 60),

  // Reverse-proxy trust (plan §8: prod terminates TLS in front of the app). When >0, the
  // client IP is read from X-Forwarded-For, counting this many trusted hops from the RIGHT
  // (the proxy appends the real client, so the rightmost entries are the ones we control).
  // 0 = no proxy, trust the socket only. Never trust raw XFF (that spoofs past per-IP limits).
  trustProxyHops: int("TRUST_PROXY_HOPS", 0),

  // Anti-cheat DETECTION policy (plan §5) — DETECTION, not prevention (RULES #8).
  // Tab-blur events are logged unconditionally; a consequence only fires once a
  // participant crosses the threshold, because OS notifications and stray alt-tabs
  // produce false positives (plan §5: "do not auto-submit on the first blur event").
  // Admin-configurable via env; the default consequence is the least destructive one.
  antiCheat: {
    blurThreshold: int("BLUR_THRESHOLD", 1),
    // "flag_for_review" | "warn" | "auto_submit" — flag is a signal for human judgment,
    // never an automatic disqualification (plan §5: consequence is a policy choice).
    consequence: env.BLUR_CONSEQUENCE || "auto_submit",
  },
};

// Token lifetime = exam window + grace + a small login-to-start buffer.
export const tokenTtlSec =
  config.examDurationSec + config.graceSec + int("LOGIN_START_BUFFER_SEC", 30 * 60);
