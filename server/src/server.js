// Phase 1 server — auth & session (plan §2). Stateless app; state in store.
// Exposes login surfaces + role-guarded stubs for /api/exam/* and /api/admin/*
// so the middleware guarantees are exercised end to end.
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { config, tokenTtlSec } from "./config.js";
import { signJwt, verifyPasswordAsync, hashPassword, DUMMY_PASSWORD_HASH } from "./crypto.js";
import { createStore } from "./store.js";
import { createRateLimiter } from "./ratelimit.js";
import { createQuestionBank } from "./questions.js";
import { createExam, ANTICHEAT_EVENTS } from "./exam.js";
import {
  requireAdmin,
  requireParticipant,
  authenticate,
  csrfOk,
} from "./auth.js";
import {
  sendJson,
  readJsonBody,
  setSessionCookie,
  clearSessionCookie,
  clientIp,
  serveStatic,
} from "./http.js";

export function createApp(store = createStore(), rl = createRateLimiter(), bank = createQuestionBank()) {
  const exam = createExam(store, bank, config, rl);
  // Keep the store's lockout-decay window in step with config (no hardcoded constant in
  // the store). See config.loginLockoutWindowSec / store.bumpParticipantFailure.
  store._lockoutWindowMs = config.loginLockoutWindowSec * 1000;
  // --- login handlers ---
  async function participantLogin(req, res) {
    const ip = clientIp(req);
    if (!rl.check(`plogin:${ip}`, config.rateLimits.participantLogin).allowed) {
      return sendJson(res, 429, { error: "rate_limited" });
    }
    const { value, error } = await readJsonBody(req);
    if (error) return sendJson(res, 400, { error });
    const { username, password } = value || {};
    if (typeof username !== "string" || typeof password !== "string") {
      return sendJson(res, 400, { error: "missing_credentials" });
    }

    const p = store.getParticipantByUsername(username);
    // Constant-time against username enumeration: when the user is missing (or locked out)
    // we still run scrypt against a dummy hash, so a bad-username 401 and a bad-password 401
    // cost the same. The generic 401 message already hides which field was wrong; this hides
    // the timing side channel too. Password check runs unconditionally, result AND-ed after.
    // Async scrypt (threadpool) so a login stampede doesn't serialize on the event loop.
    const pwOk = await verifyPasswordAsync(password, p ? p.password_hash : DUMMY_PASSWORD_HASH);
    const lockedOut = p ? store.participantFailures(p.id) >= config.loginLockoutThreshold : false;
    const ok = p && p.is_active && !lockedOut && pwOk;
    if (!ok) {
      // Count only genuine credential failures. A correct password rejected solely by an
      // active lockout must NOT bump: bumping refreshes failed_login_at, so a victim (or
      // attacker) retrying the right password would push the decay window out forever and
      // turn a temporary lockout into a permanent DoS (DECISIONS.md 2026-07-18).
      if (p && !pwOk) store.bumpParticipantFailure(p.id);
      return sendJson(res, 401, { error: "invalid_credentials" });
    }

    store.resetParticipantFailures(p.id);
    // Single active session: issuing a fresh id invalidates any prior session (plan §2.2).
    const hadSession = p.active_session_id !== null;
    const sid = store.issueSession(p.id);
    if (hadSession) {
      // A re-login while a session existed is a takeover — log it as a signal (plan §2.2).
      // Record IP + UA so an admin reviewing the log can tell a benign self-recovery (same
      // device, e.g. a token that expired mid-exam) from a genuine second-device takeover.
      const ua = req.headers["user-agent"] || "unknown";
      store.logViolation(p.id, "session_takeover", `ip=${ip} ua=${ua}`);
    }
    const token = signJwt(
      { sub: p.id, role: "participant", sid, cid: p.competition_id },
      config.jwtSecret,
      tokenTtlSec,
    );
    setSessionCookie(res, token, tokenTtlSec);
    return sendJson(res, 200, { status: "ok", role: "participant" });
  }

  async function adminLogin(req, res) {
    const ip = clientIp(req);
    if (!rl.check(`alogin:${ip}`, config.rateLimits.adminLogin).allowed) {
      return sendJson(res, 429, { error: "rate_limited" });
    }
    const { value, error } = await readJsonBody(req);
    if (error) return sendJson(res, 400, { error });
    const { username, password } = value || {};
    if (typeof username !== "string" || typeof password !== "string") {
      return sendJson(res, 400, { error: "missing_credentials" });
    }
    // Lockout is scoped to the source IP, not the account: a per-account counter would let
    // anyone knowing the admin username lock the single admin out for the whole round. Per-IP
    // an attacker only locks themselves; the real admin logs in from elsewhere unaffected.
    // FIX L7: the lockout reject still pays the scrypt cost below — an early return would
    // make locked-out 401s measurably faster, telling a prober their IP tripped the lockout.
    const lockedOut = store.adminFailuresForIp(ip) >= config.loginLockoutThreshold;
    const a = store.getAdminByUsername(username);
    // Constant-time against username enumeration (same as participant login): scrypt runs
    // against a dummy hash when the admin username is unknown, so timing can't distinguish.
    const pwOk = await verifyPasswordAsync(password, a ? a.password_hash : DUMMY_PASSWORD_HASH);
    if (lockedOut) {
      return sendJson(res, 401, { error: "invalid_credentials" });
    }
    const ok = a && pwOk;
    if (!ok) {
      store.bumpAdminFailure(ip);
      return sendJson(res, 401, { error: "invalid_credentials" });
    }
    store.resetAdminFailures(ip);
    // Single active admin session (FIX M2): sid mirrors the participant mechanism, so a
    // logout or re-login revokes every previously issued admin token server-side.
    const sid = store.issueAdminSession(a.id);
    const token = signJwt({ sub: a.id, role: "admin", sid }, config.jwtSecret, tokenTtlSec);
    setSessionCookie(res, token, tokenTtlSec);
    return sendJson(res, 200, { status: "ok", role: "admin" });
  }

  function session(req, res) {
    const claims = authenticate(req);
    if (!claims) return sendJson(res, 401, { error: "not_authenticated" });
    if (claims.role === "participant" && !store.sessionMatches(claims.sub, claims.sid)) {
      return sendJson(res, 401, { error: "session_superseded" });
    }
    if (claims.role === "admin" && !store.adminSessionMatches(claims.sub, claims.sid)) {
      return sendJson(res, 401, { error: "session_superseded" });
    }
    if (claims.role !== "participant" && claims.role !== "admin") {
      return sendJson(res, 403, { error: "forbidden" });
    }
    return sendJson(res, 200, { role: claims.role });
  }

  function logout(req, res) {
    const claims = authenticate(req);
    if (claims?.role === "participant") store.invalidateSession(claims.sub, claims.sid);
    if (claims?.role === "admin") store.invalidateAdminSession(claims.sub, claims.sid);
    clearSessionCookie(res);
    return sendJson(res, 200, { status: "ok" });
  }

  // --- router ---
  async function handle(req, res) {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    const method = req.method;

    if (path === "/health") return sendJson(res, 200, { status: "ok" });

    // Static participant shell + deterrent assets (public/). GET-only, non-API paths;
    // the traversal guard lives in serveStatic. Falls through if not a public file.
    if (!path.startsWith("/api/") && serveStatic(req, res, path)) return;

    // CSRF check on every state-changing request (plan §2.1, RULES #5).
    if (!csrfOk(req)) return sendJson(res, 403, { error: "csrf" });

    // Public auth surfaces.
    if (method === "POST" && path === "/api/auth/participant/login")
      return participantLogin(req, res);
    if (method === "POST" && path === "/api/auth/admin/login") return adminLogin(req, res);
    if (method === "GET" && path === "/api/auth/session") return session(req, res);
    if (method === "POST" && path === "/api/auth/logout") return logout(req, res);

    // Guarded exam surface (participant role + active session). Handlers in exam.js.
    if (path.startsWith("/api/exam/")) {
      const claims = requireParticipant(req, res, store);
      if (!claims) return; // guard already responded 401/403
      // Per-participant write rate limits (plan §2.3). GET (questions) is unmetered here.
      // /api/exam/event is EXEMPT from the 429-drop: its flood policy is coalescing, not
      // rejection (plan §2.3 — "counted but coalesced"), so the handler owns its own limit
      // and turns overflow into one counted rate_flood row instead of a dropped request.
      if (method !== "GET" && path !== "/api/exam/event") {
        const limit =
          path === "/api/exam/submit" ? config.rateLimits.submit : config.rateLimits.answer;
        if (!rl.check(`w:${claims.sub}:${path}`, limit).allowed)
          return sendJson(res, 429, { error: "rate_limited" });
      }
      // Phase 2 exam flow (plan §3, §4). Submit + sweep Phase 3, event Phase 4 (§5).
      if (method === "POST" && path === "/api/exam/start") return exam.start(req, res, claims);
      if (method === "GET" && path === "/api/exam/status") return exam.status(req, res, claims);
      if (method === "GET" && path === "/api/exam/questions")
        return exam.questions(req, res, claims);
      if (method === "PATCH" && path === "/api/exam/answer") return exam.answer(req, res, claims);
      if (method === "POST" && path === "/api/exam/event") return exam.event(req, res, claims);
      if (method === "GET" && path === "/api/exam/review") return exam.review(req, res, claims);
      if (method === "POST" && path === "/api/exam/submit") return exam.submit(req, res, claims);
      return sendJson(res, 404, { error: "not_found" });
    }

    // Guarded admin surface (admin role). Results live here so the role middleware —
    // not a bespoke path — is the access boundary (plan §6).
    if (path.startsWith("/api/admin/")) {
      const claims = requireAdmin(req, res, store);
      if (!claims) return;
      const m = method === "GET" && path.match(/^\/api\/admin\/results\/(\d+)$/);
      if (m) {
        const result = store.getResult(Number(m[1]));
        if (!result) return sendJson(res, 404, { error: "no_result" });
        return sendJson(res, 200, result);
      }
      // Leaderboard (plan §6): every participant's score + exam status + malpractice
      // signal in one read, so the admin dashboard doesn't fan out N requests. Scores
      // stay admin-only — this rides the same /api/admin/* role guard as results.
      if (method === "GET" && path === "/api/admin/leaderboard") {
        const leaderboard = store.allParticipants().map((p) => {
          const result = store.getResult(p.id);
          const session = store.getExamSession(p.id);
          // Malpractice = any anticheat-whitelisted violation (tab_blur/copy_paste/
          // fullscreen_exit). session_takeover/rate_flood stay in the violations view —
          // they're operational signals, not exam-conduct ones.
          const strikes = store
            .getViolations(p.id)
            .filter((v) => ANTICHEAT_EVENTS.has(v.type))
            .reduce((n, v) => n + v.count, 0);
          return {
            participant_id: p.id,
            username: p.username,
            status: session ? session.status : "NOT_STARTED",
            correct: result ? result.correct : null,
            total: result ? result.total : null,
            submitted_by: result ? result.submitted_by : null,
            malpractice: strikes > 0,
            strikes,
          };
        });
        // Graded first by score desc, then ungraded; stable on id for ties.
        leaderboard.sort((a, b) => (b.correct ?? -1) - (a.correct ?? -1) || a.participant_id - b.participant_id);
        return sendJson(res, 200, { leaderboard });
      }
      // Violation log for manual review (plan §5): all, or scoped to one participant.
      // Admin-only by virtue of the /api/admin/* prefix the role middleware guards.
      const vAll = method === "GET" && path === "/api/admin/violations";
      const vOne = method === "GET" && path.match(/^\/api\/admin\/violations\/(\d+)$/);
      if (vAll) return sendJson(res, 200, { violations: store.getAllViolations() });
      if (vOne) return sendJson(res, 200, { violations: store.getViolations(Number(vOne[1])) });
      // Operator remedy for a locked-out participant (plan §2.3): clear the lockout counter
      // and reactivate. Without this a participant DoS'd off their account had no recourse
      // mid-round. State-changing → CSRF header already enforced by the router above.
      // Provision a participant mid-round (admin allocates username + password).
      // Sync scrypt is fine here: this is a rare operator action behind the admin
      // guard, not a login-path hot spot. Duplicate check returns 409 instead of
      // letting store.addParticipant throw into the generic 500 handler.
      if (method === "POST" && path === "/api/admin/participants") {
        const { value, error } = await readJsonBody(req);
        if (error) return sendJson(res, 400, { error });
        const { username, password } = value || {};
        const name = typeof username === "string" ? username.trim() : "";
        if (!name || typeof password !== "string" || !password) {
          return sendJson(res, 400, { error: "missing_credentials" });
        }
        if (store.getParticipantByUsername(name)) {
          return sendJson(res, 409, { error: "duplicate_username" });
        }
        const id = store.addParticipant({ username: name, passwordHash: hashPassword(password) });
        return sendJson(res, 201, { status: "created", participant_id: id, username: name });
      }
      const unlock = method === "POST" && path.match(/^\/api\/admin\/participants\/(\d+)\/unlock$/);
      if (unlock) {
        const p = store.unlockParticipant(Number(unlock[1]));
        if (!p) return sendJson(res, 404, { error: "no_participant" });
        return sendJson(res, 200, { status: "unlocked", participantId: p.id });
      }
      return sendJson(res, 404, { error: "not_found" });
    }

    return sendJson(res, 404, { error: "not_found" });
  }

  return { handle, store, rl, exam };
}

// Boot only when run directly, not when imported by tests.
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  // Production must never boot on the volatile in-memory store: it would come up empty
  // (no participants can log in) and lose every answer on restart. Until a Postgres
  // adapter honoring DATABASE_URL exists, a prod boot is always this hollow server —
  // fail loudly at startup instead of during the exam (plan §8: managed Postgres).
  if (config.isProd) {
    throw new Error(
      "refusing to start: NODE_ENV=production with the in-memory store. " +
        "Production requires the Postgres adapter (schema.sql via DATABASE_URL), which is not implemented yet.",
    );
  }
  // Seed dev/demo credentials so `npm start` yields a server you can actually log into
  // (the README quickstart). Prod seeds through a migration + secrets store, never this —
  // so we only auto-seed outside production, and only into the in-memory store.
  let store = createStore();
  if (!config.isProd) {
    const { seedStore } = await import("./seed.js");
    seedStore(store);
    console.log("seeded dev credentials (non-prod): participant + admin from SEED_* env or defaults");
  }
  const app = createApp(store);
  createServer((req, res) => {
    // Request log: method, path, status, duration — printed when the response finishes.
    const startedAt = process.hrtime.bigint();
    res.on("finish", () => {
      const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
      console.log(
        `${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${ms.toFixed(1)}ms`,
      );
    });
    app.handle(req, res).catch((err) => {
      // Never leak internals to the client.
      console.error(err);
      if (!res.headersSent) sendJson(res, 500, { error: "internal" });
    });
  }).listen(config.port, () => {
    console.log(`prelims auth server on :${config.port} (secure-cookie=${config.cookie.secure})`);
  });
  // Expiry sweep worker (plan §4.1) — auto-submits sessions past the deadline even if
  // the client never calls /submit. Same atomic transition as manual submit (§4.3).
  const sweepMs = Number.parseInt(process.env.SWEEP_INTERVAL_MS || "20000", 10);
  setInterval(() => {
    try {
      app.exam.sweepExpired();
      app.rl.gc(); // opportunistic sweep of expired rate-limit keys (ratelimit.js gc)
    } catch (err) {
      console.error("sweep failed", err);
    }
  }, sweepMs).unref(); // ponytail: unref so the sweep never keeps the process alive alone.
}
