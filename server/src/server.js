// Phase 1 server — auth & session (plan §2). Stateless app; state in store.
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

// Minimum length for an admin-chosen password (self-service change only; seeded values
// are the operator's business). Short enough not to annoy, long enough to matter.
const MIN_ADMIN_PASSWORD_LEN = 8;

export function createApp(store = createStore(), rl = createRateLimiter(), bank = createQuestionBank()) {
  const exam = createExam(store, bank, config, rl);
  store._lockoutWindowMs = config.loginLockoutWindowSec * 1000;

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
    const name = username.trim();
    if (!name) return sendJson(res, 400, { error: "missing_credentials" });

    const p = await store.getParticipantByUsername(name);
    const pwOk = await verifyPasswordAsync(password, p ? p.password_hash : DUMMY_PASSWORD_HASH);
    const lockedOut = p ? (await store.participantFailures(p.id)) >= config.loginLockoutThreshold : false;
    const ok = p && p.is_active && !lockedOut && pwOk;
    if (!ok) {
      if (p && !pwOk) await store.bumpParticipantFailure(p.id);
      return sendJson(res, 401, { error: "invalid_credentials" });
    }

    await store.resetParticipantFailures(p.id);
    const hadSession = p.active_session_id !== null;
    const sid = await store.issueSession(p.id);
    if (hadSession) {
      const ua = req.headers["user-agent"] || "unknown";
      await store.logViolation(p.id, "session_takeover", `ip=${ip} ua=${ua}`);
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
    const name = username.trim();
    if (!name) return sendJson(res, 400, { error: "missing_credentials" });

    const lockedOut = store.adminFailuresForIp(ip) >= config.loginLockoutThreshold;
    const a = await store.getAdminByUsername(name);
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
    const sid = await store.issueAdminSession(a.id);
    const token = signJwt({ sub: a.id, role: "admin", sid }, config.jwtSecret, tokenTtlSec);
    setSessionCookie(res, token, tokenTtlSec);
    return sendJson(res, 200, { status: "ok", role: "admin" });
  }

  async function session(req, res) {
    const claims = authenticate(req);
    if (!claims) return sendJson(res, 401, { error: "not_authenticated" });
    if (claims.role === "participant" && !(await store.sessionMatches(claims.sub, claims.sid))) {
      return sendJson(res, 401, { error: "session_superseded" });
    }
    if (claims.role === "admin" && !(await store.adminSessionMatches(claims.sub, claims.sid))) {
      return sendJson(res, 401, { error: "session_superseded" });
    }
    if (claims.role !== "participant" && claims.role !== "admin") {
      return sendJson(res, 403, { error: "forbidden" });
    }
    return sendJson(res, 200, { role: claims.role });
  }

  async function logout(req, res) {
    const claims = authenticate(req);
    if (claims?.role === "participant") await store.invalidateSession(claims.sub, claims.sid);
    if (claims?.role === "admin") await store.invalidateAdminSession(claims.sub, claims.sid);
    clearSessionCookie(res);
    return sendJson(res, 200, { status: "ok" });
  }

  async function handle(req, res) {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    const method = req.method;

    if (path === "/health") return sendJson(res, 200, { status: "ok" });

    if (!path.startsWith("/api/") && serveStatic(req, res, path)) return;

    if (!csrfOk(req)) return sendJson(res, 403, { error: "csrf" });

    if (method === "POST" && path === "/api/auth/participant/login")
      return participantLogin(req, res);
    if (method === "POST" && path === "/api/auth/admin/login") return adminLogin(req, res);
    if (method === "GET" && path === "/api/auth/session") return session(req, res);
    if (method === "POST" && path === "/api/auth/logout") return logout(req, res);

    if (path.startsWith("/api/exam/")) {
      const claims = await requireParticipant(req, res, store);
      if (!claims) return;
      if (method !== "GET" && path !== "/api/exam/event") {
        const limit =
          path === "/api/exam/submit" ? config.rateLimits.submit : config.rateLimits.answer;
        if (!rl.check(`w:${claims.sub}:${path}`, limit).allowed)
          return sendJson(res, 429, { error: "rate_limited" });
      }
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

    if (path.startsWith("/api/admin/")) {
      const claims = await requireAdmin(req, res, store);
      if (!claims) return;
      const m = method === "GET" && path.match(/^\/api\/admin\/results\/(\d+)$/);
      if (m) {
        const result = await store.getResult(Number(m[1]));
        if (!result) return sendJson(res, 404, { error: "no_result" });
        return sendJson(res, 200, result);
      }
      if (method === "GET" && path === "/api/admin/leaderboard") {
        const participants = await store.allParticipants();
        const leaderboard = await Promise.all(
          participants.map(async (p) => {
            const result = await store.getResult(p.id);
            const session = await store.getExamSession(p.id);
            const violations = await store.getViolations(p.id);
            const strikes = violations
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
          })
        );
        leaderboard.sort((a, b) => (b.correct ?? -1) - (a.correct ?? -1) || a.participant_id - b.participant_id);
        return sendJson(res, 200, { leaderboard });
      }
      const vAll = method === "GET" && path === "/api/admin/violations";
      const vOne = method === "GET" && path.match(/^\/api\/admin\/violations\/(\d+)$/);
      if (vAll) return sendJson(res, 200, { violations: await store.getAllViolations() });
      if (vOne) return sendJson(res, 200, { violations: await store.getViolations(Number(vOne[1])) });

      if (method === "POST" && path === "/api/admin/participants") {
        const { value, error } = await readJsonBody(req);
        if (error) return sendJson(res, 400, { error });
        const { username, password } = value || {};
        const name = typeof username === "string" ? username.trim() : "";
        if (!name || typeof password !== "string" || !password) {
          return sendJson(res, 400, { error: "missing_credentials" });
        }
        if (await store.getParticipantByUsername(name)) {
          return sendJson(res, 409, { error: "duplicate_username" });
        }
        const id = await store.addParticipant({ username: name, passwordHash: hashPassword(password) });
        return sendJson(res, 201, { status: "created", participant_id: id, username: name });
      }
      const unlock = method === "POST" && path.match(/^\/api\/admin\/participants\/(\d+)\/unlock$/);
      if (unlock) {
        const p = await store.unlockParticipant(Number(unlock[1]));
        if (!p) return sendJson(res, 404, { error: "no_participant" });
        return sendJson(res, 200, { status: "unlocked", participantId: p.id });
      }
      if (method === "POST" && path === "/api/admin/unlock") {
        const { value, error } = await readJsonBody(req);
        if (error) return sendJson(res, 400, { error });
        const { participant_id, participantId } = value || {};
        const id = Number(participant_id ?? participantId);
        if (!Number.isFinite(id) || id <= 0) return sendJson(res, 400, { error: "missing_participant_id" });
        const p = await store.unlockParticipant(id);
        if (!p) return sendJson(res, 404, { error: "no_participant" });
        return sendJson(res, 200, { status: "unlocked", participantId: p.id });
      }

      const del =
        (method === "DELETE" && path.match(/^\/api\/admin\/participants\/(\d+)$/)) ||
        (method === "POST" && path.match(/^\/api\/admin\/participants\/(\d+)\/delete$/));
      if (del) {
        const id = Number(del[1]);
        const p = await store.deleteParticipant(id);
        if (!p) return sendJson(res, 404, { error: "no_participant" });
        return sendJson(res, 200, { status: "deleted", participantId: id, username: p.username });
      }
      if (method === "DELETE" && path === "/api/admin/participants") {
        const { value, error } = await readJsonBody(req);
        if (error) return sendJson(res, 400, { error });
        const { participant_id, participantId } = value || {};
        const id = Number(participant_id ?? participantId);
        if (!Number.isFinite(id) || id <= 0) return sendJson(res, 400, { error: "missing_participant_id" });
        const p = await store.deleteParticipant(id);
        if (!p) return sendJson(res, 404, { error: "no_participant" });
        return sendJson(res, 200, { status: "deleted", participantId: id, username: p.username });
      }

      // Admin self-service credentials (admin portal). Re-authenticates with the current
      // password before applying any change: a stolen session cookie alone must not be
      // enough to lock the real admin out by rotating the username/password.
      if (method === "GET" && path === "/api/admin/credentials") {
        const me = await store.getAdminById(claims.sub);
        if (!me) return sendJson(res, 401, { error: "not_authenticated" });
        return sendJson(res, 200, { username: me.username, min_password_length: MIN_ADMIN_PASSWORD_LEN });
      }
      if (method === "PATCH" && path === "/api/admin/credentials") {
        const ip = clientIp(req);
        // This endpoint verifies a password, so it is a brute-force surface like login.
        if (!rl.check(`acreds:${ip}`, config.rateLimits.adminLogin).allowed) {
          return sendJson(res, 429, { error: "rate_limited" });
        }
        const { value, error } = await readJsonBody(req);
        if (error) return sendJson(res, 400, { error });
        const { currentPassword, username, newPassword } = value || {};
        const me = await store.getAdminById(claims.sub);
        if (!me) return sendJson(res, 401, { error: "not_authenticated" });
        const pwOk =
          typeof currentPassword === "string" &&
          (await verifyPasswordAsync(currentPassword, me.password_hash));
        if (!pwOk) return sendJson(res, 401, { error: "invalid_credentials" });

        const name = typeof username === "string" ? username.trim() : "";
        const wantsName = !!name && name !== me.username;
        const wantsPass = typeof newPassword === "string" && newPassword.length > 0;
        if (!wantsName && !wantsPass) return sendJson(res, 400, { error: "nothing_to_update" });
        if (wantsPass && newPassword.length < MIN_ADMIN_PASSWORD_LEN) {
          return sendJson(res, 400, { error: "weak_password" });
        }
        if (wantsName && (await store.getAdminByUsername(name))) {
          return sendJson(res, 409, { error: "duplicate_username" });
        }
        const patch = {};
        if (wantsName) patch.username = name;
        if (wantsPass) patch.passwordHash = hashPassword(newPassword);
        let updated;
        try {
          updated = await store.updateAdmin(claims.sub, patch);
        } catch (err) {
          // Unique-violation race between the pre-check above and this write.
          if (err?.code === "23505" || err?.message === "duplicate_admin_username") {
            return sendJson(res, 409, { error: "duplicate_username" });
          }
          throw err;
        }
        if (!updated) return sendJson(res, 404, { error: "no_admin" });
        return sendJson(res, 200, { status: "updated", username: updated.username });
      }
      return sendJson(res, 404, { error: "not_found" });
    }

    return sendJson(res, 404, { error: "not_found" });
  }

  return { handle, store, rl, exam };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  // Same store selection as the serverless entry point. This used to be an unconditional
  // createStore(), so `npm start` ignored DATABASE_URL entirely and every write was thrown
  // away when the process exited, no matter how the environment was configured.
  const { createConfiguredStore } = await import("./bootstrap.js");
  const { store, mode } = await createConfiguredStore();
  const app = createApp(store);
  createServer((req, res) => {
    const startedAt = process.hrtime.bigint();
    res.on("finish", () => {
      const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
      console.log(
        `${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${ms.toFixed(1)}ms`,
      );
    });
    app.handle(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) sendJson(res, 500, { error: "internal" });
    });
  }).listen(config.port, () => {
    console.log(
      `prelims auth server on :${config.port} (store=${mode}, secure-cookie=${config.cookie.secure})`,
    );
  });
  const sweepMs = Number.parseInt(process.env.SWEEP_INTERVAL_MS || "20000", 10);
  setInterval(async () => {
    try {
      await app.exam.sweepExpired();
      app.rl.gc();
    } catch (err) {
      console.error("sweep failed", err);
    }
  }, sweepMs).unref();
}
