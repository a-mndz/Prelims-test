// In-memory store for dev/test — mirrors schema.sql. Prod swaps this for a Postgres
// adapter with the same method surface (plan §8: stateless app, DB holds all state).
// ponytail: single-process Map store; the atomic-CAS methods below define the contract
// a Postgres adapter must honor (WHERE active_session_id = ? row-count verdict).
import { newSessionId } from "./crypto.js";
import { randomBytes } from "node:crypto";

export function createStore() {
  const participants = new Map(); // id -> row
  const byUsername = new Map(); //   username -> id
  const admins = new Map(); //       username -> row
  const adminsById = new Map(); //   id -> same row (session checks key by token sub)
  const violations = []; //          append-only log
  const examSessions = new Map(); // participant_id -> exam session row (plan §4)
  const responses = new Map(); //    `${participant_id}:${question_id}` -> response row
  const results = new Map(); //      participant_id -> graded result (plan §6, admin-only)
  const adminFailures = new Map(); // source ip -> consecutive admin login failures (lockout)
  let pid = 0;
  let aid = 0;

  return {
    // --- seeding (used by seed script + tests) ---
    addParticipant({ username, passwordHash, competitionId = "prelim" }) {
      if (byUsername.has(username)) throw new Error(`dup participant ${username}`);
      const id = ++pid;
      participants.set(id, {
        id,
        username,
        password_hash: passwordHash,
        competition_id: competitionId,
        is_active: true,
        active_session_id: null,
        failed_logins: 0,
        failed_login_at: 0, // epoch ms of last failure — drives lockout decay
      });
      byUsername.set(username, id);
      return id;
    },
    addAdmin({ username, passwordHash, role = "admin" }) {
      if (admins.has(username)) throw new Error(`dup admin ${username}`);
      const id = ++aid;
      const row = { id, username, password_hash: passwordHash, role, active_session_id: null };
      admins.set(username, row);
      adminsById.set(id, row);
      return id;
    },

    // --- lookups ---
    getParticipantByUsername(username) {
      const id = byUsername.get(username);
      return id ? participants.get(id) : null;
    },
    getParticipantById(id) {
      return participants.get(id) || null;
    },
    // Leaderboard read (plan §6 admin surface): every participant row, seed order.
    allParticipants() {
      return [...participants.values()];
    },
    // Admin unlock (plan §2.3 review action): clear a participant's lockout so an
    // operator has a remedy for a locked-out participant mid-round. Returns the
    // participant or null. NOTE (FIX L8): this deliberately does NOT touch is_active —
    // nothing in the app ever sets it false yet (there is no deactivate endpoint), so a
    // reactivation branch here was dead code implying a flow that doesn't exist. If a
    // deactivation path is added later, decide then whether unlock should also reactivate.
    unlockParticipant(id) {
      const p = participants.get(id);
      if (!p) return null;
      p.failed_logins = 0;
      p.failed_login_at = 0;
      return p;
    },
    getAdminByUsername(username) {
      return admins.get(username) || null;
    },

    // --- login failure accounting (plan §2.3 lockout) ---
    // The lockout counter DECAYS: if the last failure is older than windowMs the account is
    // treated as unlocked (count read as 0) without needing a successful login. This closes
    // the attacker-triggered permanent-DoS hole — sending N bad passwords for a known
    // username used to lock that participant out of the whole round with no unlock path.
    bumpParticipantFailure(id, nowMs = Date.now()) {
      const p = participants.get(id);
      if (!p) return;
      // A failure after the window elapsed starts a fresh count, not a continuation.
      if (p.failed_login_at && nowMs - p.failed_login_at > this._lockoutWindowMs)
        p.failed_logins = 0;
      p.failed_logins += 1;
      p.failed_login_at = nowMs;
    },
    // Effective (decayed) failure count for the lockout check.
    participantFailures(id, nowMs = Date.now()) {
      const p = participants.get(id);
      if (!p) return 0;
      if (p.failed_login_at && nowMs - p.failed_login_at > this._lockoutWindowMs) return 0;
      return p.failed_logins;
    },
    resetParticipantFailures(id) {
      const p = participants.get(id);
      if (p) {
        p.failed_logins = 0;
        p.failed_login_at = 0;
      }
    },
    // Set by createApp from config so the store's decay window matches config without a
    // hardcoded constant here. Default keeps standalone store use sane.
    _lockoutWindowMs: 15 * 60 * 1000,

    // Admin lockout is scoped to the SOURCE IP, not the account (audit fix): a global
    // per-account counter lets anyone who knows the admin username lock the single admin
    // out for the whole round by sending N bad passwords. Per-IP means an attacker only
    // locks their own IP; the legitimate admin logging in from elsewhere is unaffected.
    // The per-IP/min rate limit (config.rateLimits.adminLogin) still bounds brute force.
    bumpAdminFailure(ip, nowMs = Date.now()) {
      const e = adminFailures.get(ip);
      if (e && nowMs - e.at > this._lockoutWindowMs) {
        adminFailures.set(ip, { count: 1, at: nowMs });
      } else {
        adminFailures.set(ip, { count: (e ? e.count : 0) + 1, at: nowMs });
      }
    },
    adminFailuresForIp(ip, nowMs = Date.now()) {
      const e = adminFailures.get(ip);
      if (!e) return 0;
      if (nowMs - e.at > this._lockoutWindowMs) return 0; // decayed
      return e.count;
    },
    resetAdminFailures(ip) {
      adminFailures.delete(ip);
    },

    // --- single active session (plan §2.2) ---
    // Issue a fresh session id on the row. A new login overwrites the old one, so the
    // previous session's next request fails the check below (invalidate-old-on-login).
    issueSession(participantId) {
      const p = participants.get(participantId);
      if (!p) throw new Error("no such participant");
      const sid = newSessionId();
      p.active_session_id = sid;
      return sid;
    },
    // The exclusivity check every participant request runs: the token's sid must equal
    // the row's active_session_id. Mismatch => the session was taken over => reject.
    sessionMatches(participantId, sid) {
      const p = participants.get(participantId);
      return !!p && p.active_session_id === sid;
    },
    invalidateSession(participantId, sid) {
      const p = participants.get(participantId);
      if (!p || p.active_session_id !== sid) return false;
      p.active_session_id = null;
      return true;
    },
    // Admin sessions mirror the participant mechanism (FIX M2): admin JWTs used to be
    // irrevocable — logout cleared only the cookie, and a stolen token stayed valid for
    // its full TTL. Now every admin token carries a sid that must match the row, so a
    // re-login or logout revokes all previously issued admin tokens server-side.
    issueAdminSession(adminId) {
      const a = adminsById.get(adminId);
      if (!a) throw new Error("no such admin");
      const sid = newSessionId();
      a.active_session_id = sid;
      return sid;
    },
    adminSessionMatches(adminId, sid) {
      const a = adminsById.get(adminId);
      return !!a && !!sid && a.active_session_id === sid;
    },
    invalidateAdminSession(adminId, sid) {
      const a = adminsById.get(adminId);
      if (!a || a.active_session_id !== sid) return false;
      a.active_session_id = null;
      return true;
    },

    // --- violation log (plan §2.2 takeover, §5 tab_blur, §2.3 rate_flood) ---
    logViolation(participantId, type, detail = null) {
      violations.push({
        id: violations.length + 1,
        participant_id: participantId,
        type,
        detail,
        count: 1,
        created_at: new Date().toISOString(),
      });
    },
    // Coalesced flood counter (plan §2.3): past the event rate limit we do NOT insert a
    // row per hostile request — that lets a client bloat the log/DB. Instead one row per
    // (participant, type) carries a count, so the flood stays visible as evidence without
    // amplifying it. Returns the running count.
    coalesceViolation(participantId, type, detail = null) {
      const existing = violations.find(
        (v) => v.participant_id === participantId && v.type === type,
      );
      if (existing) {
        existing.count += 1;
        if (detail !== null) existing.detail = detail;
        return existing.count;
      }
      violations.push({
        id: violations.length + 1,
        participant_id: participantId,
        type,
        detail,
        count: 1,
        created_at: new Date().toISOString(),
      });
      return 1;
    },
    getViolations(participantId) {
      return violations.filter((v) => v.participant_id === participantId);
    },
    // Admin review feed (plan §5): every participant's violations, newest id first.
    getAllViolations() {
      return violations.slice().reverse();
    },

    // --- exam sessions (plan §4) --------------------------------------------
    // NOT_STARTED is implicit (no row). Start creates the row with a server seed +
    // server clock; the seed drives per-participant order and never changes after
    // (plan §3.1 refresh-stability). Idempotent: a second start returns the same row.
    getExamSession(participantId) {
      return examSessions.get(participantId) || null;
    },
    startExam(participantId, nowMs = Date.now()) {
      const existing = examSessions.get(participantId);
      if (existing) return existing; // already started — return the stable seed/clock
      const row = {
        participant_id: participantId,
        status: "IN_PROGRESS",
        exam_started_at: nowMs,
        shuffle_seed: randomBytes(16).toString("hex"),
        submitted_at: null,
      };
      examSessions.set(participantId, row);
      return row;
    },

    // --- responses: debounced autosave upsert (plan §4.2) -------------------
    // Idempotent by (participant, question); rapid re-clicks collapse to one row.
    // MERGES rather than overwrites: `answered` and `flagged` are orthogonal (plan §4),
    // so toggling a flag must never drop a stored answer and vice versa. Mirrors the
    // Postgres upsert: INSERT ... ON CONFLICT (participant_id, question_id) DO UPDATE SET
    // option_id/answered/flagged only for the fields this call carries (patch is undefined
    // => keep existing). Grading reads `answered`, independent of `flagged`.
    upsertResponse(participantId, questionId, patch = {}) {
      const key = `${participantId}:${questionId}`;
      const prev = responses.get(key) || {
        participant_id: participantId,
        question_id: questionId,
        option_id: "",
        answered: false,
        flagged: false,
      };
      const row = {
        ...prev,
        ...(patch.option_id !== undefined ? { option_id: patch.option_id } : {}),
        ...(patch.answered !== undefined ? { answered: patch.answered } : {}),
        ...(patch.flagged !== undefined ? { flagged: patch.flagged } : {}),
      };
      responses.set(key, row);
      return row;
    },
    getResponses(participantId) {
      const out = [];
      for (const r of responses.values()) if (r.participant_id === participantId) out.push(r);
      return out;
    },

    // --- atomic submit / expiry sweep (plan §4.3, §4.1, RULES #4) ------------
    // The structural single-submit guarantee. Mirrors the SQL:
    //   UPDATE exam_sessions SET status='SUBMITTED', submitted_at=now()
    //   WHERE participant_id=? AND status='IN_PROGRESS'
    // Returns { rows, session }: rows is the affected-row count (1 = this caller won → grade;
    // 0 = someone already submitted → 409, no re-grade). session is the post-transition row
    // so the winner can read the authoritative submitted_at (in Postgres this is the
    // UPDATE ... RETURNING row — a pre-CAS snapshot would carry a stale/null timestamp).
    // Single-threaded JS means the read+write below can't interleave, so there is no
    // read-then-write window — the same property the Postgres atomic UPDATE gives.
    casSubmit(participantId, reason = "submit", nowMs = Date.now()) {
      const s = examSessions.get(participantId);
      if (!s || s.status !== "IN_PROGRESS") return { rows: 0, session: s || null };
      s.status = "SUBMITTED";
      s.submitted_at = nowMs;
      s.submitted_by = reason;
      return { rows: 1, session: s };
    },

    // Sessions the sweep must auto-submit: IN_PROGRESS and strictly past duration+grace
    // by the server clock (plan §4.1). Strict `<` matches exam.js isExpired's strict `>`,
    // so a session exactly at the boundary is neither write-rejected nor swept — no
    // one-tick window where a grace PATCH is accepted while the sweep submits underneath it.
    // Client never participates in expiry.
    expiredSessions(cutoffMs) {
      const out = [];
      for (const s of examSessions.values())
        if (s.status === "IN_PROGRESS" && s.exam_started_at < cutoffMs) out.push(s);
      return out;
    },

    // Graded result — written once by the winning submit/sweep, read only by the
    // admin results endpoint (plan §6: scores never reach a participant token).
    saveResult(participantId, result) {
      results.set(participantId, result);
      return result;
    },
    getResult(participantId) {
      return results.get(participantId) || null;
    },
  };
}
