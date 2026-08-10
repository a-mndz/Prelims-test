// Exam flow handlers — Phase 2 (plan §3, §3.1, §4, §4.2, §6, RULES #1,#2,#3).
// State machine: NOT_STARTED (no row) → IN_PROGRESS → SUBMITTED → LOCKED, one-way.
// Every handler here is already behind requireParticipant (role + active session)
// and the per-participant write rate limit in server.js (RULES #5). Status check
// lives here; the expiry check slots into requireInProgress in Phase 3 (§4.1).
import { sendJson, readJsonBody, isMobileUserAgent } from "./http.js";

// Client-reported anticheat violation types the event endpoint accepts (plan §5).
// All three feed ONE shared strike counter the threshold reads — mixed violations
// (blur + paste) count together, matching the "abort after N violations" policy.
// Exported: the admin leaderboard derives its malpractice flag from the same set.
export const ANTICHEAT_EVENTS = new Set(["tab_blur", "copy_paste", "fullscreen_exit"]);

export function createExam(store, bank, timing, rl = null) {
  // Hard server-side deadline (plan §4.1). One definition shared by the write-path
  // reject and the sweep, so "writes accepted up to duration+grace" and "sweep may
  // auto-submit" can never contradict each other at the boundary. Server clock only —
  // the client's opinion of the time is irrelevant (RULES #1).
  // ponytail: plan §4.1 sweeps at +duration and rejects writes at +duration+grace; we
  // unify on +duration+grace so the sweep never submits while a grace-window PATCH is
  // still legitimately in flight. Split the two constants if that ever needs to diverge.
  const expiryCutoffMs = () => (timing.examDurationSec + timing.graceSec) * 1000;
  function isExpired(startedAt, nowMs) {
    return nowMs - startedAt > expiryCutoffMs();
  }

  // The status + expiry choke-point every write routes through (plan §4, §4.1, RULES #5).
  // Returns the exam session row, or responds and returns null. Session check already
  // ran in requireParticipant (plan §2.2), rate limit in server.js — this is the last two.
  function requireInProgress(res, participantId) {
    const s = store.getExamSession(participantId);
    if (!s) {
      sendJson(res, 409, { error: "exam_not_started" });
      return null;
    }
    if (s.status !== "IN_PROGRESS") {
      // SUBMITTED/LOCKED: one-way, no writes accepted (plan §4).
      sendJson(res, 409, { error: "exam_not_in_progress", status: s.status });
      return null;
    }
    // Arrival-time expiry: a request landing after the deadline is rejected regardless
    // of what the client believes the clock says (plan §4.1 in-flight-PATCH rule).
    if (isExpired(s.exam_started_at, Date.now())) {
      sendJson(res, 403, { error: "exam_expired" });
      return null;
    }
    return s;
  }

  // Grade the winner's stored responses exactly once and persist the result (plan §4.3,
  // §6). Shared by manual submit and the sweep so both grade identically. The result is
  // admin-scoped — it never rides back to a participant token.
  function gradeAndStore(participantId, reason) {
    const s = store.getExamSession(participantId);
    const { correct, total } = bank.grade(store.getResponses(participantId));
    return store.saveResult(participantId, {
      participant_id: participantId,
      correct,
      total,
      submitted_at: s.submitted_at,
      submitted_by: reason,
    });
  }

  const handlers = {
    // NOT_STARTED → IN_PROGRESS. Idempotent: re-start returns the same seed/clock so a
    // refresh mid-exam is stable (plan §3.1). Starting after SUBMITTED is illegal.
    start(req, res, claims) {
      const existing = store.getExamSession(claims.sub);
      if (existing && existing.status !== "IN_PROGRESS") {
        return sendJson(res, 409, { error: "exam_not_in_progress", status: existing.status });
      }
      // Desktop-only, enforced at the start transition only — never mid-exam (plan §5.1).
      // On mobile the detection layer (§5) is weakened to meaningless, so we refuse the
      // NOT_STARTED → IN_PROGRESS transition rather than run with detection silently off.
      // UA is spoofable and that's accepted (plan §5.1) — this is fairness-by-default, not
      // a security perimeter. Only gate the FIRST start; a refresh of a live exam is fine.
      if (!existing && isMobileUserAgent(req.headers["user-agent"])) {
        return sendJson(res, 403, {
          error: "mobile_not_allowed",
          message: "This exam is desktop-only. Please use a laptop or desktop computer.",
        });
      }
      const s = store.startExam(claims.sub);
      // Client gets timing to render a countdown — display only; server clock is truth (plan §4.1).
      // serverNow lets the client offset a skewed local clock so the display can't run fast.
      return sendJson(res, 200, {
        status: s.status,
        startedAt: s.exam_started_at,
        durationSec: timing.examDurationSec,
        graceSec: timing.graceSec,
        total: bank.size,
        serverNow: Date.now(),
      });
    },

    // Shuffled + stripped questions for THIS participant's seed (plan §3.1, §6, RULES #2).
    // Read path, so no status write — but requires an in-progress exam to have a seed.
    questions(_req, res, claims) {
      const s = requireInProgress(res, claims.sub);
      if (!s) return;
      return sendJson(res, 200, { questions: bank.forParticipant(s.shuffle_seed) });
    },

    // Debounced autosave upsert (plan §4.2). Validates at the trust boundary: the
    // question must exist and the option must belong to it (RULES #1 — no client trust).
    async answer(req, res, claims) {
      const s = requireInProgress(res, claims.sub);
      if (!s) return;
      const { value, error } = await readJsonBody(req);
      if (error) return sendJson(res, 400, { error });
      const { questionId, optionId, flagged } = value || {};
      const q = typeof questionId === "string" ? bank.getById(questionId) : null;
      if (!q) return sendJson(res, 400, { error: "unknown_question" });

      // `answered` (an option) and `flagged` (a review mark) are ORTHOGONAL (plan §4):
      // one PATCH may carry either, both, or just a flag toggle. Each is optional and
      // merged into the existing row (store.upsertResponse), so flagging a question never
      // drops its stored answer and answering a flagged question never clears the flag.
      const hasOption = optionId !== undefined && optionId !== null;
      const hasFlag = flagged !== undefined;
      if (!hasOption && !hasFlag) return sendJson(res, 400, { error: "empty_update" });

      const patch = {};
      if (hasOption) {
        // An option must exist and belong to the question (RULES #1 — no client trust).
        if (typeof optionId !== "string" || !q.options.some((o) => o.id === optionId))
          return sendJson(res, 400, { error: "invalid_option" });
        patch.option_id = optionId;
        patch.answered = true;
      }
      if (hasFlag) {
        if (typeof flagged !== "boolean") return sendJson(res, 400, { error: "invalid_flag" });
        patch.flagged = flagged;
      }
      const row = store.upsertResponse(claims.sub, questionId, patch);
      return sendJson(res, 200, {
        status: "saved",
        questionId: row.question_id,
        answered: row.answered,
        flagged: row.flagged,
      });
    },

    // Anti-cheat violation events (plan §5). DETECTION, not prevention (RULES #8): the
    // server logs the signal for human review; it does not stop a participant switching
    // windows (that's outside JS's authority — a documented gap in §5). This is a write
    // endpoint, so it runs the full RULES #5 gauntlet: session (in requireParticipant),
    // status + expiry (requireInProgress), and its own rate limit with COALESCING (§2.3):
    // past the cap we increment a counter instead of inserting rows, so a hostile client
    // cannot bloat the log while the flood itself still leaves evidence.
    async event(req, res, claims) {
      const s = requireInProgress(res, claims.sub);
      if (!s) return;
      const { value, error } = await readJsonBody(req);
      if (error) return sendJson(res, 400, { error });
      const type = value && value.type;
      // Closed whitelist of client-reported violations (plan §5). Reject unknown types
      // at the trust boundary rather than logging arbitrary client-named events (RULES #1).
      if (!ANTICHEAT_EVENTS.has(type)) return sendJson(res, 400, { error: "unknown_event" });

      // Event rate limit (plan §2.3). Over the cap we do NOT 429-drop — we coalesce into
      // a single rate_flood row so the flood is counted and visible without amplifying it.
      const overCap = rl && !rl.check(`evt:${claims.sub}`, timing.rateLimits.event).allowed;
      if (overCap) {
        const floods = store.coalesceViolation(claims.sub, "rate_flood", "event_flood");
        return sendJson(res, 200, { status: "coalesced", floods });
      }

      // Under the cap: coalesce into one per-participant row PER TYPE — the admin log
      // stays distinguishable (a blur is not a paste). One row per type, not one-per-event.
      store.coalesceViolation(claims.sub, type, `ts=${Date.now()}`);
      // Strikes = total across all anticheat types, so mixed violations (2 blurs + 1
      // paste) still cross the one threshold — the policy is "N violations", not "N each".
      const strikes = store
        .getViolations(claims.sub)
        .filter((v) => ANTICHEAT_EVENTS.has(v.type))
        .reduce((n, v) => n + v.count, 0);

      // Threshold-based consequence (plan §5): never on the first strike — false positives
      // from OS notifications / stray alt-tabs. Consequence is admin-configurable; the
      // default (flag_for_review) is a signal for human judgment, not auto-disqualification.
      const { blurThreshold, consequence } = timing.antiCheat;
      let applied = null;
      if (strikes >= blurThreshold) {
        applied = consequence;
        if (consequence === "auto_submit") {
          // Structural submit path (§4.3): same atomic transition as manual submit/sweep,
          // so a threshold auto-submit racing either still yields exactly one grading run.
          if (store.casSubmit(claims.sub, "blur_threshold").rows === 1) gradeAndStore(claims.sub, "blur_threshold");
          // Kick out: revoke the active session so every subsequent request from this
          // token 401s (session_superseded). The exam is already SUBMITTED above, so a
          // re-login can only land on the locked confirmation screen — no restart path.
          store.invalidateSession(claims.sub, claims.sid);
        }
      }
      return sendJson(res, 200, { status: "logged", strikes, threshold: blurThreshold, consequence: applied });
    },

    // Review screen computed SERVER-SIDE from stored responses, never client state
    // (plan §4). No correctness leaks — counts + per-question state only (RULES #2).
    review(_req, res, claims) {
      const s = requireInProgress(res, claims.sub);
      if (!s) return;
      const rows = store.getResponses(claims.sub);
      // answered + flagged are orthogonal (plan §4): a row can be both. `unanswered` counts
      // questions with no selected option — a flag-only row is still unanswered.
      const answered = rows.filter((r) => r.answered).length;
      const flagged = rows.filter((r) => r.flagged).length;
      return sendJson(res, 200, {
        total: bank.size,
        answered,
        flagged,
        unanswered: bank.size - answered,
        // Per-question state for the review grid — which the participant touched, not what's right.
        responses: rows.map((r) => ({
          questionId: r.question_id,
          optionId: r.answered ? r.option_id : null,
          answered: r.answered,
          flagged: r.flagged,
        })),
      });
    },

    // Lightweight status read that works in EVERY state, including terminal ones — unlike
    // the IN_PROGRESS-gated reads above. The post-submit/expired confirmation screen needs
    // to render "submitted, locked" without a 409, and a refresh into a terminal state must
    // not dead-end. Leaks no score and no answer key (plan §6): status + timing only.
    // NOT_STARTED (no row) is a valid answer here, not an error.
    status(_req, res, claims) {
      const s = store.getExamSession(claims.sub);
      if (!s) return sendJson(res, 200, {
        status: "NOT_STARTED",
        durationSec: timing.examDurationSec,
        total: bank.size,
      });
      return sendJson(res, 200, {
        status: s.status,
        startedAt: s.exam_started_at,
        durationSec: timing.examDurationSec,
        graceSec: timing.graceSec,
        submittedAt: s.submitted_at,
        total: bank.size,
        serverNow: Date.now(),
      });
    },

    // IN_PROGRESS → SUBMITTED via one atomic conditional update (plan §4.3, RULES #4).
    // Row-count is the verdict, so N concurrent submits (and a submit racing the sweep)
    // resolve to exactly one grading run — no read-then-write window to exploit.
    // Deliberately does NOT go through requireInProgress: an expired session must still
    // be submittable so the participant's autosaved work gets graded rather than 403'd
    // into limbo (the sweep would submit it anyway — this just lets the client win first).
    submit(_req, res, claims) {
      const s = store.getExamSession(claims.sub);
      if (!s) return sendJson(res, 409, { error: "exam_not_started" });
      const { rows, session } = store.casSubmit(claims.sub, "submit");
      if (rows === 0) {
        // A duplicate submit or the sweep already transitioned it — idempotent, no re-grade.
        return sendJson(res, 409, { error: "already_submitted", status: "SUBMITTED" });
      }
      gradeAndStore(claims.sub, "submit"); // winner grades exactly once
      // Participant-facing response is status + timestamp only — never the score (plan §6).
      // Read submitted_at from the POST-transition row (casSubmit set it); the pre-CAS
      // snapshot `s` still had submitted_at=null.
      return sendJson(res, 200, { status: "submitted", timestamp: session.submitted_at });
    },
  };

  // Expiry sweep (plan §4.1): auto-submit sessions past the deadline using the SAME
  // atomic transition as manual submit, so a sweep and a manual submit racing each other
  // still yield exactly one SUBMITTED transition and one grading run. Client-independent:
  // a participant who never calls /submit is still submitted and graded here.
  // Returns the count swept — the caller (server boot / test) owns the interval.
  function sweepExpired(nowMs = Date.now()) {
    const cutoff = nowMs - expiryCutoffMs();
    let swept = 0;
    for (const s of store.expiredSessions(cutoff)) {
      // FIX L3: stamp submitted_at with the session's actual DEADLINE (start + duration
      // + grace), not the sweep-run time — with a 20s sweep interval the run time is up
      // to one interval late, and audit records would show submissions "after" time ran
      // out. The deadline is when the submission legally happened.
      const deadlineMs = s.exam_started_at + expiryCutoffMs();
      if (store.casSubmit(s.participant_id, "sweep", deadlineMs).rows === 1) {
        gradeAndStore(s.participant_id, "sweep");
        swept += 1;
      }
    }
    return swept;
  }

  return { ...handlers, sweepExpired };
}
