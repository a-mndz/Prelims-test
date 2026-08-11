// Exam flow handlers — Phase 2 (plan §3, §3.1, §4, §4.2, §6, RULES #1,#2,#3).
import { sendJson, readJsonBody, isMobileUserAgent } from "./http.js";

export const ANTICHEAT_EVENTS = new Set(["tab_blur", "copy_paste", "fullscreen_exit"]);

export function createExam(store, bank, timing, rl = null) {
  const expiryCutoffMs = () => (timing.examDurationSec + timing.graceSec) * 1000;
  function isExpired(startedAt, nowMs) {
    return nowMs - startedAt > expiryCutoffMs();
  }

  async function requireInProgress(res, participantId) {
    const s = await store.getExamSession(participantId);
    if (!s) {
      sendJson(res, 409, { error: "exam_not_started" });
      return null;
    }
    if (s.status !== "IN_PROGRESS") {
      sendJson(res, 409, { error: "exam_not_in_progress", status: s.status });
      return null;
    }
    if (isExpired(s.exam_started_at, Date.now())) {
      sendJson(res, 403, { error: "exam_expired" });
      return null;
    }
    return s;
  }

  async function gradeAndStore(participantId, reason) {
    const s = await store.getExamSession(participantId);
    const responses = await store.getResponses(participantId);
    const { correct, total } = bank.grade(responses);
    return await store.saveResult(participantId, {
      participant_id: participantId,
      correct,
      total,
      submitted_at: s ? s.submitted_at : Date.now(),
      submitted_by: reason,
    });
  }

  const handlers = {
    async start(req, res, claims) {
      const existing = await store.getExamSession(claims.sub);
      if (existing && existing.status !== "IN_PROGRESS") {
        return sendJson(res, 409, { error: "exam_not_in_progress", status: existing.status });
      }
      if (!existing && isMobileUserAgent(req.headers["user-agent"])) {
        return sendJson(res, 403, {
          error: "mobile_not_allowed",
          message: "This exam is desktop-only. Please use a laptop or desktop computer.",
        });
      }
      const s = await store.startExam(claims.sub);
      return sendJson(res, 200, {
        status: s.status,
        startedAt: s.exam_started_at,
        durationSec: timing.examDurationSec,
        graceSec: timing.graceSec,
        total: bank.size,
        serverNow: Date.now(),
      });
    },

    async questions(_req, res, claims) {
      const s = await requireInProgress(res, claims.sub);
      if (!s) return;
      return sendJson(res, 200, { questions: bank.forParticipant(s.shuffle_seed) });
    },

    async answer(req, res, claims) {
      const s = await requireInProgress(res, claims.sub);
      if (!s) return;
      const { value, error } = await readJsonBody(req);
      if (error) return sendJson(res, 400, { error });
      const { questionId, optionId, flagged } = value || {};
      const q = typeof questionId === "string" ? bank.getById(questionId) : null;
      if (!q) return sendJson(res, 400, { error: "unknown_question" });

      const hasOption = optionId !== undefined && optionId !== null;
      const hasFlag = flagged !== undefined;
      if (!hasOption && !hasFlag) return sendJson(res, 400, { error: "empty_update" });

      const patch = {};
      if (hasOption) {
        if (typeof optionId !== "string" || !q.options.some((o) => o.id === optionId))
          return sendJson(res, 400, { error: "invalid_option" });
        patch.option_id = optionId;
        patch.answered = true;
      }
      if (hasFlag) {
        if (typeof flagged !== "boolean") return sendJson(res, 400, { error: "invalid_flag" });
        patch.flagged = flagged;
      }
      const row = await store.upsertResponse(claims.sub, questionId, patch);
      return sendJson(res, 200, {
        status: "saved",
        questionId: row.question_id,
        answered: row.answered,
        flagged: row.flagged,
      });
    },

    async event(req, res, claims) {
      const s = await requireInProgress(res, claims.sub);
      if (!s) return;
      const { value, error } = await readJsonBody(req);
      if (error) return sendJson(res, 400, { error });
      const type = value && value.type;
      if (!ANTICHEAT_EVENTS.has(type)) return sendJson(res, 400, { error: "unknown_event" });

      const overCap = rl && !rl.check(`evt:${claims.sub}`, timing.rateLimits.event).allowed;
      if (overCap) {
        const floods = await store.coalesceViolation(claims.sub, "rate_flood", "event_flood");
        return sendJson(res, 200, { status: "coalesced", floods });
      }

      await store.coalesceViolation(claims.sub, type, `ts=${Date.now()}`);
      const violations = await store.getViolations(claims.sub);
      const strikes = violations
        .filter((v) => ANTICHEAT_EVENTS.has(v.type))
        .reduce((n, v) => n + v.count, 0);

      const { blurThreshold, consequence } = timing.antiCheat;
      let applied = null;
      if (strikes >= blurThreshold) {
        applied = consequence;
        if (consequence === "auto_submit") {
          const resCas = await store.casSubmit(claims.sub, "blur_threshold");
          if (resCas.rows === 1) await gradeAndStore(claims.sub, "blur_threshold");
          await store.invalidateSession(claims.sub, claims.sid);
        }
      }
      return sendJson(res, 200, { status: "logged", strikes, threshold: blurThreshold, consequence: applied });
    },

    async review(_req, res, claims) {
      const s = await requireInProgress(res, claims.sub);
      if (!s) return;
      const rows = await store.getResponses(claims.sub);
      const answered = rows.filter((r) => r.answered).length;
      const flagged = rows.filter((r) => r.flagged).length;
      return sendJson(res, 200, {
        total: bank.size,
        answered,
        flagged,
        unanswered: bank.size - answered,
        responses: rows.map((r) => ({
          questionId: r.question_id,
          optionId: r.answered ? r.option_id : null,
          answered: r.answered,
          flagged: r.flagged,
        })),
      });
    },

    async status(_req, res, claims) {
      const s = await store.getExamSession(claims.sub);
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

    async submit(_req, res, claims) {
      const s = await store.getExamSession(claims.sub);
      if (!s) return sendJson(res, 409, { error: "exam_not_started" });
      const { rows, session } = await store.casSubmit(claims.sub, "submit");
      if (rows === 0) {
        return sendJson(res, 409, { error: "already_submitted", status: "SUBMITTED" });
      }
      await gradeAndStore(claims.sub, "submit");
      return sendJson(res, 200, { status: "submitted", timestamp: session.submitted_at });
    },
  };

  async function sweepExpired(nowMs = Date.now()) {
    const cutoff = nowMs - expiryCutoffMs();
    let swept = 0;
    const expired = await store.expiredSessions(cutoff);
    for (const s of expired) {
      const deadlineMs = s.exam_started_at + expiryCutoffMs();
      const resCas = await store.casSubmit(s.participant_id, "sweep", deadlineMs);
      if (resCas.rows === 1) {
        await gradeAndStore(s.participant_id, "sweep");
        swept += 1;
      }
    }
    return swept;
  }

  return { ...handlers, sweepExpired };
}
