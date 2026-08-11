import pg from "pg";
const { Pool } = pg;

export function createPgStore(connectionString) {
  let connStr = connectionString;
  try {
    const parsed = new URL(connectionString);
    parsed.searchParams.delete("sslmode");
    connStr = parsed.toString();
  } catch {}

  const pool = new Pool({
    connectionString: connStr,
    ssl: connectionString.includes("sslmode=disable") ? false : { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });

  return {
    _lockoutWindowMs: 15 * 60 * 1000,

    async addParticipant({ username, passwordHash, competitionId = "prelim" }) {
      const res = await pool.query(
        `INSERT INTO participants (username, password_hash, competition_id) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING RETURNING id`,
        [username, passwordHash, competitionId]
      );
      if (res.rows.length === 0) {
        const existing = await this.getParticipantByUsername(username);
        return existing ? existing.id : null;
      }
      return Number(res.rows[0].id);
    },

    async addAdmin({ username, passwordHash, role = "admin" }) {
      const res = await pool.query(
        `INSERT INTO admins (username, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING RETURNING id`,
        [username, passwordHash, role]
      );
      if (res.rows.length === 0) {
        const existing = await this.getAdminByUsername(username);
        return existing ? existing.id : null;
      }
      return Number(res.rows[0].id);
    },

    async getParticipantByUsername(username) {
      const res = await pool.query(`SELECT * FROM participants WHERE username = $1`, [username]);
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        id: Number(r.id),
        username: r.username,
        password_hash: r.password_hash,
        competition_id: r.competition_id,
        is_active: r.is_active,
        active_session_id: r.active_session_id,
        failed_logins: r.failed_logins,
        failed_login_at: r.failed_login_at ? new Date(r.failed_login_at).getTime() : 0,
      };
    },

    async getParticipantById(id) {
      const res = await pool.query(`SELECT * FROM participants WHERE id = $1`, [id]);
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        id: Number(r.id),
        username: r.username,
        password_hash: r.password_hash,
        competition_id: r.competition_id,
        is_active: r.is_active,
        active_session_id: r.active_session_id,
        failed_logins: r.failed_logins,
        failed_login_at: r.failed_login_at ? new Date(r.failed_login_at).getTime() : 0,
      };
    },

    async allParticipants() {
      const res = await pool.query(`SELECT * FROM participants ORDER BY id ASC`);
      return res.rows.map((r) => ({
        id: Number(r.id),
        username: r.username,
        password_hash: r.password_hash,
        competition_id: r.competition_id,
        is_active: r.is_active,
        active_session_id: r.active_session_id,
        failed_logins: r.failed_logins,
        failed_login_at: r.failed_login_at ? new Date(r.failed_login_at).getTime() : 0,
      }));
    },

    async unlockParticipant(id) {
      const res = await pool.query(
        `UPDATE participants SET failed_logins = 0, failed_login_at = NULL WHERE id = $1 RETURNING *`,
        [id]
      );
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        id: Number(r.id),
        username: r.username,
        password_hash: r.password_hash,
        competition_id: r.competition_id,
        is_active: r.is_active,
        active_session_id: r.active_session_id,
        failed_logins: 0,
        failed_login_at: 0,
      };
    },

    async getAdminByUsername(username) {
      const res = await pool.query(`SELECT * FROM admins WHERE username = $1`, [username]);
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        id: Number(r.id),
        username: r.username,
        password_hash: r.password_hash,
        role: r.role,
        active_session_id: r.active_session_id,
      };
    },

    async bumpParticipantFailure(id, nowMs = Date.now()) {
      await pool.query(
        `UPDATE participants SET failed_logins = failed_logins + 1, failed_login_at = to_timestamp($2 / 1000.0) WHERE id = $1`,
        [id, nowMs]
      );
    },

    async participantFailures(id, nowMs = Date.now()) {
      const p = await this.getParticipantById(id);
      if (!p) return 0;
      if (p.failed_login_at && nowMs - p.failed_login_at > this._lockoutWindowMs) return 0;
      return p.failed_logins;
    },

    async resetParticipantFailures(id) {
      await pool.query(
        `UPDATE participants SET failed_logins = 0, failed_login_at = NULL WHERE id = $1`,
        [id]
      );
    },

    _adminFailures: new Map(),
    bumpAdminFailure(ip, nowMs = Date.now()) {
      const e = this._adminFailures.get(ip);
      if (e && nowMs - e.at > this._lockoutWindowMs) {
        this._adminFailures.set(ip, { count: 1, at: nowMs });
      } else {
        this._adminFailures.set(ip, { count: (e ? e.count : 0) + 1, at: nowMs });
      }
    },
    adminFailuresForIp(ip, nowMs = Date.now()) {
      const e = this._adminFailures.get(ip);
      if (!e) return 0;
      if (nowMs - e.at > this._lockoutWindowMs) return 0;
      return e.count;
    },
    resetAdminFailures(ip) {
      this._adminFailures.delete(ip);
    },

    async issueSession(participantId) {
      const sid = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const res = await pool.query(
        `UPDATE participants SET active_session_id = $2 WHERE id = $1 RETURNING active_session_id`,
        [participantId, sid]
      );
      if (res.rows.length === 0) throw new Error("no such participant");
      return sid;
    },

    async sessionMatches(participantId, sid) {
      const res = await pool.query(`SELECT active_session_id FROM participants WHERE id = $1`, [participantId]);
      if (res.rows.length === 0) return false;
      return res.rows[0].active_session_id === sid;
    },

    async invalidateSession(participantId, sid) {
      const res = await pool.query(
        `UPDATE participants SET active_session_id = NULL WHERE id = $1 AND active_session_id = $2`,
        [participantId, sid]
      );
      return res.rowCount > 0;
    },

    async issueAdminSession(adminId) {
      const sid = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const res = await pool.query(
        `UPDATE admins SET active_session_id = $2 WHERE id = $1 RETURNING active_session_id`,
        [adminId, sid]
      );
      if (res.rows.length === 0) throw new Error("no such admin");
      return sid;
    },

    async adminSessionMatches(adminId, sid) {
      const res = await pool.query(`SELECT active_session_id FROM admins WHERE id = $1`, [adminId]);
      if (res.rows.length === 0) return false;
      return !!sid && res.rows[0].active_session_id === sid;
    },

    async invalidateAdminSession(adminId, sid) {
      const res = await pool.query(
        `UPDATE admins SET active_session_id = NULL WHERE id = $1 AND active_session_id = $2`,
        [adminId, sid]
      );
      return res.rowCount > 0;
    },

    async logViolation(participantId, type, detail = null) {
      await pool.query(
        `INSERT INTO violations (participant_id, type, detail, count) VALUES ($1, $2, $3, 1)`,
        [participantId, type, detail]
      );
    },

    async coalesceViolation(participantId, type, detail = null) {
      const res = await pool.query(
        `INSERT INTO violations (participant_id, type, detail, count)
         VALUES ($1, $2, $3, 1)
         ON CONFLICT (participant_id, type) WHERE type IN ('tab_blur', 'rate_flood')
         DO UPDATE SET count = violations.count + 1, detail = COALESCE($3, violations.detail)
         RETURNING count`,
        [participantId, type, detail]
      );
      return res.rows[0] ? res.rows[0].count : 1;
    },

    async getViolations(participantId) {
      const res = await pool.query(`SELECT * FROM violations WHERE participant_id = $1`, [participantId]);
      return res.rows.map((r) => ({
        id: Number(r.id),
        participant_id: Number(r.participant_id),
        type: r.type,
        detail: r.detail,
        count: r.count,
        created_at: r.created_at,
      }));
    },

    async getAllViolations() {
      const res = await pool.query(`SELECT * FROM violations ORDER BY id DESC`);
      return res.rows.map((r) => ({
        id: Number(r.id),
        participant_id: Number(r.participant_id),
        type: r.type,
        detail: r.detail,
        count: r.count,
        created_at: r.created_at,
      }));
    },

    async getExamSession(participantId) {
      const res = await pool.query(`SELECT * FROM exam_sessions WHERE participant_id = $1`, [participantId]);
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        participant_id: Number(r.participant_id),
        status: r.status,
        exam_started_at: new Date(r.exam_started_at).getTime(),
        shuffle_seed: r.shuffle_seed,
        submitted_at: r.submitted_at ? new Date(r.submitted_at).getTime() : null,
        submitted_by: r.submitted_by,
      };
    },

    async startExam(participantId, nowMs = Date.now()) {
      const existing = await this.getExamSession(participantId);
      if (existing) return existing;
      const seed = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
      const res = await pool.query(
        `INSERT INTO exam_sessions (participant_id, status, exam_started_at, shuffle_seed)
         VALUES ($1, 'IN_PROGRESS', to_timestamp($2 / 1000.0), $3)
         ON CONFLICT (participant_id) DO NOTHING
         RETURNING *`,
        [participantId, nowMs, seed]
      );
      if (res.rows.length === 0) return await this.getExamSession(participantId);
      const r = res.rows[0];
      return {
        participant_id: Number(r.participant_id),
        status: r.status,
        exam_started_at: new Date(r.exam_started_at).getTime(),
        shuffle_seed: r.shuffle_seed,
        submitted_at: null,
        submitted_by: null,
      };
    },

    async upsertResponse(participantId, questionId, patch = {}) {
      const existingRes = await pool.query(
        `SELECT * FROM responses WHERE participant_id = $1 AND question_id = $2`,
        [participantId, questionId]
      );
      const prev = existingRes.rows[0] || {
        option_id: "",
        answered: false,
        flagged: false,
      };
      const optionId = patch.option_id !== undefined ? patch.option_id : prev.option_id;
      const answered = patch.answered !== undefined ? patch.answered : prev.answered;
      const flagged = patch.flagged !== undefined ? patch.flagged : prev.flagged;

      const res = await pool.query(
        `INSERT INTO responses (participant_id, question_id, option_id, answered, flagged)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (participant_id, question_id)
         DO UPDATE SET option_id = $3, answered = $4, flagged = $5
         RETURNING *`,
        [participantId, questionId, optionId, answered, flagged]
      );
      const r = res.rows[0];
      return {
        participant_id: Number(r.participant_id),
        question_id: r.question_id,
        option_id: r.option_id,
        answered: r.answered,
        flagged: r.flagged,
      };
    },

    async getResponses(participantId) {
      const res = await pool.query(`SELECT * FROM responses WHERE participant_id = $1`, [participantId]);
      return res.rows.map((r) => ({
        participant_id: Number(r.participant_id),
        question_id: r.question_id,
        option_id: r.option_id,
        answered: r.answered,
        flagged: r.flagged,
      }));
    },

    async casSubmit(participantId, reason = "submit", nowMs = Date.now()) {
      const res = await pool.query(
        `UPDATE exam_sessions
         SET status = 'SUBMITTED', submitted_at = to_timestamp($3 / 1000.0), submitted_by = $2
         WHERE participant_id = $1 AND status = 'IN_PROGRESS'
         RETURNING *`,
        [participantId, reason, nowMs]
      );
      if (res.rowCount === 0) {
        const current = await this.getExamSession(participantId);
        return { rows: 0, session: current };
      }
      const r = res.rows[0];
      const session = {
        participant_id: Number(r.participant_id),
        status: r.status,
        exam_started_at: new Date(r.exam_started_at).getTime(),
        shuffle_seed: r.shuffle_seed,
        submitted_at: new Date(r.submitted_at).getTime(),
        submitted_by: r.submitted_by,
      };
      return { rows: 1, session };
    },

    async expiredSessions(cutoffMs) {
      const res = await pool.query(
        `SELECT * FROM exam_sessions WHERE status = 'IN_PROGRESS' AND exam_started_at < to_timestamp($1 / 1000.0)`,
        [cutoffMs]
      );
      return res.rows.map((r) => ({
        participant_id: Number(r.participant_id),
        status: r.status,
        exam_started_at: new Date(r.exam_started_at).getTime(),
        shuffle_seed: r.shuffle_seed,
        submitted_at: r.submitted_at ? new Date(r.submitted_at).getTime() : null,
        submitted_by: r.submitted_by,
      }));
    },

    async saveResult(participantId, result) {
      const res = await pool.query(
        `INSERT INTO results (participant_id, correct, total, submitted_at, submitted_by)
         VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), $5)
         ON CONFLICT (participant_id)
         DO UPDATE SET correct = $2, total = $3, submitted_at = to_timestamp($4 / 1000.0), submitted_by = $5
         RETURNING *`,
        [participantId, result.correct, result.total, result.submitted_at, result.submitted_by]
      );
      const r = res.rows[0];
      return {
        participant_id: Number(r.participant_id),
        correct: r.correct,
        total: r.total,
        submitted_at: new Date(r.submitted_at).getTime(),
        submitted_by: r.submitted_by,
      };
    },

    async getResult(participantId) {
      const res = await pool.query(`SELECT * FROM results WHERE participant_id = $1`, [participantId]);
      if (res.rows.length === 0) return null;
      const r = res.rows[0];
      return {
        participant_id: Number(r.participant_id),
        correct: r.correct,
        total: r.total,
        submitted_at: new Date(r.submitted_at).getTime(),
        submitted_by: r.submitted_by,
      };
    },
  };
}
