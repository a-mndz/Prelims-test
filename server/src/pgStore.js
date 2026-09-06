import pg from "pg";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { newSessionId } from "./crypto.js";
const { Pool } = pg;

// schema.sql is the single source of truth for the shape of the database and is written to
// be idempotent, so it can be applied on the first connection of every process instead of
// depending on somebody having run it by hand. Without this, pointing the app at a fresh
// managed database (Supabase, Neon, RDS) makes the very first INSERT fail with
// 42P01 "relation \"participants\" does not exist" — the admin portal reports a 500 and no
// participant is ever saved.
//
// The read is deliberately not allowed to break module import: this file is not reachable
// through import tracing (it is data, not code) and only ships because vercel.json's
// includeFiles names "server/src/**". If that ever stops matching, a throw here would take
// down every route including /health; deferring it to ensureSchema() turns it into one
// legible bootstrap error instead.
let schemaReadError = null;
let schemaSql = "";
try {
  schemaSql = readFileSync(new URL("./schema.sql", import.meta.url), "utf8");
} catch (err) {
  schemaReadError = err;
}
export const SCHEMA_SQL = schemaSql;

// `client` is anything with a .query() — a Pool, a PoolClient, or a fake in tests.
export async function ensureSchema(client) {
  if (schemaReadError) {
    throw new Error(
      `Cannot read server/src/schema.sql, so the database schema cannot be applied: ` +
        `${schemaReadError.message}. Check that vercel.json includeFiles still ships ` +
        `server/src/**.`
    );
  }
  await client.query(SCHEMA_SQL);
}

// node-postgres does not understand sslmode in the URL; it is stripped and translated into
// the ssl option below. Supabase terminates TLS with a certificate chain Node does not
// trust by default, hence rejectUnauthorized: false.
function normalizeUrl(connectionString) {
  try {
    const parsed = new URL(connectionString);
    parsed.searchParams.delete("sslmode");
    return parsed.toString();
  } catch {
    return connectionString;
  }
}

function sslFor(connectionString) {
  return connectionString.includes("sslmode=disable") ? false : { rejectUnauthorized: false };
}

export function createPgStore(connectionString, options = {}) {
  const connStr = normalizeUrl(connectionString);
  const directUrl = options.directConnectionString || null;
  // Seam for tests: the schema bootstrap below is the fix for "created participants are not
  // saved", and asserting it runs once (and retries after a failure) must not require a
  // reachable database.
  const makePool = options.poolFactory || ((cfg) => new Pool(cfg));

  // Every warm serverless instance keeps its own pool, so a per-instance max of 10 burns
  // through Supabase's connection budget once a handful of instances are live. Keep it
  // small under Vercel and let an operator override it.
  const poolMax =
    Number.parseInt(process.env.PG_POOL_MAX || "", 10) || (process.env.VERCEL ? 2 : 10);

  const pool = makePool({
    connectionString: connStr,
    ssl: sslFor(connectionString),
    max: poolMax,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });


  let schemaPromise = null;

  return {
    _lockoutWindowMs: 15 * 60 * 1000,

    // Applied once per process and awaited before the store serves traffic. On failure the
    // memo is cleared so the next request retries: a database that was temporarily
    // unreachable (a paused Supabase project, a cold start during a restart) then recovers
    // on its own instead of poisoning the instance until the next deploy.
    async init() {
      if (!schemaPromise) {
        schemaPromise = (async () => {
          if (!directUrl) return ensureSchema(pool);
          // DDL through a transaction-mode pooler (Supabase port 6543) is unreliable, so
          // use the direct connection when the provider exposes one and release it again
          // straight away — it is needed for exactly one statement batch per process.
          const ddlPool = makePool({
            connectionString: normalizeUrl(directUrl),
            ssl: sslFor(directUrl),
            max: 1,
            connectionTimeoutMillis: 10000,
          });
          try {
            await ensureSchema(ddlPool);
          } finally {
            await ddlPool.end().catch(() => {});
          }
        })().catch((err) => {
          schemaPromise = null;
          throw err;
        });
      }
      return schemaPromise;
    },

    async close() {
      await pool.end();
    },

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

    async deleteParticipant(id) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("DELETE FROM responses WHERE participant_id = $1", [id]);
        await client.query("DELETE FROM results WHERE participant_id = $1", [id]);
        await client.query("DELETE FROM exam_sessions WHERE participant_id = $1", [id]);
        await client.query("DELETE FROM violations WHERE participant_id = $1", [id]);
        const res = await client.query(
          "DELETE FROM participants WHERE id = $1 RETURNING id, username",
          [id]
        );
        await client.query("COMMIT");
        if (res.rows.length === 0) return null;
        return {
          id: Number(res.rows[0].id),
          username: res.rows[0].username,
        };
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      } finally {
        client.release();
      }
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

    async getAdminById(id) {
      const res = await pool.query(`SELECT * FROM admins WHERE id = $1`, [id]);
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

    // Mirrors store.updateAdmin. The unique constraint on admins.username is the real
    // guard against a duplicate under a race; the route maps pg code 23505 to a 409.
    async updateAdmin(id, { username, passwordHash } = {}) {
      const sets = [];
      const params = [id];
      if (username !== undefined) sets.push(`username = $${params.push(username)}`);
      if (passwordHash !== undefined) sets.push(`password_hash = $${params.push(passwordHash)}`);
      if (!sets.length) return this.getAdminById(id);
      const res = await pool.query(
        `UPDATE admins SET ${sets.join(", ")} WHERE id = $1 RETURNING id, username, password_hash, role, active_session_id`,
        params
      );
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
        `UPDATE participants
         SET failed_logins = CASE
           WHEN failed_login_at IS NOT NULL AND ($2 - EXTRACT(EPOCH FROM failed_login_at) * 1000) > $3 THEN 1
           ELSE failed_logins + 1
         END,
         failed_login_at = to_timestamp($2 / 1000.0)
         WHERE id = $1`,
        [id, nowMs, this._lockoutWindowMs]
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
      const sid = newSessionId();
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
      const sid = newSessionId();
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
         ON CONFLICT (participant_id, type) WHERE type IN ('tab_blur', 'copy_paste', 'fullscreen_exit', 'rate_flood')
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
      const seed = randomBytes(16).toString("hex");
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
