-- Prod schema (Postgres). Dev/test use the in-memory mirror in store.js.
-- competition-system-plan-v2.md §2, §2.2, §4; ARCHITECTURE.md "Data model".
-- Postgres chosen for atomic conditional UPDATE + row-count verdict (plan §4.3),
-- replication/PITR (plan §8). Never SQLite on the app box (plan §8).

-- Two independent credential tables, not one with a client-decided role flag (plan §2).
CREATE TABLE participants (
  id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username           TEXT UNIQUE NOT NULL,
  password_hash      TEXT NOT NULL,          -- scrypt/bcrypt/argon2, never plaintext
  competition_id     TEXT NOT NULL,
  is_active          BOOLEAN NOT NULL DEFAULT TRUE,
  active_session_id  TEXT,                   -- single active session (plan §2.2)
  failed_logins      INT NOT NULL DEFAULT 0,        -- lockout counter (plan §2.3)
  failed_login_at    TIMESTAMPTZ                    -- last failure; drives lockout DECAY so a
                                                    -- known username can't be permanently DoS'd
);

CREATE TABLE admins (
  id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username           TEXT UNIQUE NOT NULL,
  password_hash      TEXT NOT NULL,
  role               TEXT NOT NULL DEFAULT 'admin',
  active_session_id  TEXT   -- single active session, mirrors participants (FIX M2):
                            -- admin JWTs carry a sid checked against this row, so
                            -- logout/re-login revokes prior tokens server-side
  -- No per-account lockout counter: admin lockout is scoped to the source IP (in the app
  -- layer / rate-limit store), so a known admin username can't be used to lock the single
  -- admin out for the whole round. Per-IP failure tracking lives with the rate limiter.
);

-- Violation log — takeovers (plan §2.2), tab-blur events + coalesced floods (plan §5, §2.3).
-- `count` lets a flood past the rate limit coalesce into one row (count++) instead of
-- inserting a row per hostile request (plan §2.3: counted but coalesced). The coalescing
-- upsert is an INSERT ... ON CONFLICT (participant_id, type) DO UPDATE SET count = count + 1.
CREATE TABLE violations (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  participant_id  BIGINT NOT NULL REFERENCES participants(id),
  type            TEXT NOT NULL,   -- session_takeover | tab_blur | rate_flood
  detail          TEXT,
  count           INT NOT NULL DEFAULT 1,   -- coalesced flood counter (plan §2.3)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX violations_participant_idx ON violations(participant_id);
-- Coalesced types (tab_blur, rate_flood) get ONE row per (participant, type) that the
-- ON CONFLICT upsert increments — so this PARTIAL unique index is the conflict target.
-- It is partial on purpose: session_takeover stays APPEND-ONLY (one row per takeover,
-- plan §2.2 "log every takeover"), so it must NOT be covered by a unique constraint.
CREATE UNIQUE INDEX violations_coalesced_uniq
  ON violations (participant_id, type)
  WHERE type IN ('tab_blur', 'rate_flood');

-- Exam state on its own table, not the participant row: the sweep (plan §4.1) and
-- the atomic submit (plan §4.3) both race over this row's status (plan §4).
CREATE TYPE exam_status AS ENUM ('IN_PROGRESS', 'SUBMITTED', 'LOCKED');
CREATE TABLE exam_sessions (
  participant_id   BIGINT PRIMARY KEY REFERENCES participants(id),  -- unique => one exam/participant
  status           exam_status NOT NULL DEFAULT 'IN_PROGRESS',
  exam_started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),              -- server clock (plan §4.1)
  shuffle_seed     TEXT NOT NULL,                                   -- per-participant order (plan §3.1)
  submitted_at     TIMESTAMPTZ,
  submitted_by     TEXT             -- who transitioned to SUBMITTED: submit | sweep | blur_threshold
                                    -- (store.js casSubmit writes it; audit trail for plan §4.1/§5)
);

-- Graded outcome, one row per participant, written exactly once by the single winning
-- casSubmit transition (plan §4.3). submitted_by mirrors exam_sessions for the audit trail.
CREATE TABLE results (
  participant_id  BIGINT PRIMARY KEY REFERENCES participants(id),
  correct         INT NOT NULL,
  total           INT NOT NULL,
  submitted_at    TIMESTAMPTZ NOT NULL,
  submitted_by    TEXT NOT NULL    -- submit | sweep | blur_threshold
);

-- One row per (participant, question). Autosave is an upsert on this key — idempotent,
-- safe to retry (plan §4.2). Answers store option_id (stable), never a position (plan §3.1).
-- `answered` and `flagged` are ORTHOGONAL (plan §4): a participant can answer a question and
-- flag it to revisit — flagging must never drop a selected answer from grading. option_id is
-- '' when the row is flag-only (flagged before any option was picked). Grading counts any row
-- with answered=TRUE, regardless of flag.
CREATE TABLE responses (
  participant_id  BIGINT NOT NULL REFERENCES participants(id),
  question_id     TEXT NOT NULL,
  option_id       TEXT NOT NULL DEFAULT '',
  answered        BOOLEAN NOT NULL DEFAULT FALSE,
  flagged         BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (participant_id, question_id)
);

-- Note: questions themselves are seed data loaded from questions.bank.json (plan §3),
-- not a table Phase 2 writes to. Freeze the bank before the dry run (MEMORY.md).
