# Go-Live Runbook (Phase 5)

Operational checklist for the competition window. Mechanism lives in the code; this
file is the decisions and the human procedure. Spec: [plan §8](competition-system-plan-v2.md#8-deployment--go-live-checklist), tests: [plan §7](competition-system-plan-v2.md#7-testing--validation).

Status legend: **[verified in repo]** runnable/checked here · **[on-infra]** owner action on real prod infra, not automatable in this repo.

## 1. Load test — 3× the stated peak — [verified in repo]

- Target: **450** concurrent (3× the 150 peak, [DECISIONS.md](DECISIONS.md)).
- Run: `JWT_SECRET=x node loadtest.js` in `server/` (or `LOAD_N=900` for headroom).
- Asserts the two §7 load claims that are real in-process: **grading independence** (each participant's score is its own — no shared-state bleed across N sessions) and **submit race-safety at scale** (2 concurrent submits/participant → exactly one 200 + one graded result + one 409). Both green at 450 and 900.
- **[on-infra] gap:** network throughput, Postgres connection-pool contention, TLS/cold-start latency. Single-threaded Node's event loop isn't where 450-concurrent contention actually lives — the Postgres adapter is. Re-run an HTTP-level load test (autocannon/k6 against `/api/exam/submit` + sustained autosave) on staging with the managed DB before sign-off.

## 2. Monitoring — [on-infra]

- `/health` exists (`server.js` → `200 {status:ok}`, unauthenticated, no DB dependency — liveness only).
- Wire an uptime check hitting `/health` **every 30s** (plan §8).
- Alerts on error-rate + DB-connection failures routed to a human **on watch** (dashboard open or pager live) for the whole window. Failure mode to design against: learning about an outage from a participant's email.
- **Owner action:** pick the uptime/alerting service, set the 30s check, name the on-watch human per time block.

## 3. Backup / PITR — [on-infra]

- Exam state lives entirely in the DB; the app server is stateless (losing it loses nothing).
- Managed/replicated Postgres with **point-in-time recovery, or snapshots at minutes-not-hours cadence** during the window (plan §8). Never SQLite on the app box (plan §8, [schema.sql](server/src/schema.sql)).
- **Rehearse the restore during a staging window** — "restore from last night's snapshot" mid-round is a cancellation plan, not a rollback plan.
- **Owner action:** confirm PITR enabled, run one timed restore rehearsal, record RPO/RTO.

## 4. Question bank freeze → dry run — [on-infra] (blocked on real bank)

- **Blocker:** only a **4-question sample** exists (`server/src/questions.bank.json`). Need the real **25 C + 25 Python = 50** finalized and loaded first (plan §8, [MEMORY.md](MEMORY.md)).
- The loader (`questions.js` `loadBank`) already validates shape at boot — a malformed/leaky bank fails loudly, doesn't serve. After loading the real bank, run `JWT_SECRET=x node --test` (grading test scripts the full loaded bank per §7) and `node loadtest.js` again.
- Freeze the bank **before** the dry run — editing questions after means you didn't test what participants see.
- Dry run on the **production URL** (not localhost), a handful of people, full exam, and deliberately exercise:
  - one **expired session** → verify the sweep fires in prod (check `submitted_by = "sweep"` server-side).
  - one **session takeover** → log in as the same participant from a 2nd browser, confirm the 1st gets 401 and a `session_takeover` violation is logged.
  - **on-device anti-cheat** (the Phase 4 items still owed, [TASKS.md](TASKS.md)): Page Visibility API fires and the mobile block renders on the *real* lab machines / locked-down browser images — not just Chrome desktop.
- Verify **server-side** that responses, violation logs, and scores recorded and admin-visible (`GET /api/admin/results/:id`, `/api/admin/violations`).
- Catches deployment-specific failures invisible in local dev: CORS, cookie flags behind real TLS (`Secure` requires HTTPS — `config.cookie.secure` is forced on when `NODE_ENV=production`), wrong API base URL, cold-start latency.

## 5. Rollback decision tree — decided now, in writing (plan §8) — [verified: decided]

Server-authoritative timing (plan §4.1: `exam_started_at` on the server, expiry computed
from it) is what makes "pause the clock" implementable — the client's clock is never trusted.

Decision order when something breaks mid-competition:

1. **App server crashes / restarts** → no action on state. It's stateless; JWTs are in cookies, all exam state is in the DB. Sessions resume on reconnect; the sweep still catches expiries on the surviving/restarted instance. Just get an instance back up.
2. **Widespread client-side failure or a bad deploy** (app-layer bug, not data loss) → **redeploy the previous known-good build.** DB untouched, so no state lost. This is why the app stays stateless and the bank is frozen — the rollback is a binary artifact swap.
3. **Participants blocked/delayed but DB intact** (partial outage, degraded latency) → **pause the clock / extend the deadline**: an admin action offsetting `exam_started_at` forward for affected sessions (equivalently `EXAM_DURATION_SEC` for a global extension), then announce the new deadline. Because expiry = `now − exam_started_at > duration + grace` on the server, moving `exam_started_at` forward *is* the pause. **Owner action to finish:** wire the admin "offset `exam_started_at` by N minutes" endpoint (behind `requireAdmin`); the timing model already supports it — no endpoint exists yet.
4. **DB data corruption / loss** (last resort) → **restore from point-in-time backup** (item 3 above) to the most recent clean point, then extend the deadline to cover lost progress. This loses the least possible with PITR; with only nightly snapshots it loses the round — which is why item 3's minutes-cadence backup is non-negotiable.

Who decides: the on-watch human (item 2) invokes 1–2 unilaterally; 3–4 need the competition organizer's sign-off on the new deadline. Decide **now** who that organizer contact is.

---

**Done** = all §7 tests green on staging with the real 50-question bank (items 1 + 4), items 2–4 confirmed on prod infra, item 5's clock-offset endpoint wired. Everything marked **[on-infra]** is an owner action at the dry run, not code owed here.
