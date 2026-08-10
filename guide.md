# Prelims Competition System — Operations & Execution Guide

This document provides a comprehensive guide on configuring, running, testing, and operating the **Competition System (Preliminary Round)**.

---

## 1. System Overview

The Prelims Competition System is a zero-dependency (Node.js standard library only) platform for hosting a 50-question MCQ exam (25 C, 25 Python). Key capabilities include:
- **Dual Authentication**: Separate login flows for participants and administrators.
- **Single Active Session**: Automatic invalidation and takeover logging if a participant logs in on a second device/browser.
- **Anti-Cheat Detection**: Server-side tracking of tab blur/focus loss events with configurable thresholds and consequences.
- **Deterministic Shuffling**: Questions and options are shuffled deterministically per participant seed, preserving position-independence for grading.
- **Server-Enforced Timing & Idempotent Submit**: Atomic state machine preventing double-submits or post-expiry submissions.

---

## 2. Environment Configuration (`.env`)

The application configuration is managed via environment variables defined in `.env` (copied from `.env.example`).

### Configured Environment Variables Overview

| Variable | Recommended Dev Value | Purpose / Description |
|---|---|---|
| `NODE_ENV` | `development` | Environment mode (`production` throws if required secrets are missing and forces HTTPS cookies). |
| `JWT_SECRET` | `a3f91d84b2e10...` | 32+ byte random hex string used to sign JWT tokens. **Must be unique per environment**. |
| `DATABASE_URL` | `postgres://...` | Connection URI for production PostgreSQL database. |
| `PORT` | `3000` | HTTP server listening port. |
| `COOKIE_SECURE` | `# COOKIE_SECURE=false` | Set to `false` ONLY for local HTTP dev; production forces `true` for HTTPS cookies. |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted reverse proxy hops (e.g. Nginx, Cloudflare). Set `0` for direct connections. |
| `EXAM_DURATION_SEC` | `3600` | Exam duration in seconds (1 hour). |
| `GRACE_SEC` | `5` | Grace period in seconds for submission network latency. |
| `LOGIN_START_BUFFER_SEC` | `1800` | Pre-exam login window (30 mins) allowed for token issuance before exam start. |
| `RL_PARTICIPANT_LOGIN` | `5` | Rate limit: Max participant logins per IP per minute. |
| `RL_ADMIN_LOGIN` | `3` | Rate limit: Max admin logins per IP per minute. |
| `RL_ANSWER` | `60` | Rate limit: Max answer updates per participant per minute. |
| `RL_EVENT` | `30` | Rate limit: Max anti-cheat events logged per minute. |
| `RL_SUBMIT` | `5` | Rate limit: Max submit attempts per minute. |
| `LOGIN_LOCKOUT` | `10` | Failed login threshold before temporary account lockout. |
| `LOGIN_LOCKOUT_WINDOW_SEC` | `900` | Lockout decay window (15 minutes). |
| `BLUR_THRESHOLD` | `3` | Number of tab blur events before anti-cheat action triggers. |
| `BLUR_CONSEQUENCE` | `flag_for_review` | Policy action (`flag_for_review`, `warn`, `auto_submit`). |
| `SEED_PARTICIPANT_USER` | `participant1` | Default participant username for dev seed. |
| `SEED_PARTICIPANT_PASS` | `change-me-participant` | Default participant password for dev seed. |
| `SEED_ADMIN_USER` | `admin1` | Default admin username for dev seed. |
| `SEED_ADMIN_PASS` | `change-me-admin` | Default admin password for dev seed. |

---

## 3. How to Run the Application

### Prerequisites
- **Node.js**: Version 18.0.0 or higher.
- **Dependencies**: No external `npm` packages required (uses Node stdlib: `node:http`, `node:crypto`, `node:test`).

### Step 1: Navigate to the Server Directory
```bash
cd server
```

### Step 2: Running Unit & Integration Tests
Execute the built-in Node test runner to verify all system guarantees (52 tests across auth, timing, rate limiting, anti-cheat, and grading):

```bash
npm test
```
*Alternatively, run with environment variables loaded:*
```bash
node --env-file=.env --test
```

### Step 3: Starting the Development Server
Start the Node HTTP server on port `3000`:

```bash
npm start
```
*Alternatively, run directly with node:*
```bash
node --env-file=.env src/server.js
```

Upon starting, you will see output indicating the server is listening:
```text
Server listening on http://localhost:3000
```

---

## 4. API Endpoints & Usage

### A. Authentication
- **Participant Login**: `POST /api/auth/participant/login`
  - Body: `{"username": "participant1", "password": "change-me-participant"}`
  - Sets HTTP-Only Session Cookie.
- **Admin Login**: `POST /api/auth/admin/login`
  - Body: `{"username": "admin1", "password": "change-me-admin"}`
- **Logout**: `POST /api/auth/logout`

### B. Participant Exam Flow (Requires Participant Cookie + `x-requested-with` CSRF header)
- **Get Status & Questions**: `GET /api/exam/questions`
- **Start Exam**: `POST /api/exam/start`
- **Save Answer (Autosave)**: `PATCH /api/exam/answer`
  - Body: `{"question_id": "q1", "option_id": "opt_a", "is_flagged": false}`
- **Log Anti-Cheat Event**: `POST /api/exam/event`
  - Body: `{"type": "tab_blur"}`
- **Submit Exam**: `POST /api/exam/submit`

### C. Admin Monitoring & Management (Requires Admin Cookie + `x-requested-with` header)
- **View Violations Log**: `GET /api/admin/violations`
- **Unlock Account**: `POST /api/admin/unlock`
  - Body: `{"participant_id": 1}`
- **View Results**: `GET /api/admin/results/:id`

---

## 5. Deployment & Production Considerations

1. **Database**: In development and testing, an in-memory store mirror (`server/src/store.js`) is used. In production, connect PostgreSQL using `server/src/schema.sql`.
2. **Reverse Proxy & TLS**: Deploy behind Nginx, AWS ALB, or Cloudflare terminating TLS. Set `TRUST_PROXY_HOPS=1` in `.env` so rate limiting and IP tracking correctly read client IPs.
3. **Secrets Management**: Replace all default seed credentials and JWT secret before deploying to staging or production.
