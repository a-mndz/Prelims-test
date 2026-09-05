# Competition System — Preliminary Round

A high-concurrency, desktop-only 50-question MCQ exam platform (25 C, 25 Python) built for timed programming competitions. Features dual authentication (Participant & Administrator), server-authoritative timing, deterministic per-participant question shuffling, real-time answer autosaving, strict anti-cheat detection with instant violation auto-submit, live admin leaderboards, and zero-downtime PostgreSQL persistence on Supabase & Vercel.

Live Production URL: [https://prelims-taupe.vercel.app](https://prelims-taupe.vercel.app)

---

## Key Features

- **Participant Exam Portal**:
  - Desktop-only access guard (mobile user agents strictly blocked at start).
  - Enforced fullscreen mode on exam start.
  - Deterministic per-participant question and option shuffling based on seeded PRNG.
  - Answer secrecy: correct answers are never delivered to the client; grading is strictly server-side.
  - Debounced autosave queue for question navigation, answers, and review flags.
  - Synchronized server-authoritative timer with visual countdown and screen-reader low-time milestone alerts.

- **Strict Anti-Cheat & Malpractice Enforcement**:
  - **Instant Abort Policy (`BLUR_THRESHOLD=1`, `BLUR_CONSEQUENCE=auto_submit`)**:
    - Switching tabs, opening another tab (`Ctrl+T` / `Ctrl+N`), or minimizing the window.
    - Loss of window focus (`window.blur`).
    - Exiting fullscreen mode (pressing Escape or exiting fullscreen).
    - Right-click / context menu attempts.
    - Clipboard operations (`copy`, `cut`, `paste`).
    - Developer tools shortcuts (`F12`, `Ctrl+Shift+I/J/C/K/P`, `Ctrl+U`, `Ctrl+S`, `Ctrl+P`, macOS Cmd equivalents).
  - Any malpractice immediately auto-submits the candidate's exam, revokes the active session token, locks out further attempts, and flags the candidate for malpractice on the admin leaderboard.

- **Administrator Dashboard**:
  - Live graded leaderboard (updates as participants submit or time out).
  - Detailed violation audit logs with strike counts and violation types (`tab_blur`, `copy_paste`, `fullscreen_exit`).
  - Batch participant account creation with automated validation.
  - Self-service admin credential updates.
  - Manual account unlock for participant lockout remediation.

- **Resilient Persistence & Concurrency**:
  - Production-ready PostgreSQL storage adapter supporting pooled Supabase connections and direct DDL bootstrap.
  - Built-in volatile in-memory fallback for local dev and zero-dependency unit tests.
  - High concurrency verified via load test (450 simulated participants, 900 concurrent submissions, atomic Compare-And-Swap submit transitions).

---

## Tech Stack

- **Runtime**: Node.js ≥22 (ES modules).
- **Core Dependencies**: Zero production runtime dependencies. Uses standard Node.js libraries (`node:http`, `node:crypto`, `node:test`, `node:assert`).
- **Database**: PostgreSQL (Supabase with Transaction Pooler & Direct DDL support).
- **Deployment**: Vercel Serverless Functions (`api/index.js`).
- **Client**: Vanilla HTML5, CSS3 (responsive desktop layout, dark/light theme support, WCAG accessible), and modular JavaScript.

---

## Project Structure

```text
.
├── api/
│   └── index.js              # Vercel serverless HTTP entry point
├── server/
│   ├── public/               # Static client assets
│   │   ├── anticheat.js      # Client deterrence & violation detection beacons
│   │   ├── app.js            # Exam UI, timer, autosave queue & admin dashboard
│   │   ├── exam.css          # Design system & accessible themes
│   │   └── exam.html         # Single-page application shell
│   ├── src/
│   │   ├── auth.js           # Role validation, CSRF guard & session middleware
│   │   ├── bootstrap.js      # Cold-start database schema bootstrap & retries
│   │   ├── config.js         # Environment config, timing, rate limits & thresholds
│   │   ├── crypto.js         # JWT signing/verification & scrypt password hashing
│   │   ├── errors.js         # Custom structured configuration & runtime errors
│   │   ├── exam.js           # Exam lifecycle, autosave, grading & anti-cheat handlers
│   │   ├── http.js           # Cookie parsing, JSON body reading & static server
│   │   ├── pgStore.js        # PostgreSQL store adapter (Supabase)
│   │   ├── questions.bank.json # 50-question curated question bank (C & Python)
│   │   ├── questions.js      # Seeded Fisher-Yates question/option shuffler & grader
│   │   ├── ratelimit.js      # In-memory sliding window rate limiter
│   │   ├── schema.sql        # Idempotent PostgreSQL DDL migrations
│   │   ├── seed.js           # Initial admin and demo participant seeder
│   │   ├── server.js         # Standalone HTTP server & route multiplexer
│   │   └── store.js          # In-memory store mirror for dev/testing
│   ├── test/                 # Automated test suite (87 tests)
│   │   ├── admin-creds.test.js
│   │   ├── anticheat.test.js
│   │   ├── audit-fixes.test.js
│   │   ├── auth.test.js
│   │   ├── exam.test.js
│   │   ├── persistence.test.js
│   │   ├── serverless-entry.test.js
│   │   └── submit.test.js
│   └── loadtest.js           # Concurrency and atomic race load testing script
├── package.json              # Root npm scripts & workspace configuration
└── vercel.json               # Vercel build & routing configuration
```

---

## Getting Started

### 1. Prerequisites
- Node.js ≥22.0.0
- npm ≥10.0.0

### 2. Installation
Clone the repository and install dependencies:
```sh
npm install
```

### 3. Environment Configuration
Copy `.env.example` to `.env` or `server/.env`:
```sh
cp .env.example server/.env
```

Key environment variables:
| Variable | Description | Default |
|---|---|---|
| `NODE_ENV` | Mode (`development` or `production`) | `development` |
| `JWT_SECRET` | 32+ character random secret for JWT signing | Required in production |
| `DATABASE_URL` / `POSTGRES_URL` | PostgreSQL connection string (Supabase) | Falls back to in-memory store in dev |
| `POSTGRES_URL_NON_POOLING` | Direct connection string for DDL migrations | Optional |
| `PORT` | Local server port | `3000` |
| `COOKIE_SECURE` | Set `false` for local HTTP testing | `true` in production |
| `BLUR_THRESHOLD` | Number of violation strikes before auto-submit | `1` |
| `BLUR_CONSEQUENCE` | Consequence on violation (`auto_submit`, `flag_for_review`) | `auto_submit` |
| `EXAM_DURATION_SEC` | Exam duration in seconds | `3600` (60 min) |
| `GRACE_SEC` | Network grace buffer after timeout | `5` |

### 4. Running Locally
Start the development server on `http://localhost:3000`:
```sh
npm start
```
Or run with auto-reload:
```sh
npm run dev
```

### 5. Running Tests
Run the entire 87-test automated test suite:
```sh
npm test
```

Run the concurrency load test:
```sh
npm run loadtest
```

---

## Deployment (Vercel + Supabase)

1. **Connect Repository / Directory** to Vercel:
   ```sh
   npx vercel
   ```
2. **Configure Environment Variables** in Vercel Dashboard:
   - `JWT_SECRET`: Random 32+ character hex string.
   - `POSTGRES_URL`: Supabase Transaction Pooler URL (port 6543).
   - `POSTGRES_URL_NON_POOLING`: Supabase Direct URL (port 5432).
   - `BLUR_THRESHOLD`: `1`
   - `BLUR_CONSEQUENCE`: `auto_submit`
   - `SEED_ADMIN_USER` & `SEED_ADMIN_PASS`: Initial admin credentials.
3. **Deploy to Production**:
   ```sh
   npm run deploy:prod
   ```
   Or:
   ```sh
   npx vercel --prod
   ```

---

## Security & Architectural Notes

- **CSRF Protection**: All state-changing endpoints (`POST`, `PATCH`, `PUT`, `DELETE`) require the custom header `x-requested-with`.
- **Session Exclusivity**: A single active session ID (`sid`) is tracked in PostgreSQL. If a participant attempts a concurrent login, old sessions are invalidated immediately (`session_superseded`).
- **Atomic CAS Transitions**: Exam submissions use SQL `UPDATE ... WHERE status = 'IN_PROGRESS'` to ensure that concurrent submissions, manual clicks, sweeps, and auto-submits grade exactly once.
- **Fail-Closed Timing**: Expiry is evaluated on every read/write using the server clock. Tampering with the client clock has zero effect on the authoritative deadline.
