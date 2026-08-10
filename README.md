# Competition System — Preliminary Round

50-question MCQ exam platform (25 C, 25 Python). Dual login (participant/admin), server-enforced timing, answer secrecy, and anti-cheat detection.

## Docs

| File | What it holds |
|---|---|
| [competition-system-plan-v2.md](competition-system-plan-v2.md) | **Single source of truth** — full technical plan |
| [PROJECT_BIBLE.md](PROJECT_BIBLE.md) | Non-negotiables + doc map |
| [PRD.md](PRD.md) | What we're building and for whom |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System shape, data model, endpoints |
| [RULES.md](RULES.md) | Engineering rules every change must obey |
| [TASKS.md](TASKS.md) | Build order (checklist of record) |
| [GUIDE.md](GUIDE.md) | Each task linked to the spec that defines its "done" |
| [DECISIONS.md](DECISIONS.md) | Decision log (what we chose and why) |
| [MEMORY.md](MEMORY.md) | Session context for AI-assisted work |

## Status

Planning complete (plan v2, post council review). Stack chosen (DECISIONS.md). **Phase 1 (auth & session) built** under `server/`. Phases 2–5 pending.

## Stack

Node ≥22, stdlib only (`node:http`, `node:crypto`, `node:test`) — no runtime dependencies. Postgres in production (`server/src/schema.sql`); an in-memory store mirror (`server/src/store.js`) backs dev and tests so it runs on `node` alone.

## Quickstart

```sh
cd server
JWT_SECRET=dev-secret node --test        # run Phase 1 tests
JWT_SECRET=dev-secret npm start           # boot the auth server on :3000
```

Secrets come from env (RULES #7). `npm start` loads `server/.env` via Node's `--env-file-if-exists=.env` (Node ≥22) — copy `.env.example` to `server/.env` and fill it in, or skip the file and export vars in the shell instead (shell exports win over `.env` values, and the flag is a no-op when the file is absent). Required in production: `JWT_SECRET`. Optional tunables in `server/src/config.js` (exam duration, grace, rate limits, lockout, seed creds). For local http, `COOKIE_SECURE=false` drops the Secure flag; production always sets it.
