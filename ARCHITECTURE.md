# Architecture

Detail lives in [competition-system-plan-v2.md](competition-system-plan-v2.md) §1–4. This is the map, not the territory.

## Shape

```
[Participant Client] --> /login       --> /api/auth/participant/login --> JWT cookie (role: participant)
[Admin Client]       --> /admin/login --> /api/auth/admin/login       --> JWT cookie (role: admin)

[Participant JWT] --> /api/exam/*   (middleware: role must be participant, session must match active_session_id, exam not expired)
[Admin JWT]       --> /api/admin/*  (middleware: role must be admin)

Both --> Question Service --> DB   (correct_option_id stripped at serialization layer)
Sweep worker (15–30s) --> auto-submits expired IN_PROGRESS sessions
```

App server is stateless; all exam state lives in the DB (replicated/managed — never SQLite on the app box).

## Data model

```
participants:   id, username, password_hash, competition_id, is_active, active_session_id
admins:         id, username, password_hash, role
questions:      id, subject (C|PYTHON), code_snippet?, prompt, options[4], correct_option_id
exam_sessions:  participant_id (unique), status, exam_started_at, shuffle_seed, submitted_at
responses:      (participant_id, question_id) unique, option_id, answered, flagged (orthogonal — a question can be both)
violations:     participant_id, type (tab_blur|session_takeover|rate_flood), timestamp
```

## State machine

`NOT_STARTED → IN_PROGRESS → SUBMITTED → LOCKED` — one-way. Every write checks status AND expiry first. Submit and sweep race safely via atomic `UPDATE ... WHERE status = 'IN_PROGRESS'` (plan §4.3).

## Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/auth/participant/login` | — | 5/min/IP, issues cookie + active_session_id |
| `POST /api/auth/admin/login` | — | stricter limit |
| `GET /api/exam/questions` | participant | shuffled by seed, no correct_option_id |
| `PATCH /api/exam/answer` | participant | debounced upsert on (participant, question) |
| `POST /api/exam/event` | participant | rate-limited, overflow coalesced |
| `POST /api/exam/submit` | participant | atomic CAS, returns `{status, timestamp}` only |
| `GET /api/admin/results/:participantId` | admin | scores live here only; inside the guarded `/api/admin/*` prefix |
