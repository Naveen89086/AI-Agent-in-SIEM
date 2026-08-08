# FIM Real Mode — Endpoint Integrity Monitoring

Converts the demo-only FIM (syscheck) module into a real Windows endpoint
integrity monitoring system:

- server-side baseline and deterministic classification (no AI involved in
  integrity decisions; the server is the final authority and never trusts
  client-supplied classification),
- authenticated `POST /api/v1/fim/ingest` from a watchdog-based agent,
- real-event frontend (SHA-256, severity, active/deleted status, rename view),
- full automated tests and a live `C:\FIM-Test` end-to-end acceptance.

SCA and the legacy FIM demo mode are untouched and green.

---

## 1. Architecture

```
Windows endpoint (fim_agent package)
  watchdog observer (watchdog)  +  poll fallback + periodic full scan
      -> content SHA-256, mtime/size/type state, exclude patterns
      -> register (one-time API key) -> heartbeat
      -> POST /api/v1/fim/ingest          (bearer API key, event_id dedupe)
                                                |
                                                v
FastAPI backend (127.0.0.1:8000)
  api/v1/fim: POST /agents/register, /agents/{code}/heartbeat, /ingest
  fim_service: dedupe, server-side classify, baseline upsert (SQLite)
  fim_rules: deterministic severity (FIM-SECURITY-001, FIM-PERSISTENCE-001, ...)
  SyscheckAgent / SyscheckFile / SyscheckEvent models  (alembic migration applied)
                                                |
                                                v
Frontend (Vite/React)
  FIM inventory (SHA-256, status, demo badge) + events tab (severity, rename,
  OLD vs NEW hash detail row, real/demo label)
```

Principles enforced:

- Server is authoritative: the client reports raw facts (path, hashes, mtime),
  the server classifies added/modified/deleted/renamed against its own baseline.
- The server stores only `sha256(api_key)`; the one-time key is returned once
  at registration and never persisted.
- No path traversal, no arbitrary command execution, no whole-`C:\` scanning by
  default, no secrets in source, no silent mock fallback in real mode.

---

## 2. New files

| File | Purpose |
| --- | --- |
| `fim_agent/__init__.py` | Package marker. |
| `fim_agent/config.py` | YAML + env (`FIM_AGENT_*`) + CLI layering; default target `C:\FIM-Test`. |
| `fim_agent/collector.py` | Content SHA-256, mtime/size/type state, exclude patterns, change classification. |
| `fim_agent/baseline.py` | JSON map of `path -> {sha256, size, mtime, file_type}`; scan/diff/load/save. |
| `fim_agent/transport.py` | Stdlib-urllib client for register/heartbeat/ingest. |
| `fim_agent/monitor.py` | Watchdog observer + polling + periodic full scan; `_ChangeQueue`, stable `event_id` from event_type+paths+hashes; heartbeat thread; excludes its own key/baseline state files. |
| `fim_agent/cli.py`, `fim_agent/__main__.py` | `register`, `heartbeat`, `baseline`, `monitor`, `daemon` subcommands. |
| `fim_agent.yaml` | Sample agent config at repo root. |
| `backend/app/schemas/fim.py` | `FimIngestRequest` (event_type literal, SHA-256 regex, control-char/NUL rejection, `event_id` dedupe). |
| `backend/app/services/fim_rules.py` | Deterministic severity engine, extensible via `fim_rules_json`. |
| `backend/app/services/fim_service.py` | Enrollment, heartbeat, ingest, server-side classification, baseline upsert, dedupe. |
| `backend/alembic/versions/20260808_f5d6c7a8b9e2_fim_real_mode.py` | Adaptive migration (applied). |
| `backend/tests/test_fim_real_mode.py` | 17 server tests. |
| `backend/tests/test_fim_agent.py` | 14 agent tests. |
| `docs/02-fim-real-mode.md` | This document. |

Modified: `backend/app/models/syscheck.py`, `backend/app/core/config.py`,
`backend/app/api/v1/fim.py`, `backend/app/services/syscheck_service.py`,
`backend/app/services/endpoint_seed.py`, `backend/requirements.txt`,
`frontend/src/api/client.ts`, `frontend/src/api/endpoint.ts`,
`frontend/src/mocks/fim.ts`, `frontend/src/components/fim/FimInventoryTab.tsx`,
`frontend/src/components/fim/FimEventsTab.tsx`,
`frontend/src/pages/FileIntegrityMonitoringPage.tsx`,
`frontend/src/styles/fim.css`.

---

## 3. Database migration

`20260808_f5d6c7a8b9e2` (down_revision `e9c4b3d2a1f0`) is adaptive: it checks
`_tables` / `_add_column` before each change, so it runs on both existing and
fresh databases. It adds:

- `SyscheckAgent`: `hostname`, `ip_address`, `version`, `api_key_hash`,
  `last_seen`, `enabled`.
- `SyscheckFile`: `sha256`, `first_seen`, `last_seen`, `owner`, `permissions`,
  `file_type`, `status`.
- `SyscheckEvent`: `event_id`, `old_path`, `old_sha256`, `new_sha256`,
  `evidence`, `source`, `severity`, `event_type` now incl. `renamed`.

Demo rows are normalized to `status='active'`. Applied to the live DB via
`alembic upgrade head`.

---

## 4. API endpoints

Legacy GETs unchanged (`/api/v1/fim/agents`, `/files`, `/events`, `/stats`,
`/files/{agent_id}`). New:

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/api/v1/fim/agents/register` | registration token (or admin JWT fallback) | Returns one-time API key; `ConflictError` on duplicate code. |
| POST | `/api/v1/fim/agents/{agent_code}/heartbeat` | API key | Updates `last_seen`, returns server status + enabled flag. |
| POST | `/api/v1/fim/ingest` | API key | Accepts `FimIngestRequest`, dedupes on `event_id`, server-classifies, upserts baseline. |

Classification (server-side, deterministic): a reported `modified` for an
unknown path becomes `added`; an `added` for a known path becomes `modified`; a
`renamed` event is matched against the OLD path in the server baseline; a
`deleted` keeps the history row with `status='deleted'`.

Severity rules (`fim_rules.py`, ordered): `FIM-SECURITY-001` critical,
`FIM-PERSISTENCE-001` critical, `FIM-WIN-SYSTEM32-001` high,
`FIM-EXECUTABLE-001` medium, `FIM-DEFAULT-001` low. Custom rules can be injected
via `settings.fim_rules_json`.

---

## 5. Agent usage

```powershell
# from the repo root (module resolution needs this working directory)
cd "F:\AI-Agent in SIEM Project"

# 1. enroll and get a one-time API key
python -m fim_agent register --agent-code fim-win-live --token <registration-token>

# 2. build the local baseline snapshot
python -m fim_agent baseline --agent-code fim-win-live

# 3. one-shot state check (for cron or testing)
python -m fim_agent monitor --once --agent-code fim-win-live

# 4. continuous watchdog daemon (heartbeat + poll + full scan)
python -m fim_agent daemon --agent-code fim-win-live --log-level INFO
```

Configuration is layered YAML -> env -> CLI (12-factor `FIM_AGENT_*`). The sample
`fim_agent.yaml` monitors `C:\FIM-Test`, excludes `*.tmp`, `~$*`, `*.swp`,
`*.bak`, watchdog on, poll 5s, heartbeat 60s. The agent never reports its own
key/baseline state files. `monitor --once` returns exit code 0 when everything
was accepted.

---

## 6. Verification

- Backend: `backend\.venv\Scripts\python.exe -m pytest -q` -> **251 passed**
  (220 legacy + 17 `test_fim_real_mode` + 14 `test_fim_agent`).
- Frontend: `npm run build` (`tsc -b && vite build`) succeeds.
- Live server: `127.0.0.1:8000` healthy after every restart (uvicorn
  `app.main:app`); alembic head `f5d6c7a8b9e2` applied.

---

## 7. Live acceptance (C:\FIM-Test, agent `fim-win-live`)

Monitored directory was reset to `base.txt` + `watchme.log`, then mutated while
the watchdog monitor was running: create `new-entry.csv`, modify `watchme.log`,
delete `base.txt`, rename `new-entry.csv` -> `entry-renamed.csv`.

Server response (live API, real DB):

```
TOTAL EVENTS: 14
deleted    sev=low  lvl=2  old=  -> C:\FIM-Test\entry-renamed.csv
modified   sev=low  lvl=2  old=  -> C:\FIM-Test\watchme.log
deleted    sev=low  lvl=2  old=  -> C:\FIM-Test\new-entry.csv
deleted    sev=low  lvl=2  old=  -> C:\FIM-Test\base.txt
modified   sev=low  lvl=2  old=  -> C:\FIM-Test\watchme.log
added      sev=low  lvl=2  old=  -> C:\FIM-Test\new-entry.csv
added      sev=low  lvl=2  old=  -> C:\FIM-Test\entry-renamed.csv
added      sev=low  lvl=2  old=  -> C:\FIM-Test\watchme.log
added      sev=low  lvl=2  old=  -> C:\FIM-Test\base.txt
INVENTORY:
deleted   55f04450 C:\FIM-Test\base.txt
deleted   aeb03881 C:\FIM-Test\config.json
deleted   205830ca C:\FIM-Test\entry-renamed.csv
deleted   205830ca C:\FIM-Test\new-entry.csv
active    60e639cf C:\FIM-Test\watchme.log
```

Evidence: watchdog events for add/modify/delete/rename were delivered with
authenticated ingest (accepted=True), the server reclassified `modified`->`added`
where it had no prior baseline and recorded subsequent `modified`, `deleted` rows
were kept with `status='deleted'`, and every event carries a SHA-256 and a
deterministic severity. All four event types plus the active/deleted inventory
states were reproduced live.
