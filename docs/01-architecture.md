# SIEM Platform — Architecture

**AI Agent-Enhanced Endpoint SIEM** for real-time threat detection, automated
incident response, and compliance reporting. Built entirely from scratch on an
industry-standard architecture.

---

## 1. High-Level Overview

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                        SIEM PLATFORM                        │
                    │                                                             │
  Endpoints         │   ┌──────────┐   ┌────────────┐   ┌────────────┐            │
 ┌──────────┐       │   │  1. Log  │   │  2. Normal │   │  3. Correl │            │
 │ Sysmon   │───────┼──►│ Collect   │──►│   & Parse  │──►│    ate     │            │
 │ auditd   │       │   │ (agents, │   │ (Grok/ECS) │   │ (Sigma)    │            │
 │ Firewall │ syslog│   │  syslog, │   └────────────┘   └─────┬──────┘            │
 │ Web srv  │ HTTP  │   │  HTTP)   │                         │                   │
 └──────────┘       │   └──────────┘                         ▼                   │
                    │      Event Bus (Redis Streams)   ┌──────────────┐           │
                    │       ▲        │                 │ 4/5. Detect │           │
                    │       │        │                 │ Sigma+YARA  │           │
                    │       │        │                 │ +ML anomaly │           │
                    │   Log Store ───┴──► Elasticsearch│              │           │
                    │   (ILM)            (raw+norm.)   └──────┬───────┘           │
                    │                                        ▼                   │
                    │   ┌─────────┐   ┌────────────┐   ┌─────────────┐            │
                    │   │  6. AI  │◄──┤ 6. Alert   │◄──┤             │            │
                    │   │  Agent  │   │  (dedup,   │   │             │            │
                    │   │ (SOC    │   │ severity,  │   │             │            │
                    │   │ analyst)│   │ notify)    │   │             │            │
                    │   └────┬────┘   └─────┬──────┘   │             │            │
                    │        ▼             ▼           ▼             │            │
                    │   ┌──────────────────────────────────┐          │            │
                    │   │  FastAPI REST API  (modules 7-12) │          │            │
                    │   │  Dashboards • Search/Investigate  │          │            │
                    │   │  Cases • Reports • SOAR • Retention│         │            │
                    │   └───────▲──────────────────▲────────┘          │            │
                    │           │                  │                    │            │
                    │   ┌───────┴─────┐    ┌───────┴──────┐            │            │
                    │   │ React       │    │ Compliance   │            │            │
                    │   │ Dashboard   │    │ Reporting    │            │            │
                    │   └─────────────┘    └──────────────┘            │            │
                    └─────────────────────────────────────────────────────────────┘
```

## 2. The 10 Core SIEM Functions → Modules

| # | Core Function            | Module | Primary Implementation |
|---|--------------------------|--------|------------------------|
| 1 | Log Collection            | M1     | Syslog receiver, HTTP collector, file tailer, endpoint agents → Redis Streams |
| 2 | Normalization & Parsing   | M2     | Grok-style pattern engine, ECS-aligned output |
| 3 | Event Correlation         | M3     | Sigma-format YAML rules with time windows |
| 4 | Real-Time Monitoring & Alerting | M5 | Alert lifecycle, dedup, severity, webhook/email |
| 5 | Threat Detection          | M4     | Sigma rules + YARA + Isolation Forest / K-means anomaly |
| 6 | Dashboards & Visualization | M8     | React dashboard over REST + ES aggregations |
| 7 | Investigation & Forensics | M9     | Full-text search, timelines, case management |
| 8 | Compliance Reporting      | M10    | NIST CSF / CIS / GDPR / HIPAA templates (HTML/PDF) |
| 9 | Log Retention & Storage   | M11    | Elasticsearch ILM lifecycle + snapshot backup |
| 10| Automated Response (SOAR)| M12    | YAML playbook engine, actions, webhooks, audit |

Plus the **AI Agent** (M6) and the platform foundation (M0), REST API layer
(M7) and demo/E2E/hardening (M13).

**Implementation status:** M0–M13 all implemented.

- M0 (foundation) ✅, M1 (log collection) ✅, M2 (normalization) ✅, M3
  (correlation) ✅, M4 (threat detection) ✅, M5 (alerting) ✅, M6 (AI
  agent) ✅, M7 (REST API layer) ✅, M8 (React dashboard) ✅, M9
  (investigation & forensics) ✅, M10 (compliance reporting) ✅, M11
  (retention & storage) ✅, M12 (automated response / SOAR) ✅, M13 (demo
  data, E2E, hardening) ✅.
- **144 passing tests**, including a full integration test that pushes raw
  events through the real pipeline and asserts the complete chain:
  raw → normalize → detect → alert → AI analysis → case → SOAR playbook.
- M8 frontend: Vite + React + TypeScript + Recharts app in `frontend/`
  (dark Splunk/Wazuh-style shell with Dashboard, Search, Alerts, Cases,
  Rules, Sources, SOAR and Reports pages), served by nginx in Docker with
  an `/api` proxy to the backend. Backend support: `/api/v1/dashboard/*`
  aggregations (summary, timeseries, top-rules, top-sources, recent-alerts)
  and `/api/v1/rules` (correlation + signature rule listing).

## 2b. REST API Surface (M7)

All HTTP endpoints live under `/api/v1` and are grouped by module. List
endpoints return a paginated `Page` envelope: `{items, total, offset, limit}`.
Every request carries an `X-Request-Id` (added by middleware) and is logged
with duration.

| Router      | Prefix            | Purpose |
|-------------|-------------------|---------|
| auth        | `/auth`           | Login, token refresh, RBAC user management |
| users       | `/users`          | User CRUD (admin only) |
| ingest      | `/ingest`         | Log collection entry point |
| sources     | `/sources`        | Data source registry + stats |
| alerts      | `/alerts`         | Alert lifecycle, dedup, triage |
| ai          | `/ai`             | Alert analysis, incident summary, chat |
| search      | `/search`         | Full-text + aggregate + histogram |
| cases       | `/cases`          | Investigation case management |
| reports     | `/reports`        | Compliance report generation (HTML/PDF) |
| retention   | `/retention`      | Retention lifecycle + snapshot |
| soar        | `/soar`           | Playbook listing + execution + audit |
| dashboard   | `/dashboard`      | KPI summary, timeseries, top rules/sources (M8) |
| rules       | `/rules`          | Detection rule listing (correlation + signature) |
| meta        | `/meta`           | Capability map + router list |
| health      | `/health`         | Component health (db/bus/store) |

## 2c. M13 — Demo Data & End-to-End Chain

- `backend/app/scripts/demo_data.py` generates realistic syslog / web /
  firewall / Windows events (benign + malicious patterns that trip all
  detection rules) and feeds them through the real pipeline. Run with
  `python -m app.scripts.demo_data --ai --cases --soar` to also run the AI
  agent, create investigation cases and execute SOAR playbooks.
- `tests/integration/test_e2e_chain.py` asserts the full chain end-to-end.

## 2d. Frontend (M8)

- `frontend/` is a Vite + React 18 + TypeScript single-page app styled like a
  commercial SIEM (dark theme, KPI cards, severity donut, trend charts).
- Pages: **Dashboard** (KPIs, severity donut, 7-day events/alerts trend, top
  rules/sources, recent alerts), **Search** (full-text + filters + hourly
  histogram + aggregations), **Alerts** (filter table + AI analysis panel),
  **Cases** (list, notes, artifacts, timeline), **Rules**, **Sources**,
  **SOAR** (playbooks + action audit + safety gate), **Reports** (HTML/PDF
  generation).
- All data comes from the `/api/v1` REST layer via `src/api/client.ts`
  (JWT bearer auth, `/login` route guard in `RequireAuth`). In dev, Vite
  proxies `/api` to `http://127.0.0.1:8000`; in Docker, nginx proxies to the
  `backend` service.
- Backend support added for the UI: `app/services/dashboard_service.py`
  (DB + log-store aggregation), `app/api/v1/dashboard.py` and
  `app/api/v1/rules.py`.

## 3. Technology Stack

| Layer            | Choice (open source) | Notes |
|------------------|----------------------|-------|
| Backend          | Python 3.13, FastAPI | Async REST, OpenAPI docs |
| ORM / DB         | SQLAlchemy 2.0, Alembic | SQLite (dev) / PostgreSQL (prod) |
| Event bus        | Redis 7 Streams      | Pluggable; in-memory bus for tests |
| Log store        | Elasticsearch 8      | Pluggable; local JSON store for dev/tests |
| ML               | scikit-learn         | IsolationForest + KMeans, joblib persistence |
| YARA             | yara (optional)      | Graceful fallback matcher |
| AI agent         | LLM providers (OpenAI/Groq/Ollama) + offline heuristic | Provider abstraction |
| Frontend         | React 18 + Vite + TypeScript + Recharts | |
| Reports          | Jinja2 + fpdf2       | HTML + PDF |
| Containerization | Docker Compose       | ES + Redis + PG + API + worker + frontend |
| Testing          | pytest               | Unit + integration |

## 4. Backend Structure (SOLID)

```
backend/app/
├── core/       config, logging, security, exceptions     (cross-cutting)
├── db/         engine, session, base                      (persistence)
├── models/     SQLAlchemy ORM                             (entities)
├── schemas/    Pydantic DTOs                              (API contracts)
├── api/v1/     Routers + deps (auth/RBAC)                 (presentation)
├── services/   Business logic                             (use cases)
├── ingestion/  Collectors (syslog/http/file)              (function 1)
├── pipeline/   Normalizer, correlator, detectors, bus     (functions 2-5)
├── storage/    LogStore abstraction (ES/local)            (function 9)
├── ai_agent/   Provider abstraction + heuristic + prompts (AI agent)
├── soar/       Playbook engine + actions                  (function 10)
├── reporting/  Compliance report generation               (function 8)
├── rules/      Sigma-style YAML detection rules
└── workers/    Pipeline worker entry points
```

Layering is strict: `api → services → models/storage`. No business logic in
routers; no SQL in services (ORM only); storage and bus behind interfaces so
the system runs against Elasticsearch+Redis in production and lightweight
local/in-memory implementations in dev and tests.

## 5. Key Abstractions

- **EventBus** (`pipeline/bus.py`) — `publish(topic, event)` / `subscribe(topic)`.
  Implementations: `RedisStreamBus`, `InMemoryBus`.
- **LogStore** (`storage/`) — `index_event()`, `search()`, `count()`, `aggregate()`.
  Implementations: `ElasticsearchStore`, `LocalJsonStore`.
- **Detector** — single responsibility per detector (sigma / yara / ml),
  orchestrated by the processor.
- **AIProvider** — `analyze(context) -> AIMarkdown analysis`. Implementations:
  OpenAI-compatible (openai/groq/ollama) and deterministic `HeuristicAnalyzer`.

## 6. Security Model

- JWT (HS256) access tokens; bcrypt password hashing.
- RBAC roles: `admin`, `analyst`, `viewer`.
- Security headers, CORS allowlist, rate limiting.
- Centralized exception handling (RFC 7807 style error bodies).
- Audit logging for sensitive operations.
- No secrets in repo; everything via environment variables.

## 7. Deployment

- **Production-like**: `docker compose up` — Elasticsearch, Redis, PostgreSQL,
  FastAPI (backend), pipeline worker, nginx-served React frontend.
- **Development**: run backend natively (`uvicorn app.main:app`) with
  `EVENT_BUS_URL=inmemory://` and `LOG_STORE_URL=local://` and no external
  services; run frontend with `npm run dev`.

See `docs/03-deployment.md` for full instructions.
