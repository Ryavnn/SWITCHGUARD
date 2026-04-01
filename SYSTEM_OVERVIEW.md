# SwitchGuard Security Platform — System Overview

> A locally-hosted vulnerability assessment system that orchestrates Nmap and OWASP ZAP
> scans through a FastAPI backend, stores results in PostgreSQL, and presents them
> through a React dashboard.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Folder Structure](#2-folder-structure)
3. [Backend — FastAPI](#3-backend--fastapi)
4. [Database — PostgreSQL](#4-database--postgresql)
5. [Scanning Engines](#5-scanning-engines)
6. [Frontend — React](#6-frontend--react)
7. [Data Flow: End-to-End Scan Lifecycle](#7-data-flow-end-to-end-scan-lifecycle)
8. [API Reference](#8-api-reference)
9. [Configuration & Environment Variables](#9-configuration--environment-variables)
10. [How to Run the System](#10-how-to-run-the-system)

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  User's Web Browser                     │
│          React Frontend  (localhost:3000)                │
└────────────────────────┬────────────────────────────────┘
                         │  HTTP/REST (Axios)
                         ▼
┌─────────────────────────────────────────────────────────┐
│            FastAPI Backend  (localhost:8000)             │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────┐  │
│  │  API Routes │   │ BackgroundTasks│  │   Parsers   │  │
│  └──────┬──────┘   └──────┬───────┘   └──────┬──────┘  │
│         │                 │                   │         │
└─────────┼─────────────────┼───────────────────┼─────────┘
          │                 │                   │
          ▼                 ▼                   ▼
   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
   │ PostgreSQL  │   │    Nmap     │   │  OWASP ZAP  │
   │ (Port 5432) │   │  CLI Tool   │   │ (Port 8080) │
   └─────────────┘   └─────────────┘   └─────────────┘
```

---

## 2. Folder Structure

```
switchguard/
├── backend/                        # Python FastAPI application
│   ├── main.py                     # App entry point, all API routes
│   ├── worker.py                   # Celery worker configuration (optional)
│   ├── requirements.txt            # Python dependencies
│   ├── .env                        # Secrets & connection strings
│   │
│   ├── database/
│   │   ├── db.py                   # SQLAlchemy engine & session factory
│   │   └── models.py               # ORM table definitions
│   │
│   ├── scanners/
│   │   ├── nmap_scanner.py         # Nmap scan wrapper (python-nmap)
│   │   └── zap_scanner.py          # OWASP ZAP API wrapper
│   │
│   └── services/
│       └── parsers.py              # Parses raw scan output → DB records
│
├── frontend/                       # React single-page application
│   ├── .env                        # REACT_APP_API_URL config
│   ├── public/
│   └── src/
│       ├── App.js                  # Router + layout shell
│       ├── App.css                 # Full design system (tokens, components)
│       ├── index.css               # Minimal reset
│       │
│       ├── components/
│       │   └── Navigation.js       # Fixed sidebar with active route detection
│       │
│       └── pages/
│           ├── Dashboard.js        # Overview: stats, charts, engine status
│           ├── Scanner.js          # New scan form
│           ├── History.js          # Scan archive table with filters
│           └── ScanDetails.js      # Full report: ports / vulnerabilities
│
├── SYSTEM_OVERVIEW.md              # This file
└── docker-compose.yml              # Legacy (no longer used)
```

---

## 3. Backend — FastAPI

**File:** `backend/main.py`

The backend is a Python FastAPI application run via Uvicorn. It handles:

### Startup
- Loads environment variables from `.env` via `python-dotenv`
- Calls `models.Base.metadata.create_all(bind=engine)` to auto-create all database tables on first boot
- Registers `CORSMiddleware` to allow requests from `http://localhost:3000`

### API Routes

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Health check |
| `POST` | `/api/scan/network` | Start Nmap network scan |
| `POST` | `/api/scan/web` | Start OWASP ZAP web scan |
| `GET` | `/api/jobs` | List all scan jobs (lightweight — no raw_results) |
| `GET` | `/api/jobs/{job_id}` | Get full job details + assets + vulnerabilities |

### Background Task Pattern

When a scan is requested, the API immediately:
1. Creates a `ScanJob` record in the database with `status = "running"`
2. Returns `{ "job_id": "..." }` to the frontend instantly (non-blocking)
3. Enqueues a `task_wrapper` function via FastAPI `BackgroundTasks`

The `task_wrapper` runs the actual scan (which can take minutes), then:
- Saves `raw_results` (JSON string) to the `ScanJob` record
- Calls the appropriate parser to extract structured records
- Sets `status = "completed"` (or `"failed"` on error)

---

## 4. Database — PostgreSQL

**Files:** `backend/database/db.py`, `backend/database/models.py`

### Connection
- Engine created from `DATABASE_URL` env variable (e.g. `postgresql://postgres:password@localhost:5432/switchguard`)
- `SessionLocal` is a `sessionmaker` factory used to create per-request sessions
- Background tasks use `with SessionLocal() as session:` (context-managed, auto-closes)

### Schema

```
scan_jobs
  ├── job_id       PK  String (UUID)
  ├── target           String
  ├── status           String  (running | completed | failed)
  ├── scan_type        String  (network | web)
  ├── created_at       DateTime
  └── raw_results      Text (JSON string from scanner)

assets
  ├── asset_id     PK  String (UUID)
  ├── job_id       FK → scan_jobs.job_id
  ├── ip_address       String
  ├── hostname         String
  └── os_detected      String

services
  ├── service_id   PK  String (UUID)
  ├── asset_id     FK → assets.asset_id
  ├── port             Integer
  ├── protocol         String
  ├── service_name     String
  ├── state            String
  └── version          String

vulnerabilities
  ├── vuln_id      PK  String (UUID)
  ├── job_id       FK → scan_jobs.job_id
  ├── title            String
  ├── description      Text
  ├── severity         String  (High | Medium | Low | Informational)
  ├── risk_score       Float
  ├── evidence         Text
  ├── url              String
  └── solution         String
```

---

## 5. Scanning Engines

### Nmap (`backend/scanners/nmap_scanner.py`)
- Uses the `python-nmap` library which wraps the local Nmap CLI binary
- Installed at: `C:\Program Files (x86)\Nmap\nmap.exe`
- Default scan arguments: `-sV -O -F` (service version detection, OS fingerprint, fast scan)
- Returns a structured Python dict (`nmap.PortScannerResult`) which is JSON-serialized and stored

**Parsed into:** `assets` and `services` tables via `parsers.parse_nmap_results()`

---

### OWASP ZAP (`backend/scanners/zap_scanner.py`)
- Uses the `python-owasp-zap-v2.4` library to communicate with the ZAP Desktop GUI's REST API
- ZAP must be running locally and its API must be enabled with an API key
- Configured via `ZAP_URL` env variable (default: `http://127.0.0.1:8080`)
- The scanner runs two phases:
  1. **Spider** — crawls all accessible URLs on the target site
  2. **Active Scan** — attacks discovered endpoints with known exploit payloads

**Parsed into:** `vulnerabilities` table via `parsers.parse_zap_results()`

---

## 6. Frontend — React

**Directory:** `frontend/src/`

The React SPA uses React Router for client-side navigation and Axios for HTTP calls. It reads the backend URL from `process.env.REACT_APP_API_URL` (set in `frontend/.env`).

### Pages

| Page | Route | Description |
|------|-------|-------------|
| `Dashboard.js` | `/` | 4 stat cards (total/completed/running/failed), donut pie chart, engine status panel, recent activity table |
| `Scanner.js` | `/scan` | Visual scan type selector, target input, live launch button with spinner, success/error feedback |
| `History.js` | `/history` | Filterable archive table (All / Network / Web / Completed / Failed); click any row to open report |
| `ScanDetails.js` | `/scan/:id` | Full report with hero summary, Nmap port table or ZAP vuln cards, collapsible raw JSON output |

### Design System (`App.css`)
- ~800 lines of pure CSS (no Bootstrap or Tailwind)
- CSS custom property tokens for all colors, shadows, and radii
- Switchable between dark and light mode by changing the `:root` variables
- Components: `.sg-card`, `.sg-stat-card`, `.sg-table`, `.sg-btn`, `.sg-status`, `.sg-type-badge`, `.vuln-card`, `.sg-port-table`, `.sg-hero`, `.sg-sidebar`

---

## 7. Data Flow: End-to-End Scan Lifecycle

```
User fills in target + picks scan type
        │
        ▼
React POSTs to /api/scan/network or /api/scan/web
        │
        ▼
FastAPI creates ScanJob (status: "running") → returns job_id instantly
        │
        ├─────────────────────────────────────────────────────┐
        │  (Background Thread)                                │
        │                                                     ▼
        │         NmapScanner.run_scan(target)         ZapScanner.run_spider()
        │                  │                                  │
        │                  ▼                                  ▼
        │         Raw scan dict/list               ZapScanner.run_active_scan()
        │                  │                                  │
        │                  ▼                                  ▼
        │         json.dumps() → raw_results       json.dumps() → raw_results
        │                  │                                  │
        │                  ▼                                  ▼
        │         parse_nmap_results()             parse_zap_results()
        │         → assets + services              → vulnerabilities
        │                  │                                  │
        │                  └──────────────┬───────────────────┘
        │                                 ▼
        │                  ScanJob.status = "completed"
        │                  session.commit()
        │
        ▼
React polls /api/jobs every ~5s (via History page auto-refresh)
User clicks job row → React fetches /api/jobs/{id}
        │
        ▼
ScanDetails.js parses raw_results + renders report
```

---

## 8. API Reference

### `POST /api/scan/network`
**Body:** `{ "target": "192.168.1.1" }`
**Response:** `{ "message": "Scan started", "job_id": "uuid" }`

### `POST /api/scan/web`
**Body:** `{ "target": "https://example.com" }`
**Response:** `{ "message": "Web Scan started", "job_id": "uuid" }`

### `GET /api/jobs`
Returns a lightweight list of all jobs (**excludes** `raw_results` to prevent payload overload).
```json
[
  { "job_id": "...", "target": "...", "status": "completed", "scan_type": "network", "created_at": "..." }
]
```

### `GET /api/jobs/{job_id}`
Returns full details including assets, vulnerabilities, and raw_results.
```json
{
  "job": { "job_id": "...", "raw_results": "{...}", ... },
  "assets": [ { "ip_address": "...", ... } ],
  "vulnerabilities": [ { "title": "...", "severity": "High", ... } ]
}
```

---

## 9. Configuration & Environment Variables

### `backend/.env`
```env
DATABASE_URL=postgresql://postgres:<password>@localhost:5432/switchguard
CELERY_BROKER_URL=redis://127.0.0.1:6379/0
ZAP_URL=http://127.0.0.1:8080
ZAP_API_KEY=<your-zap-api-key>
```

### `frontend/.env`
```env
REACT_APP_API_URL=http://localhost:8000
```

---

## 10. How to Run the System

### Prerequisites
- Python 3.10+ with a virtualenv
- Node.js 18+ and npm
- PostgreSQL running locally (database `switchguard` must exist)
- Nmap installed (`C:\Program Files (x86)\Nmap\nmap.exe`)
- OWASP ZAP Desktop running with API enabled on port 8080

### Step 1 — Start the Backend
```powershell
cd C:\Users\Admin\Desktop\ian\switchguard\backend
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\python.exe -m uvicorn main:app --reload --host localhost --port 8000
```

### Step 2 — Start the Frontend
```powershell
cd C:\Users\Admin\Desktop\ian\switchguard\frontend
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
npm start
```

### Step 3 — Open the Dashboard
Navigate to **http://localhost:3000** in your browser.

---

> **SwitchGuard v2.0** — Built with FastAPI, PostgreSQL, Nmap, OWASP ZAP, and React.
