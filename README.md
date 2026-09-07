# GreenBuck

**Timing Side-Channel Analysis of Encrypted Mobile Application Traffic**

A security-research project investigating whether TLS encryption alone conceals user behavior. Even when traffic is encrypted, a passive network observer can still see the size and timing of each request. This project measures whether that leftover metadata is enough to classify user actions in an encrypted mobile finance app — without decrypting anything — and evaluates how well common server-side defenses reduce that leakage and at what cost.

**Status:** In active development

---

## Overview

- **Client:** Flutter (Dart) mobile app — six screens, real authentication, all traffic over TLS.
- **Backend:** FastAPI (Python) — six endpoints, Argon2id password hashing, JWT auth, role-based access (admin/user). Two middleware layers instrument every request: one logs timing metadata, one applies configurable traffic-shaping defenses.
- **Database:** PostgreSQL (users, transactions, timing_log).
- **Capture rig:** Runs on a Raspberry Pi 5. A Python orchestrator starts tcpdump, triggers a user action via a Flutter integration test, stops the capture, and links each trace to its server-side timing record by request ID.
- **Analysis:** Offline feature extraction and classification (Random Forest, k-NN).

The backend, database, and capture point are co-located on the Pi to keep the single measured network hop clean. This is a controlled research testbed, not a production finance app.

---

## Repository Structure

```
Greenbuck/                  (repo root — the Flutter app lives here)
├── lib/                    Flutter client source (screens, services, models)
├── integration_test/       Integration tests that drive captured actions
├── pubspec.yaml            Flutter dependencies
├── api/                    FastAPI backend
│   ├── main.py
│   ├── requirements.txt
│   ├── schema.sql
│   └── run.sh.example
├── capture/                Capture orchestration
│   ├── run_capture.py      Runs one capture end to end
│   └── data/               Captured pcaps + markers.jsonl (gitignored)
├── .env.example            Template for environment variables
└── README.md
```

---

## Setting Up Your Own Instance

You do **not** need a Raspberry Pi to develop the app and backend. You run your
own local copy of the backend and database for development. A Raspberry Pi (or a
comparable dedicated Linux host) is only needed to reproduce the actual capture
and data-collection setup.

### Prerequisites
- Python 3.11+
- PostgreSQL
- Flutter SDK (with Android Studio + an emulator, or a physical Android device)
- Git

### Backend Setup

1. **Clone the repo and enter the backend folder:**
   ```
   git clone https://github.com/SpeerGabe/Greenbuck.git
   cd Greenbuck/api
   ```

2. **Create and activate a virtual environment:**
   ```
   python -m venv venv
   source venv/bin/activate        # macOS/Linux
   venv\Scripts\activate           # Windows
   ```

3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

4. **Create the database and the database user, then load the schema.**
   In `psql` (as a superuser):
   ```sql
   CREATE DATABASE greenbuck;
   CREATE USER greenbuck_user WITH PASSWORD 'choose-a-password';
   ```
   Then load the schema:
   ```
   psql greenbuck < schema.sql
   ```
   (The schema grants table access to `greenbuck_user`, so that user must exist first.)

5. **Provide the backend's secrets.** The backend reads `SECRET_KEY`, `DB_USER`,
   and `DB_PASSWORD` from the environment — they are never hardcoded. There are
   two equivalent ways to set them:

   - **Using a `.env` file (recommended if you have internet):** install
     `python-dotenv` (`pip install python-dotenv`), copy `../.env.example` to a
     `.env` file, and fill in your values. The backend loads it automatically.
   - **Using a shell script (works offline, no extra package):** copy the
     included template and edit it:
     ```
     cp run.sh.example run.sh
     ```
     Set in `run.sh`:
     - `SECRET_KEY` — any long random string
       (generate one with `python -c "import secrets; print(secrets.token_hex(32))"`)
     - `DB_USER` — `greenbuck_user`
     - `DB_PASSWORD` — the password you chose above

   Both `.env` and `run.sh` hold secrets and are gitignored — never commit them.

6. **Run the backend:**
   ```
   chmod +x run.sh
   ./run.sh
   ```
   (Or, if using a `.env` file, launch uvicorn directly:
   `uvicorn main:app --host 0.0.0.0 --port 8000`.)

   For local development you can run without TLS by removing the
   `--ssl-keyfile`/`--ssl-certfile` flags (the TLS certificates are not included
   in the repo — they are specific to the research Pi). Without those flags the
   server runs on plain HTTP, which is fine for app development.

### Frontend Setup

Run these from the repository root (the Flutter app is at the root, not in a
subfolder).

1. **Get dependencies:**
   ```
   cd Greenbuck
   flutter pub get
   ```

2. **Point the app at your backend.** In `lib/services/api_service.dart`, set
   `baseUrl` to your machine's address:
   - Android emulator reaching your computer's localhost: `http://10.0.2.2:8000`
   - Physical device on the same network: `http://<your-computer-LAN-IP>:8000`
   - (If your backend runs without TLS for local dev, use `http://`, not `https://`.)

3. **Run the app:**
   ```
   flutter run
   ```

### Creating a User

The database starts empty. Open the app, tap **Create Account** to register, then
log in with those credentials. Admin accounts are assigned manually in the database:
```sql
UPDATE users SET role = 'admin' WHERE username = 'your-username';
```

### Running Captures (Data Collection)

Captures run from your dev machine and require a reachable Raspberry Pi running
the backend. The orchestrator starts tcpdump on the Pi, triggers a user action
through the Flutter integration test, stops the capture, and pulls the resulting
`.pcap` back to your machine.

1. **Set the Pi connection details.** Copy `.env.example` to `.env` at the repo
   root and fill in your Pi's details:
   ```
   PI_HOST=your-pi-ip
   PI_USER=your-pi-username
   PI_PASS=your-pi-password
   PI_INTERFACE=eth0
   ```
   (`run_capture.py` loads these via `python-dotenv`; the real `.env` is gitignored.)

2. **Run a capture.** With the backend running on the Pi and an Android emulator
   (or device) active:
   ```
   python capture/run_capture.py --action check_balance --platform android --encryption none --mitigation none --run 1
   ```

Captured `.pcap` files and the `markers.jsonl` log are written to `capture/data/`,
which is gitignored — raw capture data is not committed.

---

## Research Design

- **Actions (6):** login, logout, register, view history, make transfer, check balance
- **Mitigations:** none (control), and defenses grouped by class —
  packet-level padding vs. random padding (size), batching vs. constant-rate
  response (timing).
  *(Planned design. The current capture code implements an earlier mitigation set
  — response padding, jitter, and constant-rate — and is being extended to the
  class-based set above.)*
- **Encryption:** multiple field-level cipher configurations (AES-GCM,
  ChaCha20-Poly1305, AES-256-CBC), treated as a controlled variable. *(The
  field-level encryption layer is in active development; the capture tool accepts
  these options now.)*
- **Analysis:** supervised classification (Random Forest, k-NN) on features
  extracted from captured traffic
- **Primary result:** a privacy-utility tradeoff curve — each mitigation's
  overhead vs. the classification accuracy it prevents

---

## Team

- **Gabriel Speer** — security architecture, threat model, mitigations, data analysis
- **Jose Hipolito** — encryption implementation and backend/application development

---

