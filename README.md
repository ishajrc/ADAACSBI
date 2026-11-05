# AI-Driven Adaptive Access Control System with Behavior Intelligence

FastAPI + React + PostgreSQL/SQLite + MongoDB + scikit-learn. Rebuilt from the Phase II project report.

## 1. Prerequisites
Python 3.10+, Node.js 18+, Git. (Docker is optional, for real PostgreSQL and MongoDB.)

## 2. Run the backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate      Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
python test_flow.py            # optional smoke test (all checks should pass)
uvicorn app.main:app --reload --port 8000
```
First start trains the ML models (about 10 seconds) and seeds demo users. API docs: http://127.0.0.1:8000/docs

## 3. Run the frontend (new terminal)
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:3005

## 4. Optional: PostgreSQL + MongoDB
```bash
docker compose up -d
cp backend/.env.example backend/.env   # then uncomment the PostgreSQL DATABASE_URL line
```
Without Docker the app uses SQLite and writes the audit log to `audit_log.jsonl`.
To load `.env` automatically, run `pip install python-dotenv` and add `from dotenv import load_dotenv; load_dotenv()` at the top of `app/config.py`,
or set the variables in your shell.

## 5. Demo users (password `Passw0rd!`)
| user | role | dept | notes |
|---|---|---|---|
| alice | user | Engineering | clearance 2, works 9-17 Mon-Fri |
| bob | user | Finance | clearance 3, works 9-17 Mon-Fri |
| devuser | user | Engineering | clearance 3, allowed any hour/day (easiest for demos) |
| manager, admin2 | admin | Management / Engineering | MFA always required, can freeze users and approve dual-auth |
| superadmin | superuser | Management | same as admin |

## 6. Things to demo (maps to the report's figures)
- Fig 6.1: log in as `manager`, scan the QR with Google Authenticator, enter the code.
- Fig 6.4: threat simulator, "Blacklisted IP", log in, see "Access Blocked: CRITICAL".
- Impossible travel: log in normally once, then log in with the "Impossible travel (US)" scenario.
- New device: log in as alice, switch Device to "Personal Phone", log in again, expect MFA.
- Fig 6.3: log in as `devuser`, press Request Access on Quarterly Budget (Finance) 5 times: 60s lockout and forced logout.
- Fig 6.2: log in as `manager`, Admin Oversight tab: stats, freeze/unfreeze, dual-auth queue (request Source Code Vault as manager, approve it as admin2).
- Wrong password 5 times: 15-minute lockout.

## 7. Architecture (report chapter 3 and 5)
```
backend/app/
  config.py    thresholds, blacklist, resources        security.py  Argon2, JWT, TOTP, QR
  models.py    User (ABAC + risk fields), AccessRequest  risk.py      basic + advanced login risk
  abac.py      the 6 ABAC rules                        ml.py        LogReg + DecisionTree + IsolationForest vote
  context.py   IP, geo, device fingerprint, time       audit.py     MongoDB logging with file fallback, masking
  deps.py      auth dependencies                       main.py      all API routes
```
Login: password (Argon2) -> basic risk -> advanced risk -> ALLOW / MFA / BLOCK.
Resource access: adaptive rate limit -> ABAC rules 1-6 -> ML anomaly vote -> GRANTED/DENIED, 5 violations = 60s lockout + session kill.

## 8. Security notes
- `ENABLE_SIMULATION=1` lets clients fake IP/country via headers. Set it to 0 outside demos.
- Set a real `SECRET_KEY`. The ML models are trained on synthetic data (as in the report).
- Self-registered users get clearance 1; raise it with `PATCH /api/admin/users/{id}/attributes`.

## 9. Push to GitHub straight away
```bash
git init && git add . && git commit -m "Rebuild adaptive access control system"
git branch -M main
git remote add origin https://github.com/<your-username>/adaptive-access-control.git
git push -u origin main
```
