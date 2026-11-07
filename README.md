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
Settings in `backend/.env` are loaded automatically (python-dotenv).

## 5. Demo users (password `Passw0rd!`)
| user | role | dept | notes |
|---|---|---|---|
| alice | user | Engineering | clearance 2, works 9-17 Mon-Fri |
| bob | user | Finance | clearance 3, works 9-17 Mon-Fri |
| devuser | user | Engineering | clearance 3, allowed any hour/day (easiest for demos) |
| manager, admin2 | admin | Management / Engineering | MFA always required, can freeze users and approve dual-auth |
| superadmin | superuser | Management | same as admin |

## 6. Things to demo
- Fig 6.1: log in as `manager`, scan the QR with Google Authenticator, enter the code.
- Fig 6.4: threat simulator, "Blacklisted IP", log in, see "Access Blocked: CRITICAL".
- Impossible travel: log in normally once, then log in with the "Impossible travel (US)" scenario.
- New device: log in as alice, switch Device to "Personal Phone", log in again, expect MFA.
- Fig 6.3: log in as `devuser`, press Request Access on Quarterly Budget (Finance) 5 times: 60s lockout and forced logout.
- Fig 6.2: log in as `manager`, Admin Oversight tab: stats, freeze/unfreeze, dual-auth queue (request Source Code Vault as manager, approve it as admin2).
- Wrong password 5 times: 15-minute lockout.

## 7. Architecture
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
- `ENABLE_SIMULATION=1` lets clients fake IP/country/device via headers (demo only). The server refuses to start with the default `SECRET_KEY` when simulation is off.
- The ML models are trained on synthetic data (as in the report).
- Self-registered users get clearance 1; raise it with `PATCH /api/admin/users/{id}/attributes`.

## 10. From demo to real signals
Set `ENABLE_SIMULATION=0` and a long random `SECRET_KEY` in `backend/.env`. Then:

| Signal | How it works in real mode |
|---|---|
| Client IP | Real socket address. Behind a reverse proxy set `TRUSTED_PROXIES` (IPs/CIDRs); `X-Forwarded-For` is then read safely (right-most untrusted hop). |
| Country / impossible travel | Local GeoLite2 database if present, else an HTTPS lookup (cached). |
| Managed device | An admin generates a one-time code (Admin Oversight > Managed devices). The user enrolls the browser from the login screen (needs password + code) and receives a signed device token. Header claims are ignored; admins can revoke devices. |
| IP blacklist | Edit it live in the admin dashboard (IPs or CIDR ranges), plus optional `BLACKLISTED_IPS` in `.env`. |
| Credential stuffing | 10 failed logins from one IP (any usernames) in 10 minutes returns 429 (localhost exempt). |

**GeoLite2 setup (free):** create an account at maxmind.com, download "GeoLite2 Country" (mmdb), and save it as `backend/geoip/GeoLite2-Country.mmdb`.
**Testing real mode on one machine:** your own requests always come from `127.0.0.1`, so country-based checks need real traffic. Deploy it, or expose it with a tunnel (Cloudflare Tunnel / ngrok, and add the tunnel's address to `TRUSTED_PROXIES`).
**Still prototype-level:** the failed-login tracker is in memory (use Redis with several workers), the blacklist has no live threat-intel feed, and the ML data is synthetic.

## 9. Push to GitHub straight away
```bash
git init && git add . && git commit -m "Rebuild adaptive access control system"
git branch -M main
git remote add origin https://github.com/<your-username>/adaptive-access-control.git
git push -u origin main
```
