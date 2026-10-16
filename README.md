# ScamShield-AI

AI-powered scam message and phishing URL detection — Hackathon Day 1 release.

## Project Status (Day 1)

| Area | Status |
|---|---|
| Backend (FastAPI, rule-based engine) | ✅ Complete |
| Frontend (React + TypeScript + Vite) | ✅ Complete |
| Backend unit tests | ✅ 34/34 passing |
| Synthetic evaluation benchmark | ✅ 45/45 passing (100% synthetic accuracy) |
| Frontend build (`tsc -b && vite build`) | ✅ Passes |
| Frontend lint (`eslint .`) | ✅ Passes |
| Backend deployed (Render) | ✅ `https://scamshield-ai-x4ym.onrender.com` |
| Frontend deployed (Vercel) | ✅ `https://scamshield-ai.vercel.app` |

### Live Smoke Test Results

Verified against deployed services:

| Input | Score | Level |
|---|---|---|
| Prize winner scam with shortener URL | 60+ / 100 | **High** |
| Normal everyday message | 0 / 100 | **Low** |

### Known Limitations

- **Ambiguous shortened URLs:** A URL shortener (e.g. `https://bit.ly/...`) submitted alone without accompanying context or sensitive path signals scores moderately to prevent false positives on benign shared links.
- **Synthetic benchmark only:** The evaluation dataset (`backend/evaluation_dataset.json`) contains 45 handcrafted synthetic examples across 6 categories for local regression tracking. High synthetic benchmark metrics reflect only this curated suite and are **not evidence of real-world detection performance**. Do not cite them as production-accuracy metrics.
- **Rule-based engine:** Detection is deterministic heuristics (no ML model). Novel scam lures outside codified patterns require ongoing rule expansion.

---

## Quickstart

### 1. Backend Quickstart

1. **Activate virtual environment:**
   - Windows (PowerShell): `.\backend\.venv\Scripts\Activate.ps1`
   - Linux/macOS: `source backend/.venv/bin/activate`

2. **Install dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Run the backend server:**
   ```bash
   uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
   ```
   - Health check: `http://127.0.0.1:8000/health`
   - Interactive API docs (Swagger): `http://127.0.0.1:8000/docs`

4. **Run backend automated tests:**
   ```bash
   python backend/test_main.py
   ```

5. **Run the evaluation benchmark:**
   ```bash
   python backend/evaluate.py
   ```

### 2. Frontend Quickstart

1. **Navigate to frontend directory & install dependencies:**
   ```bash
   cd frontend
   npm install
   ```

2. **Run local development server:**
   ```bash
   npm run dev
   ```
   - App runs at `http://localhost:5173`
   - By default, requests to `/api` proxy automatically to `http://127.0.0.1:8000` via `vite.config.ts`.

3. **Verify typecheck & production build:**
   ```bash
   npm run build
   npm run lint
   ```

---

## Demonstration Script

1. **Legitimate Message (Low Risk — Score 0/100):**
   - **Input:** *"Hey Sarah, are we still meeting for lunch at 12:30pm today? Let me know!"*
   - **Expected Result:** Risk Score `0/100`, Level `Low`, 0 indicators flagged.
   - **Evidence:** Shows clean safe badge with recommendation: *"No prominent scam patterns detected. Always verify unexpected requests through trusted channels."*

2. **Suspicious Threat (High Risk — Score 80/100):**
   - **Input:** *"Chase Security Alert: Unauthorized transaction detected. Verify your password within 24 hours to restore access."*
   - **Target URL:** `http://chase-security-verify.xyz/account-login`
   - **Expected Result:** Risk Score `80+/100`, Level `High`.
   - **Evidence Displayed:** Red risk badge, score progress bar, and categorized indicator pills:
     - `Brand Impersonation`: references Chase in unverified domain / text lure
     - `Credential Theft`: solicits password verification
     - `Deceptive URL`: `.xyz` suspicious TLD + unencrypted HTTP
     - Action banner: *"Do not click links, provide passwords, or send funds. Report and block the sender immediately."*

3. **Failure & Recovery Handling:**
   - **Empty Submission:** Click "Run Threat Analysis" with empty fields. Client validates immediately: *"Please provide a message, a URL, or both to analyze."*
   - **Oversized Input:** Input text exceeding 10,000 characters displays: *"Message content exceeds maximum allowed length of 10,000 characters."*
   - **Network Disconnect:** If backend is stopped or unreachable, the UI displays a non-crashing banner: *"Unable to connect to the ScamShield backend service. Please check your network connection or verify that the backend API is online."*

## Production Deployment Guide

### 1. Backend Deployment (Render)
1. Link your GitHub repository in the **Render Dashboard** as a **Web Service** (or use the included `render.yaml` Blueprint).
2. Configure settings:
   - **Root Directory:** leave empty (or set to repo root)
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r backend/requirements.txt`
   - **Start Command:** `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
3. Set **Environment Variables**:
   - `PORT`: (Managed automatically by Render, defaults to 8000 if testing locally)
   - `FRONTEND_URL`: `https://<your-vercel-app>.vercel.app` (restricts CORS to your deployed frontend domain).
4. Verify deployment: visit `https://<your-render-backend>.onrender.com/health` (should return `{"status": "ok", ...}`).

### 2. Frontend Deployment (Vercel)
1. Import the GitHub repository into **Vercel**.
2. Configure project settings:
   - **Framework Preset:** `Vite`
   - **Root Directory:** `frontend`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
3. Set **Environment Variables**:
   - `VITE_API_BASE_URL`: `https://<your-render-backend>.onrender.com` (point to your deployed backend URL).
4. Deploy. The included `frontend/vercel.json` ensures client-side routes rewrite to `index.html`.
