# ScamShield-AI

AI-powered scam message and phishing URL detection — Hackathon Day 1 release.

## Project Status (Day 1)

| Area | Status |
|---|---|
| Backend (FastAPI, rule-based engine) | ✅ Complete |
| Frontend (React + TypeScript + Vite) | ✅ Complete |
| Backend unit tests | ✅ 22/22 passing |
| Frontend build (`tsc -b && vite build`) | ✅ Passes |
| Frontend lint (`eslint .`) | ✅ Passes |
| Backend deployed (Render) | ✅ `https://scamshield-ai-x4ym.onrender.com` |
| Frontend deployed (Vercel) | ✅ `https://scamshield-ngfa0g1xm-shouryadmc5-7692.vercel.app` |

### Live Smoke Test Results (Day 1)

Verified against deployed backend:

| Input | Score | Level |
|---|---|---|
| Prize winner scam with shortener URL | 45 / 100 | **Medium** |
| Normal everyday message | 0 / 100 | **Low** |

### Known Limitations

- **Ambiguous shortened URLs:** A URL shortener (e.g. `https://bit.ly/...`) submitted alone without accompanying scam-lure text scores 20 — below the Medium threshold of 30. This is a deliberate trade-off: raising the shortener weight would produce false positives on legitimate uses (e.g. shared news links). A future fix requires text context or a URL-expand service.
- **Synthetic benchmark only:** The evaluation dataset (`backend/evaluation_dataset.json`) contains 20 handcrafted synthetic examples for regression tracking. The 95% accuracy / 0.9524 F1 figures reflect only this small dataset and are **not evidence of real-world detection performance**. Do not cite them as production-accuracy metrics.
- **Rule-based engine:** Detection is deterministic heuristics (no ML model). New scam patterns not covered by existing rules will be missed until rules are updated.

---

## Backend Quickstart

1. **Activate virtual environment:**
   - Windows (PowerShell): `.\backend\.venv\Scripts\Activate.ps1`
   - Linux/macOS: `source backend/.venv/bin/activate`

2. **Install dependencies (first time only):**
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
