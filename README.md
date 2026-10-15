# ScamShield-AI
AI-powered scam message and phishing URL detection

## Backend Quickstart

1. **Activate virtual environment:**
   - Windows (PowerShell): `.\backend\.venv\Scripts\Activate.ps1`
   - Linux/macOS: `source backend/.venv/bin/activate`

2. **Install dependencies (if not already installed):**
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
