# ScamShield AI

ScamShield analyzes suspicious message text and URLs using deterministic local rules, with optional Nebius Token Factory inference when explicitly configured. It returns a risk score, label, indicators, recommendation, and the method used. The score is a triage rating, not a calibrated probability.

## Features and limitations

- Explainable analysis report with returned indicators, safety actions, unique case reference, and a downloadable text report.
- Recent cases stored in the current browser's local storage. Submitted text, URLs, and results are retained on that device until deleted or browser storage is cleared; they are not synced or encrypted by this application.
- Passive URL inspection only. The backend does not open submitted URLs, follow redirects, or consult live reputation services.
- Optional Nebius inference. If credentials are missing or inference fails, local rule-based analysis remains available. No default model ID is assumed.
- Synthetic evaluation datasets are for regression testing only. They are not representative of real-world scam prevalence and do not demonstrate production accuracy.

## Local development

### Backend

Use Python 3.11 or later. From the repository root:

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The health endpoint is `http://127.0.0.1:8000/health`; interactive API documentation is at `/docs`. Copy `backend/.env.example` to `backend/.env` for local environment configuration. The backend loads `.env` at startup.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server runs on `http://localhost:5173` and proxies `/api` to `http://127.0.0.1:8000`. For a separate or deployed API, set `VITE_API_BASE_URL` to the backend origin using `frontend/.env.example`. Never put Nebius credentials in a `VITE_` variable or frontend code.

## Configuration and privacy

Backend settings in `backend/.env.example`:

- `PORT`: server port; hosting platforms generally provide this.
- `FRONTEND_URL`: allowed frontend origin(s), comma-separated if needed.
- `ALLOWED_ORIGINS`: optional comma-separated origin list that takes precedence over `FRONTEND_URL`.
- `NEBIUS_API_KEY`: optional server-side secret. Without it, only local rules are used.
- `NEBIUS_MODEL`: required alongside the API key. Choose an exact model ID from the Nebius Token Factory account/catalog; ScamShield does not guess a model.

When Nebius is enabled, submitted message text and URLs are sent to Nebius for inference. They are not sent to a report-generation service. The frontend creates reports locally. Browser case history stores submitted inputs and results in local storage; use per-case deletion, **Clear history**, or browser site-data controls to remove them. Browser-local storage is not an encrypted vault.

## Tests and evaluation

Run backend tests:

```powershell
backend\.venv\Scripts\python.exe -m unittest backend.test_main backend.test_nebius_client -v
```

Run the original synthetic regression benchmark:

```powershell
backend\.venv\Scripts\python.exe backend\evaluate.py
```

Run the separate held-out synthetic evaluation set:

```powershell
backend\.venv\Scripts\python.exe backend\evaluate.py --held-out
```

The evaluator prints test size, benign/scam label counts, confusion matrix, accuracy, precision, recall, F1, and any misclassified examples. The held-out examples are separate from the original dataset by ID and exact input. Both remain small, manually authored synthetic sets; results should not be presented as real-world performance.

Frontend checks:

```powershell
cd frontend
npm run lint
npm run build
```

The frontend currently has no configured component-test runner.

## Deployment

### Render backend

The root-level `render.yaml` defines a Python web service. Keep the repository root as the service root, install with `pip install -r backend/requirements.txt`, and start with `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`. Configure `FRONTEND_URL` or `ALLOWED_ORIGINS` for the deployed frontend. Set `NEBIUS_API_KEY` and `NEBIUS_MODEL` only in the server's secret environment if using Nebius.

### Vercel frontend

Set the Vercel root directory to `frontend`, build with `npm run build`, publish `dist`, and set `VITE_API_BASE_URL` to the backend origin. The Vite variable is public at build time and must not contain secrets. The included `frontend/vercel.json` provides the SPA rewrite.

After deployment, check the backend `/health` endpoint and test the frontend/API connection. A healthy endpoint or mocked unit test does not prove Nebius inference works; only a successful authenticated request with the configured model verifies live inference.
