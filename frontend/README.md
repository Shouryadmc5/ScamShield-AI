# ScamShield AI frontend

React, TypeScript, and Vite frontend for ScamShield AI. The analyzer calls the
existing backend API, while the scroll-led presentation and 3D hero run locally
in the browser.

## Local development

From this directory:

```powershell
npm install
npm run dev
```

Vite proxies `/api` requests to `http://127.0.0.1:8000` by default. Set
`VITE_API_BASE_URL` in `.env.local` to a backend origin when using a separate
backend. This is a public build-time setting; never put API keys or other
secrets in a `VITE_` variable.

## Checks and deployment

```powershell
npm run lint
npm run build
```

For Vercel, set the project root to `frontend`, use `npm run build`, publish
`dist`, and set `VITE_API_BASE_URL` to the deployed backend origin. The
`vercel.json` rewrite serves the single-page application on nested routes.

The browser stores completed case inputs and results in local storage on the
current device; history is not synced or encrypted. See the repository
[README](../README.md) for backend setup, privacy details, and API configuration.
