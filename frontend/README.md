# Frontend (Next.js + Tailwind)

SOC dashboard for SentinelAI. In Phase 2 it is a single status page that asks
the backend's `/health/ready` endpoint (server-side) whether the API,
PostgreSQL and Redis are reachable. The real dashboard (alerts, live traffic,
SHAP explanations, investigation workflow) is built in Phase 6 on top of the
backend API; it will not contain hard-coded data.

> This Next.js version (16.x) differs from older releases. See `AGENTS.md`
> and the guides bundled in `node_modules/next/dist/docs/`.

## Run locally (without Docker)

Requires Node.js 20.9+ (Docker and CI use Node 24).

```bash
cd frontend
npm ci
API_INTERNAL_URL=http://localhost:8000 npm run dev   # http://localhost:3000
```

## Lint and build

```bash
npm run lint
npm run build
```

`next.config.ts` sets `output: "standalone"`; the Dockerfile ships only
`.next/standalone` plus static assets in a non-root `node:24-alpine` image.
