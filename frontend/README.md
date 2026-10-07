# Frontend (Next.js + Tailwind)

SOC dashboard for Argus. Every widget reads the live API; there is no
hard-coded or mock data.

> This Next.js version (16.x) differs from older releases. See `AGENTS.md`
> and the guides bundled in `node_modules/next/dist/docs/`.

## Pages

| Path | Who | What |
|---|---|---|
| `/` | all roles | KPI tiles, live traffic (benign vs attack flows/s), activity over time, attack types, open alerts — all updating live |
| `/alerts` | all roles | Filter by status, severity, attack type and IP; sort by recency or risk; filters live in the URL |
| `/alerts/[id]` | all roles; actions for analyst+ | Facts, recommended action, SHAP factors, risk breakdown, detections, notes, history; acknowledge / contain / resolve / false positive / reopen, assign to me |
| `/audit` | admin | Append-only audit log with before/after values |
| `/notifications` | admin | Email, Slack and webhook channels (minimum severity, hourly cap, test message) and the delivery log with retry status |
| `/users` | admin | Create users, change roles, deactivate/reactivate |
| `/settings` | all roles | Detection settings (analyst reads, admin edits); change own password |
| `/login` | public | Sign-in form (server action) |
| `/status` | public | Reachability of API, PostgreSQL and Redis; used by health checks |

The navigation hides pages a role cannot use; the API enforces the roles
regardless.

## How it talks to the API

Next.js is a backend-for-frontend (`lib/session.ts`):

- **Sign-in** is a server action. The API's access and refresh tokens are
  stored in httpOnly, SameSite=Lax cookies (`Secure` with `COOKIE_SECURE=true`);
  browser JavaScript never sees a token.
- **`/api/backend/*`** proxies an allowlist of API endpoints, attaching the
  bearer token and refreshing it when it is about to expire. Concurrent
  refreshes share one API call, because the API treats a reused refresh token
  as theft. State-changing requests need the `x-argus-csrf: 1` header and a
  same-origin `Origin`; bodies are capped at 64 KB.
- **`/api/live`** opens the API WebSocket server-side and relays it to the
  browser as Server-Sent Events (`lib/live.tsx`). Alert events revalidate the
  SWR caches; traffic ticks feed the live chart.
- **`proxy.ts`** redirects page requests without a session cookie to
  `/login?next=…` before rendering.
- Security headers and a same-origin CSP are set in `next.config.ts`.

**Look and feel.** A dark SOC-console theme: HUD panels with corner
brackets, a left navigation rail, a threat-level indicator (highest open
severity), a UTC clock, a terminal-style live event feed and monospace data.
Tokens live in `app/globals.css`. Fonts (Chakra Petch, Inter, JetBrains Mono)
are vendored in `app/fonts` under the SIL Open Font License, so builds need no
network. Charts use Recharts with a palette validated for colour-blind
separation and contrast on the panel surface (benign `#1a9fd6`, attack
`#e8394a`). Severity and status colours always come with a label and a glyph,
and animations stop under `prefers-reduced-motion`.

## Run locally (without Docker)

Requires Node.js 20.9+ (Docker and CI use Node 24).

```bash
cd frontend
npm ci
API_INTERNAL_URL=http://localhost:8000 npm run dev   # http://localhost:3000
```

## Lint, build, end-to-end tests

```bash
npm run lint
npm run build
# Against a running stack (docker compose up -d --wait), from frontend/:
ADMIN_PASSWORD=… npm run test:e2e
```

The Playwright tests (`e2e/`) sign in, check the live feed, inject a simulated
DDoS with `docker compose exec engine …` (override with `E2E_INJECT_COMMAND`),
wait for the alert to appear without a reload, work it through acknowledge →
contain → resolve with a note, and check the audit log. Another test adds an
email channel and checks its test message is sent; with `MAILPIT_URL` set
(stack started with the `mail` profile) it also finds the message in the mail
catcher. `E2E_BASE_URL` defaults to `http://localhost:3000`.

`next.config.ts` sets `output: "standalone"`; the Dockerfile ships only
`.next/standalone` plus static assets in a non-root `node:24-alpine` image.
