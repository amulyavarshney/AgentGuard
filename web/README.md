# AgentGuard Web Console

React control-plane UI for local AgentGuard (`agentguard serve`).

## Development (hot reload + API proxy)

Terminal 1 — start the Go API:

```bash
go run ./cmd/agentguard serve
```

Terminal 2 — start Vite dev server (proxies `/api` and `/health` to `127.0.0.1:8787`):

```bash
cd web
npm install
npm run dev
```

Open http://localhost:5173

## Production (embedded in Go binary)

Build the UI, then run serve (serves `web/dist` from disk when present):

```bash
cd web && npm install && npm run build
cd .. && go run ./cmd/agentguard serve
```

Open http://127.0.0.1:8787

If `web/dist` is missing, a minimal fallback page is served from the embedded static bundle.

## Views

| Route | Purpose |
|-------|---------|
| `/approvals` | Pending approval inbox — approve / deny / save-as-rule |
| `/sessions` | Live wrapped agent sessions |
| `/blocked` | Blocked actions from audit log |
| `/replay` | Hash-chained session timeline |
| `/policies` | Default + learned policy packs (enable/disable) |
| `/credentials` | Credential blast-radius scope |
| `/risk` | Risk counts by agent, repo, rule |

## API endpoints consumed

- `GET /api/v1/sessions`, `GET /api/v1/sessions/{id}/events`
- `GET /api/v1/events?decision=block`
- `GET/POST /api/v1/approvals`, `POST .../approve|deny|save-as-rule`
- `GET/PATCH /api/v1/policies`, `GET /api/v1/policies/{id}/rules`
- `GET /api/v1/risk/summary`
- `GET /api/v1/credentials/scopes`
