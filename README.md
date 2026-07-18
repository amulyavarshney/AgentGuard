# AgentGuard

Runtime security and governance for autonomous agents — authorization, policy enforcement, and forensic replay.

AgentGuard sits **outside** the agent: every shell, filesystem, HTTP, PostgreSQL, and AWS action passes through a policy gateway before execution. Decisions are recorded in a tamper-resistant, hash-chained audit log with a local React console for approvals, replay, and intervention-to-rule workflows.

## Quickstart

```bash
# Build
go build -o bin/agentguard ./cmd/agentguard

# Terminal 1 — control plane (API + web console)
./bin/agentguard serve

# Terminal 2 — wrap an agent command
./bin/agentguard exec --task "fix auth error in staging" -- \
  bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db'
```

The destructive AWS command is classified and **blocked at the shim** before the real `aws` binary runs — no cloud credentials required for the demo.

Open **http://127.0.0.1:8787/** for the console (approvals, blocked actions, session replay, policies).

## Category demo (non-interactive)

Run the full wedge path in one script:

```bash
chmod +x scripts/demo.sh
./scripts/demo.sh
```

This script:

1. Starts `agentguard serve` on port **8797** (isolated demo data under `.agentguard-demo/`)
2. Runs `agentguard exec` with a staging fix task and a prod RDS delete — **blocked**
3. Prints the hash-chained session timeline and verifies integrity
4. **Save as rule** via `POST /api/v1/events/{id}/save-as-rule` (org-wide learned policy)
5. Confirms future identical action class is blocked by policy evaluation
6. Shows console URLs for replay

Environment overrides:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTGUARD_DEMO_PORT` | `8797` | API/console port |
| `AGENTGUARD_DEMO_DATA` | `.agentguard-demo` | Isolated SQLite + config |
| `AGENTGUARD_BIN` | `bin/agentguard` | Binary path |

For manual approval prompts during `exec`, answer `y`/`n` at the CLI prompt. Non-interactive runs:

```bash
export AGENTGUARD_AUTO_DENY=1    # deny pending approvals (default-safe)
export AGENTGUARD_AUTO_APPROVE=1 # approve (use with care)
```

## CLI reference

```bash
agentguard serve                          # API + embedded console
agentguard exec --task "..." -- <cmd>      # wrap agent process (shim PATH)
agentguard session list                   # sessions from audit log
agentguard session replay <session-id>    # hash-chained timeline (JSON)
agentguard session verify <session-id>    # verify chain integrity
agentguard policy validate policies/default/destructive-pack.yaml
agentguard policy save-rule --proposal proposal.json --scope org
```

## Configuration

Copy or edit `agentguard.yaml` in the repo root. Key fields:

```yaml
data_dir: .agentguard          # SQLite audit store
policy_dir: policies             # default/ + learned/ YAML packs
api:
  listen: 127.0.0.1:8787
```

Policies live under `policies/default/` (shipped destructive pack) and `policies/learned/` (rules saved from human interventions).

## Tests

```bash
go test ./...
go test ./test/demo/... -v      # end-to-end demo path (exec + audit + save-as-rule)
```

## Web console

```bash
cd web && npm install && npm run build   # optional; serve also uses web/dist if present
cd web && npm run dev                    # dev mode with API proxy
```

Primary views: **Approvals**, **Session Replay**, **Policies**, **Blocked Actions**.

## Architecture (MVP)

```text
Agent → agentguard exec (shim PATH + HTTP proxy)
     → Policy engine + intent comparator
     → allow | block | require_approval
     → SQLite hash-chain audit
     → Control-plane API + React console
```

Interception is honest MVP scope: agents must launch through `agentguard exec`. Shims wrap `bash`, `aws`, `psql`, `rm`, and route HTTP via a local forward proxy.

## Layout

```text
cmd/agentguard/          CLI entry
internal/
  intercept/             process wrap, shims, HTTP proxy
  adapters/              shell, fs, http, postgres, aws classifiers
  policy/                YAML engine + learned rules
  intent/                task vs action heuristics
  approval/              CLI/UI approval broker
  audit/                 SQLite hash-chain store
  api/                   control-plane HTTP + embedded UI
  session/               session lifecycle
policies/default/        built-in destructive pack
policies/learned/        rules from interventions
web/                     React console (Vite)
scripts/demo.sh          category demo script
test/demo/               end-to-end tests
docs/PRODUCT.md          product vision
```

See [docs/PRODUCT.md](docs/PRODUCT.md) for positioning and MVP scope.
