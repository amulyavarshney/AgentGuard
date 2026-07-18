#!/usr/bin/env bash
# AgentGuard category demo — block → save-as-rule → replay (safe: no real AWS calls)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEMO_DATA="${AGENTGUARD_DEMO_DATA:-$ROOT/.agentguard-demo}"
DEMO_PORT="${AGENTGUARD_DEMO_PORT:-8797}"
BIN="${AGENTGUARD_BIN:-$ROOT/bin/agentguard}"
CONFIG="$DEMO_DATA/agentguard.yaml"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[36m==>\033[0m %s\n' "$*"; }

mkdir -p "$DEMO_DATA" "$ROOT/bin" "$ROOT/policies/learned"

cat > "$CONFIG" <<EOF
data_dir: $DEMO_DATA
policy_dir: $ROOT/policies
api:
  listen: 127.0.0.1:$DEMO_PORT
EOF

step "Building AgentGuard"
go build -o "$BIN" ./cmd/agentguard

step "Starting control plane (API + console)"
"$BIN" serve --config "$CONFIG" &
SERVE_PID=$!
cleanup() {
  kill "$SERVE_PID" 2>/dev/null || true
  wait "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$DEMO_PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -sf "http://127.0.0.1:$DEMO_PORT/health" >/dev/null

bold "Console: http://127.0.0.1:$DEMO_PORT/"
bold "API:     http://127.0.0.1:$DEMO_PORT/api/v1/"

step "Running wrapped agent command (expect block before real aws executes)"
set +e
AGENTGUARD_AUTO_DENY=1 "$BIN" exec --config "$CONFIG" \
  --task "fix auth error in staging" -- \
  bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db' 2>&1 | tee "$DEMO_DATA/exec.log"
EXEC_RC=${PIPESTATUS[0]}
set -e
if [[ "$EXEC_RC" -eq 0 ]]; then
  echo "ERROR: expected non-zero exit when action is blocked" >&2
  exit 1
fi
grep -qi 'blocked\|AgentGuard' "$DEMO_DATA/exec.log"

step "Reading session + audit timeline from SQLite"
SESSION_ID="$("$BIN" session list --config "$CONFIG" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
if [[ -z "$SESSION_ID" ]]; then
  echo "ERROR: no session found in audit log" >&2
  exit 1
fi
echo "Session: $SESSION_ID"
"$BIN" session replay "$SESSION_ID" --config "$CONFIG" | tee "$DEMO_DATA/replay.json"
"$BIN" session verify "$SESSION_ID" --config "$CONFIG"

step "Saving intervention as permanent org-wide rule (from blocked audit event)"
EVENT_ID="$(curl -sf "http://127.0.0.1:$DEMO_PORT/api/v1/sessions/$SESSION_ID/events" | python3 -c 'import json,sys; ev=json.load(sys.stdin); print(ev[0]["id"])')"
SAVE_RESP="$(curl -sf -X POST "http://127.0.0.1:$DEMO_PORT/api/v1/events/$EVENT_ID/save-as-rule" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"org","reason":"demo: deny prod RDS delete during staging fix task"}')"
echo "$SAVE_RESP" | python3 -m json.tool
RULE_PATH="$(echo "$SAVE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["file_path"])')"
test -f "$RULE_PATH"

step "Verifying learned rule blocks identical action class (policy-only probe)"
curl -sf -X POST "http://127.0.0.1:$DEMO_PORT/api/v1/policies/evaluate" \
  -H 'Content-Type: application/json' \
  -d '{
    "action_type":"aws",
    "environment":"production",
    "command":"aws rds delete-db-instance --db-instance-identifier prod-db",
    "affected_resources":["prod-db"],
    "raw_request":{"action":"rds_delete_db_instance"}
  }' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["decision"]=="block", d'

step "Hash-chain verification via API"
VERIFY="$(curl -sf "http://127.0.0.1:$DEMO_PORT/api/v1/sessions/$SESSION_ID/verify")"
echo "$VERIFY" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("valid") is True, d'

step "Re-running exec (still blocked — learned rule + intent; aws never invoked)"
set +e
AGENTGUARD_AUTO_DENY=1 "$BIN" exec --config "$CONFIG" \
  --task "fix auth error in staging" -- \
  bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db' >/dev/null 2>&1
set -e

bold "Demo complete"
echo "  Session replay:  http://127.0.0.1:$DEMO_PORT/replay?session=$SESSION_ID"
echo "  Blocked actions: http://127.0.0.1:$DEMO_PORT/blocked"
echo "  Learned rule:    $RULE_PATH"
echo "  Audit DB:        $DEMO_DATA/audit.db"
