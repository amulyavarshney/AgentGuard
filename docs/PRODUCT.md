# AgentGuard — Product Vision

## Category

**Runtime security and governance for autonomous agents** — authorization, policy enforcement, and forensic replay. Not observability-only.

## Wedge

Turn every human intervention into a permanent organizational control.

Enforcement sits **outside** the agent. The model never polices itself.

```text
Agent
  → Policy + permission gateway (AgentGuard)
  → Terminal / FS / HTTP / PostgreSQL / AWS
  → Tamper-resistant audit record
```

## Problem

Autonomous agents can execute destructive or out-of-scope actions using credentials with broad blast radius. Traditional observability tells you what happened after the fact; it does not gate actions at execution time or convert operator judgment into durable policy.

## Solution

AgentGuard is a Go-based runtime gateway that:

1. **Intercepts** agent tool use through a controlled execution path (`agentguard exec`, shims, proxies).
2. **Evaluates** YAML policies against a normalized `ActionProposal` schema.
3. **Blocks, allows, or pauses** for human approval based on environment, resource patterns, and blast-radius signals.
4. **Records** every decision in an append-only SQLite audit log with a per-session hash chain for tamper detection and replay.
5. **Exposes** a local control plane (API + React console) for live sessions, approvals, policy management, and session replay.

## MVP scope

| In scope | Out of scope (MVP) |
|----------|-------------------|
| Shell + filesystem shims via wrapper | Kernel/eBPF sandbox |
| HTTP forward proxy, `psql` + `aws` CLI wraps | Full SaaS multi-tenant cloud |
| Custom YAML policies + learned rules | Native SDK for every agent framework |
| SQLite audit + hash chain | HSM / remote attestation |
| Local API + React console | Perfect IAM simulation for all clouds |

## Interception model

Agents must launch through AgentGuard:

- `agentguard exec -- <cmd>` — wraps processes; injects env for shims and proxies.
- `agentguard run <agent>` — convenience presets for known launchers.

Bypassing the wrapper is out of band; product value comes when teams adopt AgentGuard as the required launch path.

## Core data model

- **ActionProposal** — every gated call normalized to one schema (action type, command, credentials, blast radius, environment, model context).
- **PolicyDecision** — `allow`, `block`, `require_approval`, `pause_and_escalate`.
- **AuditEvent** — proposal, decision, approvers, result, side effects, `prev_hash`, `event_hash`.

Replay = ordered audit events for a `session_id`.

## Policy language (v1)

YAML rules under `policies/` with match/require/deny/action blocks. Ship a default destructive-action pack (DB delete, backup delete, IAM changes, secret exposure, logging disable, billing changes, mass file delete, large egress).

After human block/approve-with-deny: **Save as permanent rule** with scope (session agent | repo | team | org).

## Success criteria

A demo path that proves the category:

```bash
agentguard serve
agentguard exec --task "fix auth error in staging" -- bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db'
# → blocked / approval required
# → human denies
# → "Save as rule" → future identical class blocked org-wide
# → session replay shows full timeline with hash-chained events
```

## Stack

| Layer | Choice |
|-------|--------|
| CLI + proxy + adapters | Go |
| Policy language | Custom YAML (MVP); design for OPA/Cedar later |
| Audit store | SQLite, append-only + hash chain |
| Control plane API | Go HTTP (`agentguard serve`) |
| Web console | TypeScript + React (Vite) |
| Config | `agentguard.yaml` + `policies/*.yaml` |

## Console (planned)

Primary surfaces: **approvals**, **replay**, and **policies** — not a generic multi-widget dashboard.

- Live sessions, blocked actions, approval inbox
- Credential scope vs task
- Session replay timeline
- Policy browse (default + learned)
- Risk summary by agent, repo, rule hit
