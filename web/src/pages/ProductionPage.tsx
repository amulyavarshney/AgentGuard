export function ProductionPage() {
  return (
    <div className="page-narrow">
      <header className="page-header">
        <h1>Using AgentGuard in production</h1>
        <p>
          AgentGuard is a local (or team-hosted) control plane. Agents must launch through the
          gateway — enforcement is not a SaaS sidecar that magically wraps every process.
        </p>
      </header>

      <section className="prose">
        <h2>Recommended topology</h2>
        <pre className="code-block">{`┌──────────────────────────────────────────────┐
│  Control plane (always on)                   │
│  agentguard serve                            │
│  • API + console  (internal / VPN)           │
│  • SQLite audit + policies on shared volume  │
└──────────────────────────────────────────────┘
                 ▲ writes audit
                 │
┌──────────────────────────────────────────────┐
│  Agent hosts (CI, laptops, runners)          │
│  agentguard exec --task "…" -- <agent>       │
│  • PATH shims + HTTP proxy                   │
│  • Policy + intent evaluation                │
│  • CLI approval or AUTO_DENY for CI          │
└──────────────────────────────────────────────┘`}</pre>

        <h2>Rollout steps</h2>
        <ol>
          <li>
            <strong>Install the binary</strong> on agent hosts and the control-plane host (
            <code>go build</code> or a release artifact).
          </li>
          <li>
            <strong>Ship policies</strong> — start with{' '}
            <code>policies/default/destructive-pack.yaml</code>, then grow{' '}
            <code>policies/learned/</code> from real interventions.
          </li>
          <li>
            <strong>Map credentials</strong> in <code>agentguard.yaml</code> (AWS profiles, Postgres
            hosts, HTTP token patterns) so environment and blast-radius labels are accurate.
          </li>
          <li>
            <strong>Require the launch path</strong> — CI and agent runners use{' '}
            <code>agentguard exec</code> (or <code>agentguard run</code>) as the only supported
            entrypoint. Bypass is out of band by design.
          </li>
          <li>
            <strong>Operate</strong> — use the console for blocked actions, session replay, and
            save-as-rule. For CI, set <code>AGENTGUARD_AUTO_DENY=1</code> so approvals fail closed.
          </li>
        </ol>

        <h2>What production gets you</h2>
        <ul>
          <li>Destructive classes (RDS delete, backup wipe, IAM changes, secret exfil) gated before tools run</li>
          <li>Intent mismatch detection (task vs proposed environment / destructiveness)</li>
          <li>Immutable, hash-chained evidence for incident review</li>
          <li>Institutional memory: interventions become YAML rules shared across sessions</li>
        </ul>

        <h2>Honest boundaries</h2>
        <ul>
          <li>Not a kernel/eBPF sandbox — processes that skip <code>agentguard exec</code> are ungated</li>
          <li>Credential labels are configured (MVP), not full live IAM simulation</li>
          <li>Approvals during <code>exec</code> are CLI-prompted; console approvals are for the serve API queue</li>
          <li>This GitHub Pages site is documentation + playground only — no remote enforcement</li>
        </ul>

        <h2>Hardening checklist</h2>
        <ul>
          <li>Bind <code>api.listen</code> to a private interface; put the console behind SSO/VPN</li>
          <li>Back up <code>data_dir</code> audit DB; treat hash-chain breaks as integrity alerts</li>
          <li>Version-control <code>policies/</code>; review learned rules like code</li>
          <li>Use least-privilege credentials; AgentGuard reduces blast radius but does not replace IAM</li>
          <li>Pin agent runners to the AgentGuard binary via PATH / container entrypoint</li>
        </ul>
      </section>
    </div>
  )
}
