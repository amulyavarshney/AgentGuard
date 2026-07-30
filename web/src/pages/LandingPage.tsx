import { Link } from 'react-router-dom'

export function LandingPage() {
  return (
    <div className="landing">
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Runtime security &amp; governance</p>
          <h1 className="hero-title">AgentGuard</h1>
          <p className="hero-lead">
            A policy firewall and flight recorder between agents and the systems they act on.
            Stop unacceptable actions before they execute — then turn every human “no” into a
            permanent organizational control.
          </p>
          <div className="hero-actions">
            <Link className="btn btn-primary" to="/playground">
              Open playground
            </Link>
            <Link className="btn btn-ghost" to="/production">
              Production guide
            </Link>
          </div>
        </div>
        <div className="hero-panel" aria-hidden="true">
          <pre className="hero-terminal">{`Agent
  ↓
Policy + permission gateway
  ↓
Terminal / APIs / cloud / databases
  ↓
Tamper-resistant audit record`}</pre>
        </div>
      </section>

      <section className="section">
        <h2>What it does</h2>
        <p className="section-lead">
          Every meaningful agent action passes through AgentGuard before execution.
        </p>
        <div className="card-grid">
          <article className="feature">
            <h3>Intercept</h3>
            <p>
              Wrap agents with <code>agentguard exec</code>. Shell, filesystem, HTTP, PostgreSQL,
              and AWS CLI calls hit PATH shims and a local proxy.
            </p>
          </article>
          <article className="feature">
            <h3>Enforce</h3>
            <p>
              YAML policies allow, block, require approval, or escalate — including a default
              destructive-action pack for backups, IAM, secrets, and mass deletes.
            </p>
          </article>
          <article className="feature">
            <h3>Compare intent</h3>
            <p>
              A staging fix task proposing a production database delete is blocked as out of
              scope — the model never polices itself.
            </p>
          </article>
          <article className="feature">
            <h3>Learn rules</h3>
            <p>
              When an operator blocks an action, save it as a permanent rule for this agent,
              repo, team, or the whole org.
            </p>
          </article>
          <article className="feature">
            <h3>Replay</h3>
            <p>
              Hash-chained session timelines connect instruction → decision → tool call →
              consequence for security review.
            </p>
          </article>
          <article className="feature">
            <h3>Credential scope</h3>
            <p>
              Map what a token can do before use, and fail closed when blast radius exceeds the
              assigned task.
            </p>
          </article>
        </div>
      </section>

      <section className="section section-band">
        <h2>Try the wedge path</h2>
        <pre className="code-block">{`# Control plane
agentguard serve

# Agent proposes a destructive out-of-scope action
agentguard exec --task "fix auth error in staging" -- \\
  bash -c 'aws rds delete-db-instance --db-instance-identifier prod-db'

# → blocked at the shim (aws never runs)
# → save as org-wide rule from console or API
# → session replay shows the full timeline`}</pre>
        <div className="hero-actions">
          <Link className="btn btn-primary" to="/playground">
            Simulate in playground
          </Link>
          <a
            className="btn btn-ghost"
            href="https://github.com/amulyavarshney/AgentGuard#quickstart"
            target="_blank"
            rel="noreferrer"
          >
            Install locally
          </a>
        </div>
      </section>
    </div>
  )
}
