import { useMemo, useState } from 'react'
import { decisionLabel, evaluateAction } from '../playground/engine'
import { SCENARIOS } from '../playground/scenarios'

export function PlaygroundPage() {
  const [selectedId, setSelectedId] = useState(SCENARIOS[0].id)
  const action = useMemo(
    () => SCENARIOS.find((s) => s.id === selectedId) ?? SCENARIOS[0],
    [selectedId],
  )
  const result = useMemo(() => evaluateAction(action), [action])

  return (
    <div className="playground">
      <header className="page-header">
        <h1>Policy playground</h1>
        <p>
          Simulate AgentGuard decisions in the browser. This uses a client-side port of the MVP
          rule pack and intent heuristics — run the Go binary locally for real enforcement.
        </p>
      </header>

      <div className="playground-grid">
        <aside className="scenario-list">
          <h2>Scenarios</h2>
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`scenario-btn${s.id === selectedId ? ' active' : ''}`}
              onClick={() => setSelectedId(s.id)}
            >
              {s.label}
            </button>
          ))}
        </aside>

        <div className="playground-main">
          <section className="panel">
            <h3>Requested</h3>
            <p className="task-line">{action.task}</p>
            <h3>Proposed</h3>
            <pre className="code-block tight">{action.command}</pre>
            <div className="meta-row">
              <span>
                <strong>Type</strong> {action.actionType}
              </span>
              <span>
                <strong>Env</strong> {action.environment}
              </span>
              <span>
                <strong>Credential</strong> {action.credential}
              </span>
            </div>
            <div className="scope-box">
              <strong>This credential can:</strong>
              <ul>
                {action.credentialScope.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
          </section>

          <section className={`panel verdict verdict-${result.decision}`}>
            <p className="verdict-label">Verdict</p>
            <h2>{decisionLabel(result.decision)}</h2>
            <p>{result.summary}</p>
            {result.matchedRules.length > 0 && (
              <p className="muted">
                Matched rules: <code>{result.matchedRules.join(', ')}</code>
              </p>
            )}
            {!result.intentAligned && (
              <ul className="intent-list">
                {result.intentReasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel">
            <h3>Session replay</h3>
            <ol className="pg-timeline">
              {result.timeline.map((row) => (
                <li key={row.t + row.event} className={`tl-${row.kind}`}>
                  <time>{row.t}</time>
                  <span>{row.event}</span>
                </li>
              ))}
            </ol>
          </section>
        </div>
      </div>
    </div>
  )
}
