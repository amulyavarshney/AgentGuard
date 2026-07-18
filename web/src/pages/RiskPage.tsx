import { api } from '../api/client'
import { useFetch } from '../hooks'
import type { RiskBucket } from '../types'

function RiskBars({ title, buckets }: { title: string; buckets: RiskBucket[] }) {
  const max = Math.max(...buckets.map((b) => b.count), 1)
  const sorted = [...buckets].sort((a, b) => b.count - a.count)

  return (
    <div className="panel">
      <div className="panel-header">{title}</div>
      <div className="risk-bars">
        {sorted.length === 0 ? (
          <div className="empty">No data</div>
        ) : (
          sorted.map((b) => (
            <div key={b.key} className="risk-row">
              <span className="mono">{b.key}</span>
              <div className="risk-bar-track">
                <div
                  className="risk-bar-fill"
                  style={{ width: `${(b.count / max) * 100}%` }}
                />
              </div>
              <span>{b.count}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export function RiskPage() {
  const { data, loading, error } = useFetch(() => api.riskSummary(), [])

  return (
    <>
      <header className="page-header">
        <h2>Risk Summary</h2>
        <p>Event counts by agent, environment/repo, rule hits, and decision type</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading risk summary…</div>}

      {!loading && data && (
        <>
          <p style={{ fontSize: '0.875rem', color: 'var(--muted)', marginBottom: '1rem' }}>
            Total audit events analyzed: {data.total_events}
          </p>
          <div className="grid-2">
            <RiskBars title="By agent" buckets={data.by_agent} />
            <RiskBars title="By environment / repo" buckets={data.by_repo} />
            <RiskBars title="By rule / decision" buckets={data.by_rule} />
            <RiskBars title="By decision type" buckets={data.by_decision} />
          </div>
        </>
      )}
    </>
  )
}
