import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch, formatTime, decisionClass } from '../hooks'

export function BlockedPage() {
  const { data, loading, error } = useFetch(
    () => api.events({ decision: 'block', limit: 100 }),
    [],
  )

  return (
    <>
      <header className="page-header">
        <h2>Blocked Actions</h2>
        <p>Policy denials from the audit log</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading blocked actions…</div>}

      {!loading && data && (
        <div className="panel">
          <div className="panel-header">Blocked ({data.length})</div>
          <div className="panel-body">
            {data.length === 0 ? (
              <div className="empty">No blocked actions recorded yet.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Command</th>
                    <th>Result</th>
                    <th>Session</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((ev) => (
                    <tr key={ev.id}>
                      <td>{formatTime(ev.timestamp)}</td>
                      <td>{ev.proposal.action_type}</td>
                      <td className="mono">{ev.proposal.command}</td>
                      <td>
                        <span className={decisionClass(ev.decision)}>{ev.decision}</span>
                      </td>
                      <td>
                        <Link to={`/replay?session=${ev.session_id}`} className="link-btn mono">
                          {ev.session_id.slice(0, 8)}…
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </>
  )
}
