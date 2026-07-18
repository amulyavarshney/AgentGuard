import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useFetch, formatTime } from '../hooks'

export function SessionsPage() {
  const { data, loading, error } = useFetch(() => api.sessions(), [])

  return (
    <>
      <header className="page-header">
        <h2>Live Sessions</h2>
        <p>Wrapped agent processes and their execution context</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading sessions…</div>}

      {!loading && data && (
        <div className="panel">
          <div className="panel-header">Sessions ({data.length})</div>
          <div className="panel-body">
            {data.length === 0 ? (
              <div className="empty">No active sessions. Start one with <code>agentguard exec</code>.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Task</th>
                    <th>Environment</th>
                    <th>Agent</th>
                    <th>Started</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <span className={`status-badge ${s.status}`}>{s.status}</span>
                      </td>
                      <td>{s.task || '—'}</td>
                      <td>{s.environment || '—'}</td>
                      <td className="mono">{s.agent_launcher || '—'}</td>
                      <td>{formatTime(s.started_at)}</td>
                      <td>
                        <Link to={`/replay?session=${s.id}`} className="link-btn">
                          Replay
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
