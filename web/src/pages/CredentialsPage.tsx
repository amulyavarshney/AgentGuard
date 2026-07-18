import { api } from '../api/client'
import { useFetch, formatTime } from '../hooks'

export function CredentialsPage() {
  const { data, loading, error } = useFetch(() => api.credentialScopes(), [])

  return (
    <>
      <header className="page-header">
        <h2>Credential Scope</h2>
        <p>Blast-radius capabilities per credential reference used in gated actions</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading credential scopes…</div>}

      {!loading && data && (
        <div className="panel">
          <div className="panel-header">Credentials ({data.length})</div>
          <div className="panel-body">
            {data.length === 0 ? (
              <div className="empty">
                No credential usage recorded yet. Scope labels appear when adapters annotate proposals.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Reference</th>
                    <th>Scope capabilities</th>
                    <th>Usage</th>
                    <th>Last used</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((c) => (
                    <tr key={c.ref}>
                      <td className="mono">{c.ref}</td>
                      <td>
                        {c.scope.length === 0 ? (
                          <span style={{ color: 'var(--muted)' }}>—</span>
                        ) : (
                          <div className="scope-tags">
                            {c.scope.map((s: string) => (
                              <span key={s} className="scope-tag">
                                {s}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td>{c.usage_count}</td>
                      <td>{formatTime(c.last_used)}</td>
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
