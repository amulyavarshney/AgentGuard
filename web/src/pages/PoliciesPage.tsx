import { Fragment, useState } from 'react'
import { api } from '../api/client'
import { useFetch } from '../hooks'
import type { PolicyDocument, PolicyEntry } from '../types'

export function PoliciesPage() {
  const { data, loading, error, reload } = useFetch(() => api.policies(), [])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [rules, setRules] = useState<PolicyDocument | null>(null)
  const [rulesLoading, setRulesLoading] = useState(false)

  async function toggleEnabled(entry: PolicyEntry) {
    try {
      await api.setPolicyEnabled(entry.id, !entry.enabled)
      reload()
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Toggle failed')
    }
  }

  async function expand(id: string) {
    if (expanded === id) {
      setExpanded(null)
      setRules(null)
      return
    }
    setExpanded(id)
    setRulesLoading(true)
    try {
      const doc = await api.policyRules(id)
      setRules(doc)
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Load rules failed')
      setExpanded(null)
    } finally {
      setRulesLoading(false)
    }
  }

  return (
    <>
      <header className="page-header">
        <h2>Policies</h2>
        <p>Default rule packs and learned rules from human interventions</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading policies…</div>}

      {!loading && data && (
        <div className="panel">
          <div className="panel-header">Policy packs ({data.length})</div>
          <div className="panel-body">
            {data.length === 0 ? (
              <div className="empty">No policy files found under policies/default or policies/learned.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Enabled</th>
                    <th>ID</th>
                    <th>Source</th>
                    <th>Rules</th>
                    <th>Path</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((p) => (
                    <Fragment key={p.id}>
                      <tr>
                        <td>
                          <button
                            type="button"
                            className={`toggle${p.enabled ? ' on' : ''}`}
                            aria-label={p.enabled ? 'Disable' : 'Enable'}
                            onClick={() => toggleEnabled(p)}
                          />
                        </td>
                        <td className="mono">{p.id}</td>
                        <td>{p.source}</td>
                        <td>{p.rule_count}</td>
                        <td className="mono" style={{ fontSize: '0.75rem' }}>
                          {p.file_path}
                        </td>
                        <td>
                          <button type="button" onClick={() => expand(p.id)}>
                            {expanded === p.id ? 'Hide' : 'Rules'}
                          </button>
                        </td>
                      </tr>
                      {expanded === p.id && (
                        <tr key={`${p.id}-rules`}>
                          <td colSpan={6} style={{ background: '#fafbf8', padding: '1rem' }}>
                            {rulesLoading ? (
                              <div className="loading">Loading rules…</div>
                            ) : rules ? (
                              <pre
                                className="mono"
                                style={{
                                  margin: 0,
                                  fontSize: '0.75rem',
                                  whiteSpace: 'pre-wrap',
                                  overflow: 'auto',
                                }}
                              >
                                {JSON.stringify(rules.rules, null, 2)}
                              </pre>
                            ) : null}
                          </td>
                        </tr>
                      )}
                    </Fragment>
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
