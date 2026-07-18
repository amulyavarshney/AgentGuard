import { useState } from 'react'
import { api } from '../api/client'
import { useFetch, formatTime, decisionClass } from '../hooks'
import type { ApprovalRequest } from '../types'

export function ApprovalsPage() {
  const { data, loading, error, reload } = useFetch(() => api.approvals(), [])
  const [acting, setActing] = useState<string | null>(null)

  async function act(id: string, action: 'approve' | 'deny' | 'save') {
    setActing(id)
    try {
      if (action === 'approve') await api.approve(id)
      else if (action === 'deny') await api.deny(id)
      else await api.saveAsRule(id, { scope: 'org' })
      reload()
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Action failed')
    } finally {
      setActing(null)
    }
  }

  return (
    <>
      <header className="page-header">
        <h2>Approval Inbox</h2>
        <p>Review gated actions — approve, deny, or save as a permanent rule</p>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading approvals…</div>}

      {!loading && data && (
        <div className="panel">
          <div className="panel-header">Pending ({data.length})</div>
          <div className="panel-body">
            {data.length === 0 ? (
              <div className="empty">No pending approvals. Actions requiring human review will appear here.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Requested</th>
                    <th>Action</th>
                    <th>Command</th>
                    <th>Decision</th>
                    <th>Environment</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.map((req: ApprovalRequest) => (
                    <tr key={req.id}>
                      <td>{formatTime(req.created_at)}</td>
                      <td>{req.proposal.action_type}</td>
                      <td className="mono">{req.proposal.command}</td>
                      <td>
                        <span className={decisionClass(req.decision)}>{req.decision}</span>
                      </td>
                      <td>{req.proposal.environment || '—'}</td>
                      <td>
                        <div className="btn-row">
                          <button
                            className="primary"
                            disabled={acting === req.id}
                            onClick={() => act(req.id, 'approve')}
                          >
                            Approve
                          </button>
                          <button
                            className="danger"
                            disabled={acting === req.id}
                            onClick={() => act(req.id, 'deny')}
                          >
                            Deny
                          </button>
                          <button
                            disabled={acting === req.id}
                            onClick={() => act(req.id, 'save')}
                          >
                            Save as rule
                          </button>
                        </div>
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
