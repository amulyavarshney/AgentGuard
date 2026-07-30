import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { formatTime, decisionClass } from '../hooks'
import type { AuditEvent, Session } from '../types'

export function ReplayPage() {
  const [params, setParams] = useSearchParams()
  const sessionId = params.get('session') ?? ''
  const [sessions, setSessions] = useState<Session[]>([])
  const [session, setSession] = useState<Session | null>(null)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .sessions()
      .then((list) => {
        setSessions(list)
        if (!params.get('session') && list.length > 0 && import.meta.env.VITE_STATIC === 'true') {
          setParams({ session: list[0].id })
        }
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!sessionId) {
      setSession(null)
      setEvents([])
      return
    }
    setLoading(true)
    setError(null)
    Promise.all([api.session(sessionId).catch(() => null), api.sessionEvents(sessionId)])
      .then(([sess, evs]) => {
        setSession(sess)
        setEvents(evs)
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [sessionId])

  return (
    <>
      <header className="page-header">
        <h2>Session Replay</h2>
        <p>Immutable hash-chained timeline — instruction → decision → action → result</p>
      </header>

      <div className="panel" style={{ marginBottom: '1rem' }}>
        <div className="panel-body" style={{ padding: '1rem' }}>
          <label htmlFor="session-select" style={{ fontSize: '0.875rem', marginRight: '0.5rem' }}>
            Session
          </label>
          <select
            id="session-select"
            value={sessionId}
            onChange={(e) => setParams(e.target.value ? { session: e.target.value } : {})}
            style={{ font: 'inherit', padding: '0.375rem 0.5rem', minWidth: '280px' }}
          >
            <option value="">Select a session…</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {s.task || s.id.slice(0, 8)} — {s.status}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Loading timeline…</div>}

      {session && (
        <div className="panel" style={{ marginBottom: '1rem' }}>
          <div className="panel-header">Session context</div>
          <div className="panel-body" style={{ padding: '1rem', fontSize: '0.875rem' }}>
            <p style={{ margin: '0 0 0.5rem' }}>
              <strong>Task:</strong> {session.task || '—'}
            </p>
            <p style={{ margin: '0 0 0.5rem' }}>
              <strong>Environment:</strong> {session.environment || '—'}
            </p>
            <p style={{ margin: 0 }}>
              <strong>Agent:</strong> {session.agent_launcher || '—'}
            </p>
          </div>
        </div>
      )}

      {!loading && sessionId && events.length === 0 && !error && (
        <div className="empty">No audit events for this session.</div>
      )}

      {events.length > 0 && (
        <div className="panel">
          <div className="panel-header">Timeline ({events.length} events)</div>
          <ol className="timeline">
            {events.map((ev) => (
              <li key={ev.id}>
                <div className="timeline-time">
                  #{ev.sequence} · {formatTime(ev.timestamp)}
                </div>
                <div className="timeline-command">{ev.proposal.command}</div>
                <div style={{ marginBottom: '0.25rem' }}>
                  <span className={decisionClass(ev.decision)}>{ev.decision}</span>
                  {ev.result && (
                    <span style={{ marginLeft: '0.5rem', fontSize: '0.8125rem', color: 'var(--muted)' }}>
                      → {ev.result}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--muted)', fontFamily: 'var(--mono)' }}>
                  hash: {ev.event_hash.slice(0, 16)}…
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </>
  )
}
