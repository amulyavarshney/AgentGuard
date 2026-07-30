import { NavLink, Outlet } from 'react-router-dom'

const links = [
  { to: '/console/approvals', label: 'Approvals' },
  { to: '/console/sessions', label: 'Live Sessions' },
  { to: '/console/blocked', label: 'Blocked Actions' },
  { to: '/console/replay', label: 'Session Replay' },
  { to: '/console/policies', label: 'Policies' },
  { to: '/console/credentials', label: 'Credential Scope' },
  { to: '/console/risk', label: 'Risk Summary' },
]

const isStatic = import.meta.env.VITE_STATIC === 'true'

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <NavLink to="/" className="brand-home">
            <h1>AgentGuard</h1>
          </NavLink>
          <p>{isStatic ? 'Console tour (demo data)' : 'Local control plane'}</p>
        </div>
        <nav>
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <NavLink to="/playground" className="nav-link">
            ← Playground
          </NavLink>
        </div>
      </aside>
      <main className="main">
        {isStatic && (
          <div className="banner">
            Static demo: console APIs are unavailable on GitHub Pages. Use the playground, or run{' '}
            <code>agentguard serve</code> locally for live data.
          </div>
        )}
        <Outlet />
      </main>
    </div>
  )
}
