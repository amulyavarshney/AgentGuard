import { NavLink, Outlet } from 'react-router-dom'

const links = [
  { to: '/approvals', label: 'Approvals' },
  { to: '/sessions', label: 'Live Sessions' },
  { to: '/blocked', label: 'Blocked Actions' },
  { to: '/replay', label: 'Session Replay' },
  { to: '/policies', label: 'Policies' },
  { to: '/credentials', label: 'Credential Scope' },
  { to: '/risk', label: 'Risk Summary' },
]

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <h1>AgentGuard</h1>
          <p>Runtime policy firewall</p>
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
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
