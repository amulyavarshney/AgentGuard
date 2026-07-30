import { NavLink, Outlet } from 'react-router-dom'

const links = [
  { to: '/', label: 'Home', end: true },
  { to: '/playground', label: 'Playground' },
  { to: '/production', label: 'Production' },
  { to: '/console', label: 'Console' },
]

export function SiteLayout() {
  return (
    <div className="site">
      <header className="site-header">
        <NavLink to="/" className="site-brand">
          <span className="site-mark">AG</span>
          <span className="site-name">AgentGuard</span>
        </NavLink>
        <nav className="site-nav">
          {links.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end}
              className={({ isActive }) => `site-nav-link${isActive ? ' active' : ''}`}
            >
              {l.label}
            </NavLink>
          ))}
          <a
            className="site-nav-cta"
            href="https://github.com/amulyavarshney/AgentGuard"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </nav>
      </header>
      <Outlet />
      <footer className="site-footer">
        <p>
          Runtime security for autonomous agents — enforcement outside the model.
        </p>
        <p className="muted">
          Local binary required for real gating. This site is a static playground + guide.
        </p>
      </footer>
    </div>
  )
}
