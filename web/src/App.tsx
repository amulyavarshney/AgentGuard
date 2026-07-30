import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { SiteLayout } from './components/SiteLayout'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { BlockedPage } from './pages/BlockedPage'
import { CredentialsPage } from './pages/CredentialsPage'
import { LandingPage } from './pages/LandingPage'
import { PlaygroundPage } from './pages/PlaygroundPage'
import { PoliciesPage } from './pages/PoliciesPage'
import { ProductionPage } from './pages/ProductionPage'
import { ReplayPage } from './pages/ReplayPage'
import { RiskPage } from './pages/RiskPage'
import { SessionsPage } from './pages/SessionsPage'

const isStatic = import.meta.env.VITE_STATIC === 'true'

export function App() {
  return (
    <Routes>
      <Route element={<SiteLayout />}>
        <Route index element={<LandingPage />} />
        <Route path="playground" element={<PlaygroundPage />} />
        <Route path="production" element={<ProductionPage />} />
      </Route>

      <Route path="console" element={<Layout />}>
        <Route index element={<Navigate to={isStatic ? 'replay' : 'approvals'} replace />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="blocked" element={<BlockedPage />} />
        <Route path="replay" element={<ReplayPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="credentials" element={<CredentialsPage />} />
        <Route path="risk" element={<RiskPage />} />
      </Route>

      {/* Back-compat for old console routes when embedded in serve */}
      {!isStatic && (
        <>
          <Route path="approvals" element={<Navigate to="/console/approvals" replace />} />
          <Route path="sessions" element={<Navigate to="/console/sessions" replace />} />
          <Route path="blocked" element={<Navigate to="/console/blocked" replace />} />
          <Route path="replay" element={<Navigate to="/console/replay" replace />} />
          <Route path="policies" element={<Navigate to="/console/policies" replace />} />
          <Route path="credentials" element={<Navigate to="/console/credentials" replace />} />
          <Route path="risk" element={<Navigate to="/console/risk" replace />} />
        </>
      )}

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
