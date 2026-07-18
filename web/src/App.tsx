import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { BlockedPage } from './pages/BlockedPage'
import { CredentialsPage } from './pages/CredentialsPage'
import { PoliciesPage } from './pages/PoliciesPage'
import { ReplayPage } from './pages/ReplayPage'
import { RiskPage } from './pages/RiskPage'
import { SessionsPage } from './pages/SessionsPage'

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/approvals" replace />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="blocked" element={<BlockedPage />} />
        <Route path="replay" element={<ReplayPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="credentials" element={<CredentialsPage />} />
        <Route path="risk" element={<RiskPage />} />
      </Route>
    </Routes>
  )
}
