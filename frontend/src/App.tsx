import { Navigate, Route, Routes } from "react-router-dom";
import { useLocation } from "react-router-dom";
import { RequireAuth } from "./components/RequireAuth";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import SearchPage from "./pages/SearchPage";
import CasesPage from "./pages/CasesPage";
import RulesPage from "./pages/RulesPage";
import SourcesPage from "./pages/SourcesPage";
import SoarPage from "./pages/SoarPage";
import ReportsPage from "./pages/ReportsPage";

const PAGE_TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/search": "Search & Investigate",
  "/alerts": "Alerts",
  "/cases": "Cases",
  "/rules": "Detection Rules",
  "/sources": "Data Sources",
  "/soar": "SOAR Automation",
  "/reports": "Reports",
};

function Shell({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  return <Layout title={PAGE_TITLES[location.pathname] ?? "SIEM Platform"}>{children}</Layout>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Shell>
              <DashboardPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/search"
        element={
          <RequireAuth>
            <Shell>
              <SearchPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/alerts"
        element={
          <RequireAuth>
            <Shell>
              <AlertsPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/cases"
        element={
          <RequireAuth>
            <Shell>
              <CasesPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/rules"
        element={
          <RequireAuth>
            <Shell>
              <RulesPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/sources"
        element={
          <RequireAuth>
            <Shell>
              <SourcesPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/soar"
        element={
          <RequireAuth>
            <Shell>
              <SoarPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/reports"
        element={
          <RequireAuth>
            <Shell>
              <ReportsPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
