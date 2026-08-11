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
import EndpointPage from "./pages/EndpointPage";
import ModuleDetailPage from "./pages/ModuleDetailPage";
import ConfigurationAssessmentPage from "./pages/ConfigurationAssessmentPage";
import FileIntegrityMonitoringPage from "./pages/FileIntegrityMonitoringPage";
import IocLookupPage from "./pages/IocLookupPage";
import ThreatHuntingPage from "./pages/ThreatHuntingPage";
import VulnerabilityPage from "./pages/VulnerabilityPage";
import NetworkMonitoringPage from "./pages/NetworkMonitoringPage";
import ProcessServicePage from "./pages/ProcessServicePage";

const PAGE_TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/search": "Search & Investigate",
  "/alerts": "Alerts",
  "/cases": "Cases",
  "/rules": "Detection Rules",
  "/sources": "Data Sources",
  "/soar": "SOAR Automation",
  "/reports": "Reports",
  "/endpoint": "Endpoint Security — Configuration",
  "/endpoint/config": "Configuration Assessment",
  "/endpoint/malware": "Malware Detection",
  "/endpoint/fim": "File Integrity Monitoring",
  "/endpoint/ioc": "IOC Lookup",
  "/endpoint/hunting": "Threat Hunting",
  "/endpoint/vulnerabilities": "Vulnerability Detection",
  "/endpoint/network": "Network Monitoring",
  "/endpoint/process": "Process & Service Monitoring",
  "/endpoint/registry": "Registry Monitoring",
  "/endpoint/usb": "USB Monitoring",
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
      <Route
        path="/endpoint"
        element={
          <RequireAuth>
            <Shell>
              <EndpointPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/config"
        element={
          <RequireAuth>
            <Shell>
              <ConfigurationAssessmentPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/fim"
        element={
          <RequireAuth>
            <Shell>
              <FileIntegrityMonitoringPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/ioc"
        element={
          <RequireAuth>
            <Shell>
              <IocLookupPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/hunting"
        element={
          <RequireAuth>
            <Shell>
              <ThreatHuntingPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/vulnerabilities"
        element={
          <RequireAuth>
            <Shell>
              <VulnerabilityPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/network"
        element={
          <RequireAuth>
            <Shell>
              <NetworkMonitoringPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/process"
        element={
          <RequireAuth>
            <Shell>
              <ProcessServicePage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/endpoint/:moduleId"
        element={
          <RequireAuth>
            <Shell>
              <ModuleDetailPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
