import { AiAssistantHero } from "../components/soc/AiAssistantHero";
import { AnalyticsSection } from "../components/soc/AnalyticsSection";
import { ComplianceSection } from "../components/soc/ComplianceSection";
import { EndpointSection } from "../components/soc/EndpointSection";
import { OverviewSection } from "../components/soc/OverviewSection";
import { SecurityOpsSection } from "../components/soc/SecurityOpsSection";
import { ThreatIntelSection } from "../components/soc/ThreatIntelSection";

/**
 * SOC command-center dashboard. Every section is an independent, reusable
 * component with its own loading / error / empty states. Real endpoints
 * drive the live widgets; mock fetchers back the ones with no API yet.
 */
function DashboardPage() {
  return (
    <div className="soc-dash">
      <OverviewSection />
      <AiAssistantHero />
      <EndpointSection />
      <ThreatIntelSection />
      <SecurityOpsSection />
      <AnalyticsSection />
      <ComplianceSection />
    </div>
  );
}

export default DashboardPage;
