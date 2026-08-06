import { useAsync } from "../../hooks/useAsync";
import { complianceItems } from "../../mocks/soc";
import type { ComplianceItem } from "../../mocks/soc";
import { Icon } from "../icons";
import { SectionGrid } from "./SectionGrid";
import { Section, Widget } from "./Widget";

const STATUS_LABEL: Record<string, { text: string; className: string }> = {
  pass: { text: "Compliant", className: "status-ok" },
  warn: { text: "At Risk", className: "status-warn" },
  fail: { text: "Non-Compliant", className: "status-crit" },
};

function ComplianceWidget({ item }: { item: ComplianceItem }) {
  const status = STATUS_LABEL[item.status];
  const pct = (item.checksPassed / item.totalChecks) * 100;
  const color = item.score >= 85 ? "var(--green)" : item.score >= 70 ? "var(--amber)" : "var(--red)";
  return (
    <Widget title={item.name} icon="shieldCheck" actions={<span className={`soc-pill ${status.className}`}>{status.text}</span>}>
      <div className="soc-compliance">
        <div className="soc-compliance-top">
          <div className="soc-compliance-score mono" style={{ color }}>
            {item.score}
            <span className="soc-compliance-pct">%</span>
          </div>
          <div className="soc-compliance-bar">
            <div className="soc-compliance-fill" style={{ width: `${item.score}%`, background: color }} />
          </div>
        </div>
        <div className="soc-compliance-meta">
          <span className="mono">
            {item.checksPassed} / {item.totalChecks}
          </span>
          <span>controls passed ({Math.round(pct)}%)</span>
        </div>
      </div>
    </Widget>
  );
}

export function ComplianceSection() {
  const items = useAsync(() => complianceItems(), [], 60_000);
  return (
    <Section icon="award" title="Compliance" subtitle="Framework posture across your control set">
      <SectionGrid status={items.status} error={items.error} columns="3">
        {items.data?.map((item) => (
          <ComplianceWidget key={item.id} item={item} />
        ))}
      </SectionGrid>
      <div className="soc-footnote">
        <Icon name="book" size={13} />
        Compliance scores are derived from control evidence; reports are available in the Reports workspace.
      </div>
    </Section>
  );
}
