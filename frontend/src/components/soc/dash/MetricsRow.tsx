import {
  BatteryBar,
  CategoryBars,
  DashPanel,
  MiniLineChart,
  MultiTrend,
  RadialNeedle,
  StatusPill,
} from "./primitives";
import type { EventIngestion, NetworkActivity, SystemPerf } from "./dashData";
import { compact } from "./dashData";

function logTrend(data: number[]): number[] {
  return data.map((v) => Math.log10(1 + v));
}

export function SystemPerfPanel({ perf }: { perf: SystemPerf }) {
  const cpuLast = perf.cpuTrend[perf.cpuTrend.length - 1] ?? perf.cpu;
  return (
    <DashPanel title="System Performance" icon="cpu" badge={<StatusPill text="Critical" tone="crit" />}>
      <div className="dash-perf">
        <div className="dash-perf-cpu">
          <div className="dash-perf-cpu-gauge">
            <div className="dash-perf-label-row">
              <span className="dash-perf-label">CPU UTILIZATION</span>
            </div>
            <RadialNeedle value={perf.cpu} max={perf.cpuMax} label="UTILIZATION" />
          </div>
          <div className="dash-perf-cpu-chart">
            <div className="dash-perf-head">
              <span className="dash-perf-label">CPU LOAD · LAST 24H</span>
              <span className="dash-perf-big dash-perf-warn">{cpuLast}%</span>
              <span className="dash-perf-chip dash-perf-chip-warn">AMBER CRITICAL</span>
            </div>
            <MiniLineChart data={perf.cpuTrend} color="var(--red)" height={44} fillOpacity={0.14} />
          </div>
        </div>

        <div className="dash-perf-disk">
          <div className="dash-perf-head">
            <span className="dash-perf-label">DISK STORAGE</span>
            <span className="dash-perf-big dash-perf-crit">{perf.diskPct}%</span>
          </div>
          <BatteryBar pct={perf.diskPct} color="var(--red)" />
          <div className="dash-perf-disk-caption">
            <span className="dash-perf-chip dash-perf-chip-crit">CRITICAL SPACE LOW</span>
            <span className="dash-perf-disk-meta">
              {perf.diskUsed} / {perf.diskTotal} Used
            </span>
          </div>
          <CategoryBars data={perf.diskCategories} max={1000} height={74} />
        </div>

        <div className="dash-perf-dials">
          <div className="dash-perf-dial">
            <RadialNeedle value={perf.dial} max={perf.dialMax} label="LOAD" size={110} />
          </div>
          <div className="dash-perf-dial">
            <RadialNeedle
              value={perf.ram}
              max={100}
              label="RAM"
              size={110}
              bands={[{ to: 1, color: "var(--green)" }]}
            />
            <div className="dash-perf-ram-trend">
              <MiniLineChart data={perf.ramTrend} color="var(--green)" height={26} />
            </div>
          </div>
        </div>
      </div>
    </DashPanel>
  );
}

export function NetworkActivityPanel({ net }: { net: NetworkActivity }) {
  return (
    <DashPanel title="Network Activity" icon="activity" badge={<StatusPill text="Live" tone="ok" />}>
      <div className="dash-net">
        <div className="dash-net-top">
          <RadialNeedle value={net.throughput} max={net.netMax} label="MBPS" size={130} />
          <div className="dash-net-stats">
            <div className="dash-net-stat">
              <span className="dash-net-stat-v">{net.peak}</span>
              <span className="dash-net-stat-l">PEAK MBPS</span>
            </div>
            <div className="dash-net-stat">
              <span className="dash-net-stat-v">{net.connections}</span>
              <span className="dash-net-stat-l">CONNECTIONS</span>
            </div>
            <div className="dash-net-stat">
              <span className="dash-net-stat-v">{net.inbound}</span>
              <span className="dash-net-stat-l">INBOUND MBPS</span>
            </div>
            <div className="dash-net-stat">
              <span className="dash-net-stat-v">{net.outbound}</span>
              <span className="dash-net-stat-l">OUTBOUND MBPS</span>
            </div>
          </div>
        </div>
        <div className="dash-net-trend">
          <span className="dash-perf-label">NETWORK TRAFFIC TREND · LOG SCALE · LAST 24H</span>
          <MultiTrend
            data={[logTrend(net.inTrend), logTrend(net.outTrend)]}
            colors={["var(--orange)", "var(--amber)"]}
            labels={["INBOUND", "OUTBOUND"]}
            height={44}
            grid
          />
        </div>
      </div>
    </DashPanel>
  );
}

export function EventIngestionPanel({ ingest }: { ingest: EventIngestion }) {
  return (
    <DashPanel title="Event Ingestion" icon="database">
      <div className="dash-ingest">
        <RadialNeedle value={ingest.eps} max={50} label="EVENTS / SEC" size={130} />
        <div className="dash-ingest-eps">{ingest.eps} EPS</div>
        <div className="dash-ingest-today">
          <span className="dash-ingest-today-v">{compact(ingest.today)}</span>
          <span className="dash-ingest-today-l">EVENTS TODAY</span>
        </div>
        <div className="dash-ingest-trend">
          <span className="dash-perf-label">INGESTION RATE · LAST 24H</span>
          <MiniLineChart data={ingest.trend} color="var(--amber)" height={34} />
        </div>
      </div>
    </DashPanel>
  );
}
