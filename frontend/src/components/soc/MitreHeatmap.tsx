import type { MitreCell } from "../../mocks/soc";

const HEAT_ALPHA = [0.05, 0.16, 0.32, 0.55, 0.8];

export function MitreHeatmap({ cells }: { cells: MitreCell[] }) {
  if (!cells || cells.length === 0) return null;
  return (
    <div className="soc-heatmap">
      <div className="soc-heatmap-grid">
        {cells.map((cell) => (
          <div
            key={cell.tactic}
            className="soc-heat-cell"
            style={{
              background: `rgba(46, 168, 255, ${HEAT_ALPHA[cell.intensity]})`,
            }}
            title={`${cell.tactic}: ${cell.count} events`}
          >
            <span className="soc-heat-count">{cell.count}</span>
            <span className="soc-heat-label">{cell.tactic}</span>
          </div>
        ))}
      </div>
      <div className="soc-heat-legend">
        <span>Low</span>
        {HEAT_ALPHA.map((a) => (
          <span key={a} className="soc-heat-swatch" style={{ background: `rgba(46,168,255,${a})` }} />
        ))}
        <span>High</span>
      </div>
    </div>
  );
}
