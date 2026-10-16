import { Card, Kpi, PageHeader } from "../components/Card";
import { TrendChart } from "../components/Charts";
import { ErrorState, Loading } from "../components/Feedback";
import { useApi } from "../hooks/useApi";
import { formatNumber, timeAgo } from "../lib/format";

function heatColor(score) {
  if (score >= 75) return "var(--sev-critical)";
  if (score >= 50) return "var(--sev-high)";
  if (score >= 25) return "var(--sev-medium)";
  if (score > 0) return "var(--sev-low)";
  return "var(--surface-3)";
}

const LEVEL_TONE = { critical: "danger", high: "danger", medium: "warn", info: "info" };

export default function Executive() {
  const { data, error, loading, reload } = useApi("/executive/summary/", null, { pollMs: 120000 });
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const { posture, kpis, heatmap, trend, findings, compliance } = data;

  return (
    <>
      <PageHeader title="Executive risk view"
        description={`Business-level security posture for leadership · updated ${timeAgo(data.generated_at)}`}>
        <button className="btn" onClick={() => window.print()}>Print / save PDF</button>
      </PageHeader>
      <div className="grid grid-main-side">
        <Card title="Corporate security posture" subtitle="0 = calm, 100 = severe; combines live threats and open alerts">
          <div className="grid grid-2" style={{ alignItems: "center" }}>
            <div className="gauge">
              <div className={`gauge-score posture-${posture.level}`}>{posture.score}</div>
              <div className={`badge posture-${posture.level}`} style={{ fontSize: "0.9rem" }}>{posture.level.toUpperCase()}</div>
            </div>
            <TrendChart height="chart-box short" labels={trend.map((p) => p.date.slice(5))}
              datasets={[{ label: "Posture score (30 days)", data: trend.map((p) => p.score) }]} />
          </div>
        </Card>
        <Card title="What leadership needs to know">
          <ul className="stack" style={{ margin: 0, paddingLeft: 0, listStyle: "none", gap: 10 }}>
            {findings.map((f, i) => (
              <li key={i} className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
                <span className={`badge ${LEVEL_TONE[f.level] || ""}`}>{f.level}</span>
                <span>{f.text}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="grid grid-kpi mt">
        <Kpi label="Open incidents" value={formatNumber(kpis.open_incidents)} sub={`${kpis.critical_incidents} critical`}
          tone={kpis.critical_incidents ? "critical" : "ok"} />
        <Kpi label="Managed devices" value={`${kpis.assets ? Math.round(100 * (1 - kpis.shadow_it / kpis.assets)) : 0}%`}
          sub={`${kpis.shadow_it} shadow-IT devices`} />
        <Kpi label="Critical vulnerabilities" value={kpis.critical_vulnerable_assets} sub="Assets with CVSS ≥ 9"
          tone={kpis.critical_vulnerable_assets ? "high" : "ok"} />
        <Kpi label="Leaked credentials" value={kpis.leaked_credentials} tone={kpis.leaked_credentials ? "high" : "ok"} />
        <Kpi label="Look-alike domains" value={kpis.typosquats} />
        <Kpi label="Isolated devices" value={kpis.isolated_assets} sub="Contained by the SOC" />
      </div>

      <div className="grid grid-main-side mt">
        <Card title="Risk heatmap" subtitle="Business unit × security domain (open-alert risk, 0-100)">
          <div className="table-wrap">
            <div className="heatmap" style={{ gridTemplateColumns: `minmax(110px, auto) repeat(${heatmap.columns.length}, minmax(70px, 1fr))` }}>
              <span />
              {heatmap.columns.map((c) => <span key={c.key} className="muted small" style={{ textAlign: "center" }}>{c.label}</span>)}
              {heatmap.rows.map((row) => [
                <span key={`${row}-label`} className="heatmap-label">{row}</span>,
                ...heatmap.columns.map((col) => {
                  const cell = heatmap.cells.find((c) => c.row === row && c.column === col.key) || { score: 0, alerts: 0 };
                  return (
                    <span key={`${row}-${col.key}`} className="heatmap-cell"
                      style={{ background: heatColor(cell.score), color: cell.score ? "#fff" : "var(--text-faint)" }}
                      title={`${row} / ${col.label}: risk ${cell.score}, ${cell.alerts} open alerts`}>
                      {cell.score || "·"}
                    </span>
                  );
                }),
              ])}
            </div>
          </div>
        </Card>
        <Card title="Audit readiness">
          <div className="stack" style={{ gap: 12 }}>
            {compliance.map((f) => (
              <div key={f.framework}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <span>{f.label}</span><strong>{f.readiness}%</strong>
                </div>
                <div className="bar-track" style={{ height: 10, marginTop: 4 }}>
                  <div className="bar-fill" style={{ width: `${f.readiness}%`, background: f.readiness >= 80 ? "var(--ok)" : f.readiness >= 50 ? "var(--warn)" : "var(--danger)" }} />
                </div>
                <div className="faint small">{f.counts.pass || 0} pass · {f.counts.partial || 0} partial · {f.counts.fail || 0} fail · {f.counts.manual || 0} manual</div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}
