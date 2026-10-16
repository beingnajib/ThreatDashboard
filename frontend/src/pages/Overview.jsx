import { Link } from "react-router-dom";

import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { BarList, Card, Kpi, PageHeader } from "../components/Card";
import { BarChart, DoughnutChart, severityColors, TrendChart } from "../components/Charts";
import DataTable from "../components/DataTable";
import { ErrorState, Loading } from "../components/Feedback";
import { useApi } from "../hooks/useApi";
import { useStoredState } from "../hooks/useStoredState";
import { formatDate, formatNumber, IOC_TYPES, THREAT_TYPES, timeAgo } from "../lib/format";

export default function Overview() {
  const [days, setDays] = useStoredState("threatdash.overview.days", 30);
  const [live, setLive] = useStoredState("threatdash.overview.live", true);
  const poll = live ? 30000 : 0;
  const { data, error, loading, reload } = useApi("/analytics/summary/", { days }, { pollMs: poll });
  const { data: incidents } = useApi("/incidents/", { open: true, ordering: "-priority_score", page_size: 6 }, { pollMs: poll });
  const { data: events } = useApi("/events/stats/", null, { pollMs: poll });

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const t = data.totals;
  const timeline = data.timeline.indicators;

  return (
    <>
      <PageHeader title="SOC overview" description={`Updated ${timeAgo(data.generated_at)} · window ${data.window_days} days`}>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Time window">
          {[7, 14, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </select>
        <label className="check"><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />Auto-refresh</label>
        <button className="btn" onClick={() => reload()}>Refresh</button>
      </PageHeader>

      {data.anomalies.length > 0 && (
        <div className="alert-banner warn" role="status">
          <strong>Volume anomaly:</strong>
          <span>
            {data.anomalies.slice(-3).map((a) => `${a.date}: ${a.count} new indicators vs baseline ${a.baseline}${a.zscore ? ` (z=${a.zscore})` : ""}`).join(" · ")}
          </span>
        </div>
      )}
      {data.trending.length > 0 && (
        <div className="alert-banner info" role="status">
          <strong>Trending:</strong>
          <span>{data.trending.map((tr) => `${tr.label} ×${tr.change_ratio ?? "new"} (${tr.last_24h} in 24h)`).join(" · ")}</span>
        </div>
      )}

      <div className="grid grid-kpi">
        <Kpi label="Threat posture" value={<span className={`posture-${data.posture.level}`}>{data.posture.score}</span>}
          sub={data.posture.level.toUpperCase()} />
        <Kpi label="Open incidents" value={formatNumber(incidents?.count)} tone={incidents?.count ? "high" : "ok"}
          sub={<Link to="/incidents">View queue</Link>} />
        <Kpi label="Open alerts" value={formatNumber(t.open_alerts)} sub={`${t.alerts_24h} in last 24h`} tone={t.open_alerts ? "high" : "ok"} />
        <Kpi label="Critical active IoCs" value={formatNumber(t.critical_active)} tone={t.critical_active ? "critical" : "ok"}
          sub={`${t.high_risk} scored 80+`} />
        <Kpi label="Events (24h)" value={formatNumber(events?.last_24h)} sub={`${events?.matched_last_24h ?? 0} matched intel`} />
        <Kpi label="MTTR" value={t.mttr_hours != null ? `${t.mttr_hours}h` : "—"} sub="Mean time to resolve alerts" />
      </div>

      <div className="grid grid-main-side mt">
        <Card title="Detection timeline" subtitle="New indicators and alerts per day">
          <TrendChart labels={timeline.map((p) => p.date.slice(5))} datasets={[
            { label: "Indicators", data: timeline.map((p) => p.count) },
            { label: "Alerts", data: data.timeline.alerts.map((p) => p.count), fill: false },
          ]} />
        </Card>
        <Card title="Active by severity">
          <DoughnutChart labels={data.by_severity.map((s) => s.label)} values={data.by_severity.map((s) => s.count)}
            colors={severityColors()} />
        </Card>
      </div>

      <div className="grid grid-3 mt">
        <Card title="Threat categories">
          <BarChart horizontal labels={data.by_threat_type.map((r) => r.label)} values={data.by_threat_type.map((r) => r.count)} />
        </Card>
        <Card title="Telemetry by domain" subtitle="Last 24 hours">
          <BarList items={(events?.by_domain || []).map((d) => ({ key: d.domain, label: d.domain, count: d.count }))} />
          <h3 className="mt">Indicator types</h3>
          <div className="mt"><BarList items={data.by_ioc_type.map((r) => ({ ...r, label: IOC_TYPES[r.key] || r.label }))} /></div>
        </Card>
        <Card title="Top MITRE ATT&CK techniques">
          <BarList items={data.mitre_techniques.slice(0, 10)} />
          <h3 className="mt">Top origin countries</h3>
          <div className="mt"><BarList items={data.top_countries.slice(0, 6)} /></div>
        </Card>
      </div>

      <div className="grid grid-2 mt">
        <Card title="Priority incidents" flush actions={<Link to="/incidents" className="small">All incidents</Link>}>
          <DataTable rows={incidents?.results} emptyText="No open incidents." columns={[
            { key: "priority_score", label: "Priority", render: (r) => <RiskScore score={r.priority_score} /> },
            { key: "title", label: "Incident", render: (r) => <Link to={`/incidents/${r.id}`}>{r.title}</Link> },
            { key: "severity", label: "Severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
            { key: "last_activity", label: "Last activity", render: (r) => timeAgo(r.last_activity) },
          ]} />
        </Card>
        <Card title="Highest-risk indicators" flush actions={<Link to="/indicators" className="small">All indicators</Link>}>
          <DataTable rows={data.top_risky} columns={[
            { key: "risk_score", label: "Risk", render: (r) => <RiskScore score={r.risk_score} /> },
            { key: "value", label: "Indicator", className: "value", render: (r) => <span className="mono truncate" title={r.value}>{r.value}</span> },
            { key: "threat_type", label: "Threat", render: (r) => THREAT_TYPES[r.threat_type] || r.threat_type },
            { key: "last_seen", label: "Last seen", render: (r) => formatDate(r.last_seen) },
          ]} />
        </Card>
      </div>
      <div className="grid grid-2 mt">
        <Card title="Top tags"><BarList items={data.top_tags.slice(0, 10)} /></Card>
        <Card title="Indicators by source"><BarList items={data.by_source} /></Card>
      </div>
    </>
  );
}
