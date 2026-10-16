import { useNavigate } from "react-router-dom";

import { RiskScore, SeverityBadge, StatusBadge, Techniques } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState } from "../components/Feedback";
import { useList } from "../hooks/useList";
import { INCIDENT_STATUS, SEVERITY, timeAgo } from "../lib/format";

export default function Incidents() {
  const navigate = useNavigate();
  const list = useList("/incidents/", { initialFilters: { open: "true" }, ordering: "-priority_score", pollMs: 30000 });
  return (
    <>
      <PageHeader title="Incidents"
        description="Related alerts are automatically bundled into cases by shared asset, identity, IP and indicator." />
      <Card flush>
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <div className="filters">
            <input type="search" placeholder="Search incidents" value={list.search} onChange={(e) => list.setSearch(e.target.value)} aria-label="Search incidents" />
            <select value={list.filters.open ?? ""} onChange={(e) => list.setFilter("open", e.target.value)} aria-label="Open or closed">
              <option value="true">Open</option><option value="false">Closed</option><option value="">All</option>
            </select>
            <select value={list.filters.status || ""} onChange={(e) => list.setFilter("status", e.target.value)} aria-label="Status">
              <option value="">Any status</option>
              {Object.entries(INCIDENT_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.severity_min || ""} onChange={(e) => list.setFilter("severity_min", e.target.value)} aria-label="Minimum severity">
              <option value="">Any severity</option>
              {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}+</option>)}
            </select>
          </div>
        </div>
        <ErrorState error={list.error} onRetry={list.reload} />
        <DataTable rows={list.rows} loading={list.loading} ordering={list.ordering} onSort={list.setOrdering}
          onRowClick={(row) => navigate(`/incidents/${row.id}`)} emptyText="No incidents match — the queue is clear."
          columns={[
            { key: "priority_score", label: "Priority", sortKey: "priority_score", render: (r) => <RiskScore score={r.priority_score} /> },
            { key: "title", label: "Incident", render: (r) => <div><strong>{r.title}</strong><div className="faint small">{r.summary}</div></div> },
            { key: "severity", label: "Severity", sortKey: "severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
            { key: "alert_count", label: "Alerts", sortKey: "alert_count" },
            { key: "assets", label: "Assets", render: (r) => r.assets.map((a) => a.name).slice(0, 3).join(", ") || "—" },
            { key: "actors", label: "Attribution", render: (r) => r.attributed_actors.map((a) => a.name).join(", ") || <span className="faint">—</span> },
            { key: "mitre", label: "Techniques", render: (r) => <Techniques items={r.mitre_techniques} max={3} /> },
            { key: "last_activity", label: "Last activity", sortKey: "last_activity", render: (r) => timeAgo(r.last_activity) },
          ]} />
        <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
      </Card>
    </>
  );
}
