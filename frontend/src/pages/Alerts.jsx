import { useState } from "react";
import { Link } from "react-router-dom";

import { SeverityBadge, StatusBadge, Techniques } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState, useToast } from "../components/Feedback";
import { useList } from "../hooks/useList";
import { api } from "../lib/api";
import { ALERT_STATUS, DETECTION_TYPES, SEVERITY, timeAgo } from "../lib/format";

export default function Alerts() {
  const toast = useToast();
  const list = useList("/alerts/", { initialFilters: { open: "true" }, ordering: "-created_at", pollMs: 30000 });
  const [busyId, setBusyId] = useState(null);

  async function act(alert, verb) {
    setBusyId(alert.id);
    try {
      await api.post(`/alerts/${alert.id}/${verb}/`);
      const past = { acknowledge: "acknowledged", resolve: "resolved", dismiss: "dismissed", reopen: "reopened" };
      toast(`Alert ${past[verb]}`, "success");
      list.reload(true);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <PageHeader title="Alerts" description="Detections from rules, IoC matches in telemetry, behavioural analytics and source products." />
      <Card flush>
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <div className="filters">
            <input type="search" placeholder="Search alerts" value={list.search} onChange={(e) => list.setSearch(e.target.value)} aria-label="Search alerts" />
            <select value={list.filters.open ?? ""} onChange={(e) => list.setFilter("open", e.target.value)} aria-label="Open state">
              <option value="true">Open & acknowledged</option><option value="false">Closed</option><option value="">All</option>
            </select>
            <select value={list.filters.status || ""} onChange={(e) => list.setFilter("status", e.target.value)} aria-label="Status">
              <option value="">Any status</option>
              {Object.entries(ALERT_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.detection_type || ""} onChange={(e) => list.setFilter("detection_type", e.target.value)} aria-label="Detection type">
              <option value="">Any detection</option>
              {Object.entries(DETECTION_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.severity_min || ""} onChange={(e) => list.setFilter("severity_min", e.target.value)} aria-label="Minimum severity">
              <option value="">Any severity</option>
              {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}+</option>)}
            </select>
          </div>
        </div>
        <ErrorState error={list.error} onRetry={list.reload} />
        <DataTable rows={list.rows} loading={list.loading} ordering={list.ordering} onSort={list.setOrdering}
          emptyText="No alerts — nothing needs triage." columns={[
            { key: "severity", label: "Severity", sortKey: "severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "title", label: "Alert", render: (r) => <div><div>{r.title}</div><div className="faint small">{r.description}</div></div> },
            { key: "detection_type", label: "Source", render: (r) => DETECTION_TYPES[r.detection_type] || r.detection_type },
            { key: "asset", label: "Asset", render: (r) => r.asset_name || "—" },
            { key: "mitre", label: "ATT&CK", render: (r) => <Techniques items={r.mitre_techniques} max={2} /> },
            { key: "incident", label: "Incident", render: (r) => r.incident ? <Link to={`/incidents/${r.incident}`}>#{r.incident}</Link> : "—" },
            { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
            { key: "created_at", label: "Raised", sortKey: "created_at", render: (r) => timeAgo(r.created_at) },
            { key: "actions", label: "", render: (r) => (
              <span className="row" style={{ flexWrap: "nowrap" }}>
                {r.status === "open" && <button className="btn small" disabled={busyId === r.id} onClick={() => act(r, "acknowledge")}>Ack</button>}
                {["open", "acknowledged"].includes(r.status) && <>
                  <button className="btn small" disabled={busyId === r.id} onClick={() => act(r, "resolve")}>Resolve</button>
                  <button className="btn small ghost" disabled={busyId === r.id} onClick={() => act(r, "dismiss")}>Dismiss</button>
                </>}
                {["resolved", "dismissed"].includes(r.status) && <button className="btn small ghost" disabled={busyId === r.id} onClick={() => act(r, "reopen")}>Reopen</button>}
              </span>
            ) },
          ]} />
        <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
      </Card>
    </>
  );
}
