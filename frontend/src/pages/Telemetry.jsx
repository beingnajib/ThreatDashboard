import { Fragment, useState } from "react";

import { SeverityBadge, StatusBadge } from "../components/Badges";
import { BarList, Card, Kpi, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState } from "../components/Feedback";
import { Drawer } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { useList } from "../hooks/useList";
import { DOMAINS, formatDate, formatNumber, SEVERITY, timeAgo } from "../lib/format";

export default function Telemetry() {
  const stats = useApi("/events/stats/", null, { pollMs: 15000 });
  const list = useList("/events/", { ordering: "-timestamp", pollMs: 15000, pageSize: 50 });
  const [selected, setSelected] = useState(null);
  const detail = useApi(selected ? `/events/${selected}/` : null);
  const s = stats.data;

  return (
    <>
      <PageHeader title="Unified telemetry"
        description="Endpoint, cloud (AWS / Azure), identity, network and email logs fused into one normalised stream." />
      <div className="grid grid-kpi">
        <Kpi label="Events (24h)" value={formatNumber(s?.last_24h)} />
        <Kpi label="Matched threat intel (24h)" value={formatNumber(s?.matched_last_24h)} tone={s?.matched_last_24h ? "critical" : "ok"} />
        {Object.entries(DOMAINS).map(([key, label]) => {
          const count = s?.by_domain?.find((d) => d.domain === key)?.count || 0;
          return <Kpi key={key} label={label} value={formatNumber(count)} sub={count ? "receiving" : "no data in 24h"} tone={count ? "" : "high"} />;
        })}
      </div>
      <div className="grid grid-main-side mt">
        <Card flush title="Event stream">
          <div className="card-body" style={{ paddingBottom: 0 }}>
            <div className="filters">
              <input type="search" placeholder="Search message, user, host, domain, process" value={list.search}
                onChange={(e) => list.setSearch(e.target.value)} aria-label="Search events" />
              <select value={list.filters.domain || ""} onChange={(e) => list.setFilter("domain", e.target.value)} aria-label="Domain">
                <option value="">All domains</option>{Object.entries(DOMAINS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <select value={list.filters.severity_min || ""} onChange={(e) => list.setFilter("severity_min", e.target.value)} aria-label="Minimum severity">
                <option value="">Any severity</option>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}+</option>)}
              </select>
              <select value={list.filters.outcome || ""} onChange={(e) => list.setFilter("outcome", e.target.value)} aria-label="Outcome">
                <option value="">Any outcome</option><option value="success">Success</option><option value="failure">Failure</option>
              </select>
              <label className="check"><input type="checkbox" checked={list.filters.matched === "true"} onChange={(e) => list.setFilter("matched", e.target.checked ? "true" : "")} />IoC matches only</label>
            </div>
          </div>
          <ErrorState error={list.error} onRetry={list.reload} />
          <DataTable rows={list.rows} loading={list.loading} onRowClick={(r) => setSelected(r.id)} selectedKey={selected} columns={[
            { key: "timestamp", label: "Time", render: (r) => <span title={formatDate(r.timestamp)}>{timeAgo(r.timestamp)}</span> },
            { key: "domain", label: "Domain", render: (r) => <span className="badge">{DOMAINS[r.domain]}</span> },
            { key: "provider", label: "Source" },
            { key: "event_type", label: "Event", render: (r) => <span className="mono small">{r.event_type}</span> },
            { key: "severity", label: "Severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "subject", label: "Subject", render: (r) => r.asset_name || r.username || r.src_ip || "—" },
            { key: "message", label: "Detail", render: (r) => <span className="small muted">{r.message}</span> },
            { key: "intel", label: "Intel", render: (r) => r.matched_indicators.length ? <span className="badge danger">{r.matched_indicators.length} match</span> : "" },
          ]} />
          <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
        </Card>
        <div className="stack">
          <Card title="Top providers (24h)"><BarList items={(s?.by_provider || []).map((p) => ({ key: p.provider, label: p.provider || "unknown", count: p.count }))} /></Card>
          <Card title="Connectors" subtitle="Manage under Feeds & connectors">
            <div className="stack" style={{ gap: 8 }}>
              {(s?.connectors || []).map((c) => (
                <div key={c.id} className="row" style={{ justifyContent: "space-between" }}>
                  <span>{c.name}<div className="faint small">{c.provider} · {formatNumber(c.events_received)} events</div></span>
                  <StatusBadge value={c.enabled ? (c.last_event_at ? "active" : "pending") : "dismissed"}
                    label={c.enabled ? (c.last_event_at ? `seen ${timeAgo(c.last_event_at)}` : "waiting") : "disabled"} />
                </div>
              ))}
              {!s?.connectors?.length && <span className="muted small">No connectors configured.</span>}
            </div>
          </Card>
        </div>
      </div>
      {selected && (
        <Drawer title={detail.data?.event_type || "Event"} subtitle={detail.data && formatDate(detail.data.timestamp)} onClose={() => setSelected(null)}>
          {detail.data && (
            <>
              <dl className="dl">
                {["domain", "provider", "outcome", "message", "username", "src_ip", "dst_ip", "dst_port", "asset_name", "target_asset_name",
                  "domain_name", "url", "file_hash", "process", "bytes_out", "country", "mitre_technique"].map((k) => detail.data[k] ? (
                  <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd className="mono small">{String(detail.data[k])}</dd></Fragment>
                ) : null)}
              </dl>
              <section><h3>Raw event</h3><pre className="terminal" style={{ height: "auto", maxHeight: 360 }}>{JSON.stringify(detail.data.raw, null, 2)}</pre></section>
            </>
          )}
        </Drawer>
      )}
    </>
  );
}
