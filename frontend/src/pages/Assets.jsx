import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { RiskScore, SeverityBadge, StatusBadge } from "../components/Badges";
import { BarList, Card, Kpi, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState, Loading, useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Drawer } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { useList } from "../hooks/useList";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ASSET_TYPES, formatDate, timeAgo } from "../lib/format";

function AssetDrawer({ id, onClose, onChanged }) {
  const toast = useToast();
  const navigate = useNavigate();
  const { canRespond, canUseTerminal } = useAuth();
  const asset = useApi(`/assets/${id}/`);
  const risk = useApi(`/assets/${id}/risk/`);
  const timeline = useApi(`/assets/${id}/timeline/`);
  const a = asset.data;

  async function containment(type) {
    try {
      const result = await api.post("/response-actions/", { action_type: type, asset: id });
      toast(`${type === "isolate_host" ? "Isolation" : "Release"}: ${result.status}`, result.status === "succeeded" ? "success" : "error");
      asset.reload();
      risk.reload();
      onChanged();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function markManaged() {
    try {
      asset.setData(await api.patch(`/assets/${id}/`, { managed: true }));
      toast("Asset marked as managed", "success");
      onChanged();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  return (
    <Drawer title={a ? (a.hostname || a.ip_address) : "Asset"} subtitle={a && `${ASSET_TYPES[a.asset_type]} · ${a.operating_system || "unknown OS"} · ${a.department || "no department"}`}
      onClose={onClose} actions={a && canRespond && (a.is_isolated
        ? <button className="btn small" onClick={() => containment("release_host")}><Icon name="unlock" />Release</button>
        : <button className="btn small danger" onClick={() => containment("isolate_host")}><Icon name="lock" />Isolate host</button>)}>
      {!a ? <Loading /> : (
        <>
          <div className="row">
            <RiskScore score={a.risk_score} />
            {a.is_shadow_it ? <span className="badge warn">Shadow IT</span> : <span className="badge ok">Managed</span>}
            {a.is_isolated && <span className="badge ok">Isolated {timeAgo(a.isolated_at)}</span>}
            {a.is_shadow_it && <button className="btn small" onClick={markManaged}>Mark as managed</button>}
            {canUseTerminal && a.managed && <button className="btn small" onClick={() => navigate(`/response?terminal=${a.id}`)}><Icon name="terminal" />Live response</button>}
          </div>
          <dl className="dl">
            <dt>IP / MAC</dt><dd className="mono">{a.ip_address || "—"} / {a.mac_address || "—"}</dd>
            <dt>Owner</dt><dd>{a.owner || "—"}</dd>
            <dt>Criticality</dt><dd><SeverityBadge value={a.criticality} /></dd>
            <dt>Discovered via</dt><dd>{a.discovered_via.replace(/_/g, " ")}</dd>
            {a.cloud_provider && <><dt>Cloud</dt><dd className="mono small">{a.cloud_provider} {a.cloud_resource_id}</dd></>}
            <dt>First / last seen</dt><dd>{formatDate(a.first_seen)} → {formatDate(a.last_seen)}</dd>
            <dt>Vulnerabilities</dt><dd>{a.vulnerabilities.length ? a.vulnerabilities.map((v) => `${v.cve} (CVSS ${v.cvss})`).join(", ") : "none recorded"}</dd>
            <dt>Software</dt><dd>{a.software.length ? a.software.slice(0, 12).map((s) => `${s.name} ${s.version || ""}`).join(", ") : "—"}</dd>
          </dl>
          {risk.data && (
            <section>
              <h3>Dynamic risk</h3>
              <dl className="dl mt">
                <dt>Criticality base</dt><dd>{risk.data.criticality_base}</dd>
                <dt>Open alerts</dt><dd>{risk.data.open_alerts} (+{risk.data.alert_points})</dd>
                <dt>Max CVSS</dt><dd>{risk.data.max_cvss} (+{risk.data.cvss_points})</dd>
                <dt>Shadow IT</dt><dd>+{risk.data.shadow_it_points}</dd>
                <dt>Behavioural drift</dt><dd>{risk.data.behaviour_zscore ?? "insufficient baseline"} {risk.data.behaviour_points ? `(+${risk.data.behaviour_points})` : ""}</dd>
              </dl>
            </section>
          )}
          <section>
            <h3>Recent activity</h3>
            <ul className="timeline mt">
              {(timeline.data || []).slice(0, 25).map((e) => (
                <li key={e.id}><span className="faint small">{formatDate(e.timestamp)}</span><span className="tl-dot" style={{ background: `var(--sev-${["low", "medium", "high", "critical"][e.severity - 1]})` }} />
                  <span><span className="mono small">{e.event_type}</span> {e.message}</span></li>
              ))}
            </ul>
          </section>
        </>
      )}
    </Drawer>
  );
}

export default function Assets() {
  const discovery = useApi("/assets/discovery/", null, { pollMs: 60000 });
  const list = useList("/assets/", { ordering: "-risk_score" });
  const [selected, setSelected] = useState(null);
  const d = discovery.data;

  return (
    <>
      <PageHeader title="Assets & shadow IT" description="Inventory built automatically from agents, cloud APIs and passive network telemetry." />
      <div className="grid grid-kpi">
        <Kpi label="Total assets" value={d?.total} sub={`${d?.active_24h ?? 0} active in 24h`} />
        <Kpi label="Managed" value={d?.managed} tone="ok" />
        <Kpi label="Shadow IT" value={d?.shadow_it} tone={d?.shadow_it ? "high" : "ok"} sub="No agent / unknown owner" />
        <Kpi label="Isolated" value={d?.isolated} />
        <Kpi label="New this week" value={d?.new_7d} />
      </div>
      <div className="grid grid-main-side mt">
        <Card flush title="Inventory">
          <div className="card-body" style={{ paddingBottom: 0 }}>
            <div className="filters">
              <input type="search" placeholder="Search host, IP, owner, OS" value={list.search} onChange={(e) => list.setSearch(e.target.value)} aria-label="Search assets" />
              <select value={list.filters.asset_type || ""} onChange={(e) => list.setFilter("asset_type", e.target.value)} aria-label="Asset type">
                <option value="">All types</option>{Object.entries(ASSET_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <select value={list.filters.managed ?? ""} onChange={(e) => list.setFilter("managed", e.target.value)} aria-label="Management">
                <option value="">Managed & unmanaged</option><option value="true">Managed</option><option value="false">Shadow IT</option>
              </select>
              <label className="check"><input type="checkbox" checked={list.filters.is_isolated === "true"} onChange={(e) => list.setFilter("is_isolated", e.target.checked ? "true" : "")} />Isolated</label>
            </div>
          </div>
          <ErrorState error={list.error} onRetry={list.reload} />
          <DataTable rows={list.rows} loading={list.loading} ordering={list.ordering} onSort={list.setOrdering}
            onRowClick={(r) => setSelected(r.id)} selectedKey={selected} columns={[
              { key: "risk_score", label: "Risk", sortKey: "risk_score", render: (r) => <RiskScore score={r.risk_score} /> },
              { key: "hostname", label: "Asset", sortKey: "hostname", render: (r) => <div><strong>{r.hostname || <span className="muted">unnamed</span>}</strong><div className="faint small mono">{r.ip_address}</div></div> },
              { key: "asset_type", label: "Type", render: (r) => ASSET_TYPES[r.asset_type] },
              { key: "department", label: "Department", render: (r) => r.department || "—" },
              { key: "criticality", label: "Criticality", sortKey: "criticality", render: (r) => <SeverityBadge value={r.criticality} /> },
              { key: "managed", label: "Agent", render: (r) => r.managed ? <span className="badge ok">managed</span> : <span className="badge warn">shadow IT</span> },
              { key: "open_alerts", label: "Alerts", render: (r) => r.open_alerts || "—" },
              { key: "state", label: "State", render: (r) => r.is_isolated ? <StatusBadge value="contained" label="isolated" /> : "online" },
              { key: "last_seen", label: "Last seen", sortKey: "last_seen", render: (r) => timeAgo(r.last_seen) },
            ]} />
          <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
        </Card>
        <div className="stack">
          <Card title="Coverage by type">
            <BarList items={(d?.by_type || []).map((t) => ({ key: t.asset_type, label: `${ASSET_TYPES[t.asset_type]} (${t.unmanaged} unmanaged)`, count: t.count }))} />
          </Card>
          <Card title="Newly discovered shadow IT">
            <div className="stack" style={{ gap: 8 }}>
              {(d?.recent_shadow_it || []).map((a) => (
                <button key={a.id} className="btn ghost" style={{ justifyContent: "space-between" }} onClick={() => setSelected(a.id)}>
                  <span className="mono">{a.hostname || a.ip_address}</span><span className="faint small">{timeAgo(a.first_seen)}</span>
                </button>
              ))}
              {!d?.recent_shadow_it?.length && <span className="muted small">No unmanaged devices.</span>}
            </div>
          </Card>
        </div>
      </div>
      {selected && <AssetDrawer id={selected} onClose={() => setSelected(null)} onChanged={() => { list.reload(true); discovery.reload(true); }} />}
    </>
  );
}
