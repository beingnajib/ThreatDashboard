import { Fragment, useState } from "react";

import { RiskScore, SeverityBadge, StatusBadge, Tags, Techniques } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState, Loading, useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Drawer, Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { useList } from "../hooks/useList";
import { api, download } from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  defang, formatDate, INDICATOR_STATUS, IOC_TYPES, SEVERITY, THREAT_TYPES, timeAgo, TLP,
} from "../lib/format";

function IndicatorDrawer({ id, onClose, onChanged }) {
  const toast = useToast();
  const { canRespond } = useAuth();
  const detail = useApi(`/indicators/${id}/`);
  const related = useApi(`/indicators/${id}/related/`);
  const attribution = useApi(`/indicators/${id}/attribution/`);
  const sightings = useApi(`/indicators/${id}/sightings/`);
  const ind = detail.data;

  async function setStatus(status) {
    try {
      detail.setData(await api.patch(`/indicators/${id}/`, { status }));
      toast("Status updated", "success");
      onChanged();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function block() {
    try {
      const result = await api.post("/response-actions/", { action_type: "block_indicator", indicator: id });
      toast(`Block: ${result.status}`, result.status === "succeeded" ? "success" : "error");
      detail.reload();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  return (
    <Drawer title={ind ? ind.value : "Indicator"} onClose={onClose}
      subtitle={ind && `${IOC_TYPES[ind.ioc_type]} · ${THREAT_TYPES[ind.threat_type]} · defanged: ${defang(ind.value)}`}
      actions={ind && canRespond && !ind.tags.includes("blocked") && <button className="btn small danger" onClick={block}><Icon name="lock" />Block</button>}>
      {!ind ? <Loading /> : (
        <>
          <div className="row">
            <RiskScore score={ind.risk_score} /><SeverityBadge value={ind.severity} /><StatusBadge value={ind.status} />
            <span className="badge">{TLP[ind.tlp]}</span>
            <select value={ind.status} onChange={(e) => setStatus(e.target.value)} aria-label="Change status">
              {Object.entries(INDICATOR_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <dl className="dl">
            <dt>Source</dt><dd>{ind.source_name || "—"}</dd>
            <dt>Confidence</dt><dd>{ind.confidence}%</dd>
            {ind.cvss_score && <><dt>CVSS</dt><dd>{ind.cvss_score}</dd></>}
            <dt>First / last seen</dt><dd>{formatDate(ind.first_seen)} → {formatDate(ind.last_seen)}</dd>
            <dt>Sightings</dt><dd>{ind.sighting_count}</dd>
            <dt>Expires</dt><dd>{formatDate(ind.expires_at)}</dd>
            <dt>Country</dt><dd>{ind.country || "—"}</dd>
            <dt>Tags</dt><dd><Tags items={ind.tags} max={20} /></dd>
            <dt>ATT&CK</dt><dd><Techniques items={ind.mitre_techniques} max={20} /></dd>
            <dt>Actors</dt><dd>{ind.actors.map((a) => a.name).join(", ") || "—"}</dd>
            <dt>Description</dt><dd>{ind.description || "—"}</dd>
          </dl>
          <section>
            <h3>Risk score breakdown</h3>
            <dl className="dl mt">
              <dt>Severity base</dt><dd>{ind.score_breakdown.severity_base}{ind.score_breakdown.cvss_score != null && ` (CVSS ${ind.score_breakdown.cvss_score})`}</dd>
              <dt>Confidence × reliability</dt><dd>{ind.score_breakdown.confidence_factor} × {ind.score_breakdown.reliability_factor}</dd>
              <dt>Recency decay</dt><dd>× {ind.score_breakdown.recency_factor}</dd>
              <dt>Bonuses</dt><dd>sightings +{ind.score_breakdown.sightings_bonus}, ATT&CK +{ind.score_breakdown.mitre_bonus}, enrichment +{ind.score_breakdown.enrichment_bonus}</dd>
              <dt>Lifecycle</dt><dd>× {ind.score_breakdown.lifecycle_factor}</dd>
              <dt>Flags</dt><dd>{ind.score_breakdown.enrichment_flags.join(", ") || "none"}</dd>
            </dl>
          </section>
          <section>
            <h3>Enrichment</h3>
            <dl className="dl mt">
              {Object.entries(ind.enrichment).map(([k, v]) => (
                <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd className="mono">{String(v)}</dd></Fragment>
              ))}
            </dl>
          </section>
          <section>
            <h3>Attribution</h3>
            {(attribution.data?.results || []).length ? attribution.data.results.map((r) => (
              <div key={r.actor_id} className="small">{r.name} — {r.confidence}%</div>
            )) : <div className="muted small">No actor match.</div>}
          </section>
          <section>
            <h3>Sightings in telemetry ({sightings.data?.length ?? 0})</h3>
            {(sightings.data || []).slice(0, 8).map((e) => (
              <div key={e.id} className="small">{formatDate(e.timestamp)} · {e.domain}/{e.event_type} · {e.asset_name || e.username || e.src_ip}</div>
            ))}
          </section>
          <section>
            <h3>Related indicators ({related.data?.count ?? 0})</h3>
            <div className="stack" style={{ gap: 6, marginTop: 8 }}>
              {(related.data?.results || []).slice(0, 15).map((r) => (
                <div key={r.id} className="small">
                  <span className="mono">{r.value}</span> <SeverityBadge value={r.severity} />
                  <div className="faint">{r.reasons.join(" · ")}</div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </Drawer>
  );
}

function AddIndicatorModal({ onClose, onCreated }) {
  const toast = useToast();
  const [form, setForm] = useState({ value: "", ioc_type: "", threat_type: "malware", severity: 2, confidence: 70, tags: "", mitre_techniques: "", description: "", tlp: "amber" });
  const [error, setError] = useState("");
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  async function submit(event) {
    event.preventDefault();
    setError("");
    const split = (s) => s.split(/[,\s]+/).map((v) => v.trim()).filter(Boolean);
    const body = { ...form, severity: Number(form.severity), confidence: Number(form.confidence), tags: split(form.tags), mitre_techniques: split(form.mitre_techniques) };
    if (!body.ioc_type) delete body.ioc_type;
    try {
      await api.post("/indicators/", body);
      toast("Indicator added", "success");
      onCreated();
      onClose();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <Modal title="Add indicator" onClose={onClose} footer={<>
      <button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn primary" type="submit" form="add-indicator">Add</button>
    </>}>
      <form id="add-indicator" className="stack" style={{ gap: 12 }} onSubmit={submit}>
        <label className="field">Value (defanged values are fine)<input value={form.value} onChange={set("value")} required placeholder="hxxp://evil[.]example/payload" /></label>
        <div className="form-grid">
          <label className="field">Type<select value={form.ioc_type} onChange={set("ioc_type")}><option value="">Auto-detect</option>{Object.entries(IOC_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Threat<select value={form.threat_type} onChange={set("threat_type")}>{Object.entries(THREAT_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Severity<select value={form.severity} onChange={set("severity")}>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Confidence<input type="number" min="0" max="100" value={form.confidence} onChange={set("confidence")} /></label>
          <label className="field">TLP<select value={form.tlp} onChange={set("tlp")}>{Object.entries(TLP).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        </div>
        <label className="field">Tags (comma separated)<input value={form.tags} onChange={set("tags")} /></label>
        <label className="field">ATT&CK techniques<input value={form.mitre_techniques} onChange={set("mitre_techniques")} placeholder="T1566, T1059.001" /></label>
        <label className="field">Description<textarea rows="3" value={form.description} onChange={set("description")} /></label>
        {error && <div className="error-text" role="alert">{error}</div>}
      </form>
    </Modal>
  );
}

function LookupModal({ onClose }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  async function run() {
    setError("");
    try {
      setResult(await api.post("/indicators/lookup/", { values: text }));
    } catch (err) {
      setError(err.message);
    }
  }
  return (
    <Modal title="Bulk IoC lookup" onClose={onClose} footer={<button className="btn primary" onClick={run} disabled={!text.trim()}>Check</button>}>
      <label className="field">Paste observables (one per line; defanged OK)
        <textarea rows="6" value={text} onChange={(e) => setText(e.target.value)} className="mono" />
      </label>
      {error && <div className="error-text">{error}</div>}
      {result && (
        <div className="stack" style={{ gap: 6 }}>
          <strong>{result.matches} of {result.count} matched known intelligence</strong>
          {result.results.map((r, i) => (
            <div key={i} className="small row">
              <span className="mono">{r.value || r.input}</span>
              {!r.valid ? <span className="badge">invalid</span> : r.match ? <><SeverityBadge value={r.match.severity} /><RiskScore score={r.match.risk_score} /></> : <span className="badge ok">no match</span>}
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

export default function Indicators() {
  const toast = useToast();
  const list = useList("/indicators/", { initialFilters: { actionable: "true" }, ordering: "-risk_score" });
  const [selected, setSelected] = useState(null);
  const [modal, setModal] = useState(null);

  async function exportAs(format) {
    try {
      const params = { ...list.filters, search: list.search, ordering: list.ordering, export_format: format };
      await download("/indicators/export/", params, `indicators.${format === "stix" ? "json" : format}`);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  return (
    <>
      <PageHeader title="Indicators of compromise" description="Normalised, enriched and risk-scored intelligence from every source.">
        <button className="btn" onClick={() => setModal("lookup")}><Icon name="search" />Lookup</button>
        <button className="btn" onClick={() => exportAs("csv")}><Icon name="download" />CSV</button>
        <button className="btn" onClick={() => exportAs("json")}>JSON</button>
        <button className="btn" onClick={() => exportAs("stix")}>STIX 2.1</button>
        <button className="btn primary" onClick={() => setModal("add")}><Icon name="plus" />Add</button>
      </PageHeader>
      <Card flush>
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <div className="filters">
            <input type="search" placeholder="Search value, description, source" value={list.search} onChange={(e) => list.setSearch(e.target.value)} aria-label="Search indicators" />
            <select value={list.filters.ioc_type || ""} onChange={(e) => list.setFilter("ioc_type", e.target.value)} aria-label="Type">
              <option value="">All types</option>{Object.entries(IOC_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.threat_type || ""} onChange={(e) => list.setFilter("threat_type", e.target.value)} aria-label="Threat type">
              <option value="">All threats</option>{Object.entries(THREAT_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.severity_min || ""} onChange={(e) => list.setFilter("severity_min", e.target.value)} aria-label="Minimum severity">
              <option value="">Any severity</option>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}+</option>)}
            </select>
            <select value={list.filters.status || ""} onChange={(e) => { list.setFilter("status", e.target.value); list.setFilter("actionable", ""); }} aria-label="Status">
              <option value="">Any status</option>{Object.entries(INDICATOR_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <label className="check"><input type="checkbox" checked={list.filters.actionable === "true"} onChange={(e) => list.setFilter("actionable", e.target.checked ? "true" : "")} />Actionable only</label>
          </div>
        </div>
        <ErrorState error={list.error} onRetry={list.reload} />
        <DataTable rows={list.rows} loading={list.loading} ordering={list.ordering} onSort={list.setOrdering}
          onRowClick={(row) => setSelected(row.id)} selectedKey={selected} columns={[
            { key: "risk_score", label: "Risk", sortKey: "risk_score", render: (r) => <RiskScore score={r.risk_score} /> },
            { key: "value", label: "Indicator", sortKey: "value", className: "value", render: (r) => <div className="truncate mono" title={r.value}>{r.value}</div> },
            { key: "ioc_type", label: "Type", render: (r) => IOC_TYPES[r.ioc_type] },
            { key: "threat_type", label: "Threat", render: (r) => THREAT_TYPES[r.threat_type] },
            { key: "severity", label: "Severity", sortKey: "severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
            { key: "tags", label: "Tags", render: (r) => <Tags items={r.tags} max={3} /> },
            { key: "open_alerts", label: "Alerts", render: (r) => r.open_alerts || "—" },
            { key: "last_seen", label: "Last seen", sortKey: "last_seen", render: (r) => timeAgo(r.last_seen) },
          ]} />
        <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
      </Card>
      {selected && <IndicatorDrawer id={selected} onClose={() => setSelected(null)} onChanged={() => list.reload(true)} />}
      {modal === "add" && <AddIndicatorModal onClose={() => setModal(null)} onCreated={() => list.reload()} />}
      {modal === "lookup" && <LookupModal onClose={() => setModal(null)} />}
    </>
  );
}
