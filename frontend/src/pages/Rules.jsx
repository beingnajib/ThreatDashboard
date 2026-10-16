import { useState } from "react";

import { SeverityBadge } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable from "../components/DataTable";
import { useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { IOC_TYPES, SEVERITY, THREAT_TYPES, timeAgo } from "../lib/format";

const EMPTY = { name: "", description: "", enabled: true, ioc_types: [], threat_types: [], tags: "", mitre_techniques: "",
  min_severity: "", min_confidence: "", min_risk_score: "", value_pattern: "", countries: "", alert_severity: "" };

function toPayload(form) {
  const split = (s) => s.split(/[,\s]+/).map((v) => v.trim()).filter(Boolean);
  const num = (v) => (v === "" || v === null ? null : Number(v));
  return {
    ...form, tags: split(form.tags), mitre_techniques: split(form.mitre_techniques), countries: split(form.countries),
    min_severity: num(form.min_severity), min_confidence: num(form.min_confidence), min_risk_score: num(form.min_risk_score),
    alert_severity: num(form.alert_severity),
  };
}

function MultiSelect({ options, value, onChange, label }) {
  return (
    <label className="field">{label}
      <select multiple value={value} size={5} onChange={(e) => onChange([...e.target.selectedOptions].map((o) => o.value))}>
        {Object.entries(options).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select>
    </label>
  );
}

export default function Rules() {
  const toast = useToast();
  const { isStaff } = useAuth();
  const rules = useApi("/rules/", { page_size: 200, ordering: "name" });
  const [editing, setEditing] = useState(null);
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState("");

  function edit(rule) {
    setError("");
    setPreview(null);
    setEditing(rule ? {
      ...rule, tags: rule.tags.join(", "), mitre_techniques: rule.mitre_techniques.join(", "), countries: rule.countries.join(", "),
      min_severity: rule.min_severity ?? "", min_confidence: rule.min_confidence ?? "", min_risk_score: rule.min_risk_score ?? "",
      alert_severity: rule.alert_severity ?? "",
    } : { ...EMPTY });
  }

  async function save(event) {
    event.preventDefault();
    setError("");
    try {
      const body = toPayload(editing);
      if (editing.id) await api.patch(`/rules/${editing.id}/`, body);
      else await api.post("/rules/", body);
      toast("Rule saved", "success");
      setEditing(null);
      rules.reload();
    } catch (err) {
      setError(err.message);
    }
  }

  async function test() {
    setError("");
    try {
      setPreview((await api.post("/rules/test/", toPayload(editing))).matches);
    } catch (err) {
      setError(err.message);
    }
  }

  async function run(rule) {
    try {
      const result = await api.post(`/rules/${rule.id}/run/`);
      toast(`${rule.name}: ${result.alerts_created} new alert(s)`, "success");
      rules.reload(true);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function toggle(rule) {
    try {
      await api.patch(`/rules/${rule.id}/`, { enabled: !rule.enabled });
      rules.reload(true);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function remove(rule) {
    if (!window.confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await api.del(`/rules/${rule.id}/`);
      rules.reload();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  const set = (key) => (e) => setEditing({ ...editing, [key]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  return (
    <>
      <PageHeader title="Detection rules" description="Watchlists evaluated on every new or updated indicator. Matching conditions are combined with AND.">
        <button className="btn primary" onClick={() => edit(null)}><Icon name="plus" />New rule</button>
      </PageHeader>
      <Card flush>
        <DataTable rows={rules.data?.results} loading={rules.loading} emptyText="No rules yet." columns={[
          { key: "name", label: "Rule", render: (r) => <div><strong>{r.name}</strong><div className="faint small">{r.description}</div></div> },
          { key: "conditions", label: "Conditions", render: (r) => <span className="small muted">{[
            r.threat_types.length && `threat ∈ ${r.threat_types.join("/")}`, r.ioc_types.length && `type ∈ ${r.ioc_types.join("/")}`,
            r.min_severity && `severity ≥ ${SEVERITY[r.min_severity]}`, r.min_confidence != null && `confidence ≥ ${r.min_confidence}`,
            r.min_risk_score != null && `risk ≥ ${r.min_risk_score}`, r.tags.length && `tags ∋ ${r.tags.join("/")}`,
            r.mitre_techniques.length && `ATT&CK ∋ ${r.mitre_techniques.join("/")}`, r.value_pattern && `value ~ /${r.value_pattern}/`,
            r.countries.length && `country ∈ ${r.countries.join("/")}`].filter(Boolean).join(" · ")}</span> },
          { key: "alert_severity", label: "Raises", render: (r) => r.alert_severity ? <SeverityBadge value={r.alert_severity} /> : <span className="faint small">inherit</span> },
          { key: "hits", label: "Hits", render: (r) => <div>{r.hit_count}<div className="faint small">{r.last_triggered_at ? timeAgo(r.last_triggered_at) : "never"}</div></div> },
          { key: "enabled", label: "Enabled", render: (r) => <label className="check"><input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} /></label> },
          { key: "actions", label: "", render: (r) => <span className="row" style={{ flexWrap: "nowrap" }}>
            <button className="btn small" onClick={() => edit(r)}>Edit</button>
            <button className="btn small" disabled={!r.enabled} onClick={() => run(r)} title="Retro-hunt existing indicators">Run</button>
            {isStaff && <button className="btn small ghost" onClick={() => remove(r)}>Delete</button>}
          </span> },
        ]} />
      </Card>
      {editing && (
        <Modal title={editing.id ? "Edit rule" : "New rule"} onClose={() => setEditing(null)} footer={<>
          {preview !== null && <span className="muted small" style={{ marginRight: "auto" }}>Currently matches {preview} indicator(s)</span>}
          <button className="btn" type="button" onClick={test}>Dry run</button>
          <button className="btn primary" type="submit" form="rule-form">Save</button>
        </>}>
          <form id="rule-form" className="stack" style={{ gap: 12 }} onSubmit={save}>
            <label className="field">Name<input required value={editing.name} onChange={set("name")} /></label>
            <label className="field">Description<input value={editing.description} onChange={set("description")} /></label>
            <div className="form-grid">
              <MultiSelect label="Threat types (any)" options={THREAT_TYPES} value={editing.threat_types} onChange={(v) => setEditing({ ...editing, threat_types: v })} />
              <MultiSelect label="IoC types (any)" options={IOC_TYPES} value={editing.ioc_types} onChange={(v) => setEditing({ ...editing, ioc_types: v })} />
            </div>
            <div className="form-grid">
              <label className="field">Min severity<select value={editing.min_severity} onChange={set("min_severity")}><option value="">—</option>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
              <label className="field">Min confidence<input type="number" min="0" max="100" value={editing.min_confidence} onChange={set("min_confidence")} /></label>
              <label className="field">Min risk score<input type="number" min="0" max="100" value={editing.min_risk_score} onChange={set("min_risk_score")} /></label>
              <label className="field">Alert severity<select value={editing.alert_severity} onChange={set("alert_severity")}><option value="">Inherit</option>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            </div>
            <label className="field">Tags (any)<input value={editing.tags} onChange={set("tags")} placeholder="apt29, cobalt-strike" /></label>
            <label className="field">ATT&CK techniques (any; parents match sub-techniques)<input value={editing.mitre_techniques} onChange={set("mitre_techniques")} placeholder="T1059, T1566" /></label>
            <div className="form-grid">
              <label className="field">Value regex<input className="mono" value={editing.value_pattern} onChange={set("value_pattern")} placeholder="\.(zip|mov)$" /></label>
              <label className="field">Countries<input value={editing.countries} onChange={set("countries")} placeholder="RU, KP" /></label>
            </div>
            <label className="check"><input type="checkbox" checked={editing.enabled} onChange={set("enabled")} />Enabled</label>
            {error && <div className="error-text" role="alert">{error}</div>}
          </form>
        </Modal>
      )}
    </>
  );
}
