import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import AttackPathGraph from "../components/AttackPathGraph";
import { RiskScore, SeverityBadge, StatusBadge, Techniques } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable from "../components/DataTable";
import { ErrorState, Loading, useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { DETECTION_TYPES, formatDate, INCIDENT_STATUS } from "../lib/format";

export default function IncidentDetail() {
  const { id } = useParams();
  const toast = useToast();
  const { user, canRespond } = useAuth();
  const incident = useApi(`/incidents/${id}/`, null, { pollMs: 30000 });
  const graph = useApi(`/incidents/${id}/attack-path/`);
  const alerts = useApi(`/incidents/${id}/alerts/`, null, { pollMs: 30000 });
  const attribution = useApi(`/incidents/${id}/attribution/`);
  const actions = useApi(`/incidents/${id}/actions/`);
  const playbooks = useApi("/playbooks/");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(null);

  if (incident.loading && !incident.data) return <Loading />;
  if (incident.error && !incident.data) return <ErrorState error={incident.error} onRetry={incident.reload} />;
  const inc = incident.data;
  const users = [...new Set((graph.data?.nodes || []).filter((n) => n.type === "user").map((n) => n.label))];

  async function update(changes, message) {
    setBusy(true);
    try {
      incident.setData(await api.patch(`/incidents/${id}/`, changes));
      toast(message, "success");
      alerts.reload();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function runAction(body, label) {
    setBusy(true);
    try {
      const result = await api.post("/response-actions/", { ...body, incident: Number(id) });
      toast(`${label}: ${result.status}`, result.status === "succeeded" ? "success" : "error");
      incident.reload();
      graph.reload();
      actions.reload();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  async function runPlaybook(playbook, target) {
    setBusy(true);
    try {
      const result = await api.post(`/playbooks/${playbook.id}/run/`, { incident: Number(id), ...target });
      toast(`${playbook.name}: ${result.status}`, result.status === "succeeded" ? "success" : "error");
      incident.reload();
      graph.reload();
      actions.reload();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  async function applyAttribution() {
    try {
      await api.post(`/incidents/${id}/attribution/`, { min_confidence: 50 });
      toast("Attribution applied to the incident", "success");
      incident.reload();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  const byKind = (kind) => (playbooks.data?.results || []).filter((p) => p.target_kind === kind && p.enabled);

  return (
    <>
      <PageHeader title={inc.title} description={inc.summary}>
        <Link to="/incidents" className="btn">Back to queue</Link>
      </PageHeader>

      <div className="grid grid-kpi">
        <div className="card kpi"><div className="kpi-label">Priority</div><div className="kpi-value"><RiskScore score={inc.priority_score} /></div></div>
        <div className="card kpi"><div className="kpi-label">Severity</div><div className="kpi-value"><SeverityBadge value={inc.severity} /></div></div>
        <div className="card kpi"><div className="kpi-label">Correlated alerts</div><div className="kpi-value">{inc.alert_count}</div></div>
        <div className="card kpi"><div className="kpi-label">Assets involved</div><div className="kpi-value">{inc.assets.length}</div></div>
        <div className="card kpi"><div className="kpi-label">First → last activity</div>
          <div className="small" style={{ marginTop: 6 }}>{formatDate(inc.first_activity)}<br />{formatDate(inc.last_activity)}</div></div>
      </div>

      <Card title="Case management" className="mt">
        <div className="row">
          <label className="field">Status
            <select value={inc.status} disabled={busy} onChange={(e) => update({ status: e.target.value }, "Status updated")}>
              {Object.entries(INCIDENT_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <div className="field">Assignee
            <div className="row">
              <span>{inc.assigned_to_username || "Unassigned"}</span>
              {inc.assigned_to !== user.id && (
                <button className="btn small" disabled={busy} onClick={() => update({ assigned_to: user.id }, "Assigned to you")}>Assign to me</button>
              )}
            </div>
          </div>
          <div className="field" style={{ flex: 1 }}>Techniques<div><Techniques items={inc.mitre_techniques} max={12} /></div></div>
        </div>
      </Card>

      <Card title="Attack path" subtitle="How the attacker entered, moved laterally and where data left the network" className="mt">
        {graph.loading && !graph.data ? <Loading /> : <AttackPathGraph graph={graph.data} />}
      </Card>

      <div className="grid grid-main-side mt">
        <Card title="Alert timeline" flush>
          <DataTable rows={alerts.data} loading={alerts.loading} columns={[
            { key: "created_at", label: "Time", render: (r) => <span style={{ whiteSpace: "nowrap" }} title={formatDate(r.created_at)}>{new Date(r.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span> },
            { key: "title", label: "Alert", render: (r) => <div><div>{r.title}</div><div className="faint small">{r.description}</div></div> },
            { key: "detection_type", label: "Source", render: (r) => DETECTION_TYPES[r.detection_type] || r.detection_type },
            { key: "severity", label: "Severity", render: (r) => <SeverityBadge value={r.severity} /> },
            { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
          ]} />
        </Card>

        <div className="stack">
          <Card title="Actor attribution" subtitle="Matched on shared indicators, ATT&CK techniques and malware families"
            actions={attribution.data?.results?.length ? <button className="btn small" onClick={applyAttribution}>Apply ≥50%</button> : null}>
            {attribution.loading ? <Loading /> : attribution.data?.results?.length ? (
              <div className="stack" style={{ gap: 10 }}>
                {attribution.data.results.map((r) => (
                  <div key={r.actor_id}>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <strong>{r.name}</strong><span className="badge info">{r.confidence}% confidence</span>
                    </div>
                    <div className="faint small">{r.aliases.slice(0, 3).join(", ")}</div>
                    <div className="small muted">
                      {r.evidence.shared_indicators.length} shared IoCs · TTPs: {r.evidence.shared_techniques.join(", ") || "none"}
                      {r.evidence.malware_families.length ? ` · malware: ${r.evidence.malware_families.join(", ")}` : ""}
                    </div>
                  </div>
                ))}
                <div className="faint small">Attribution is an analytical aid, not proof.</div>
              </div>
            ) : <div className="muted small">No known actor matches the evidence.</div>}
          </Card>

          <Card title="Respond" subtitle={canRespond ? "Actions are audited and run through the response connector" : "Requires the responders group"}>
            <div className="stack" style={{ gap: 12 }}>
              {inc.assets.map((asset) => (
                <div key={asset.id} className="row" style={{ justifyContent: "space-between" }}>
                  <span>
                    <Icon name="server" size={14} /> {asset.name}
                    {asset.is_isolated && <span className="badge ok" style={{ marginLeft: 6 }}>isolated</span>}
                    {!asset.managed && <span className="badge warn" style={{ marginLeft: 6 }}>no agent</span>}
                  </span>
                  <span className="row">
                    {asset.is_isolated ? (
                      <button className="btn small" disabled={!canRespond || busy}
                        onClick={() => runAction({ action_type: "release_host", asset: asset.id }, "Release")}>
                        <Icon name="unlock" />Release
                      </button>
                    ) : (
                      <button className="btn small danger" disabled={!canRespond || busy}
                        onClick={() => setConfirm({ label: `Isolate ${asset.name} from the network?`,
                          run: () => runAction({ action_type: "isolate_host", asset: asset.id }, "Isolation") })}>
                        <Icon name="lock" />Isolate
                      </button>
                    )}
                    {byKind("asset").map((p) => (
                      <button key={p.id} className="btn small" disabled={!canRespond || busy}
                        onClick={() => setConfirm({ label: `Run "${p.name}" on ${asset.name}?`, run: () => runPlaybook(p, { asset: asset.id }) })}>
                        <Icon name="play" />{p.name}
                      </button>
                    ))}
                  </span>
                </div>
              ))}
              {users.map((name) => (
                <div key={name} className="row" style={{ justifyContent: "space-between" }}>
                  <span><Icon name="user" size={14} /> {name}</span>
                  <span className="row">
                    {byKind("user").map((p) => (
                      <button key={p.id} className="btn small" disabled={!canRespond || busy}
                        onClick={() => setConfirm({ label: `Run "${p.name}" for ${name}?`, run: () => runPlaybook(p, { target_user: name }) })}>
                        <Icon name="play" />{p.name}
                      </button>
                    ))}
                  </span>
                </div>
              ))}
              {byKind("global").map((p) => (
                <button key={p.id} className="btn danger" disabled={!canRespond || busy}
                  onClick={() => setConfirm({ label: `${p.name}: ${p.description} This affects every user.`,
                    run: () => runPlaybook(p, { confirm: true }) })}>
                  <Icon name="zap" />{p.name}
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <Card title="Response history" flush className="mt">
        <DataTable rows={actions.data} emptyText="No response actions yet." columns={[
          { key: "created_at", label: "Time", render: (r) => formatDate(r.created_at) },
          { key: "action_type", label: "Action", render: (r) => r.playbook_name ? `${r.action_type.replace(/_/g, " ")} (${r.playbook_name})` : r.action_type.replace(/_/g, " ") },
          { key: "target", label: "Target", render: (r) => r.asset_name || r.target_user || r.indicator_value || "global" },
          { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "by", label: "By", render: (r) => r.requested_by_username || "system" },
          { key: "output", label: "Output", render: (r) => <span className="small muted">{(r.output || r.error).split("\n")[0]}</span> },
        ]} />
      </Card>

      {confirm && (
        <Modal title="Confirm response action" onClose={() => setConfirm(null)} footer={<>
          <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
          <button className="btn danger" disabled={busy} onClick={confirm.run}>Confirm</button>
        </>}>
          <p style={{ margin: 0 }}>{confirm.label}</p>
        </Modal>
      )}
    </>
  );
}
