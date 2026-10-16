import { useState } from "react";

import { StatusBadge } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import { BarChart } from "../components/Charts";
import DataTable from "../components/DataTable";
import { ErrorState, Loading, useToast } from "../components/Feedback";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import { timeAgo } from "../lib/format";

export default function Compliance() {
  const toast = useToast();
  const summary = useApi("/compliance/summary/");
  const controls = useApi("/compliance/");
  const [framework, setFramework] = useState("nist_csf");
  const [busy, setBusy] = useState(false);

  async function evaluate() {
    setBusy(true);
    try {
      summary.setData(await api.post("/compliance/evaluate/"));
      controls.reload(true);
      toast("Controls re-evaluated against live platform state", "success");
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function override(control, status) {
    try {
      await api.patch(`/compliance/${control.id}/`, { status, manual_override: Boolean(control.check_key) });
      controls.reload(true);
      summary.reload(true);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  if ((summary.loading && !summary.data) || (controls.loading && !controls.data)) return <Loading />;
  const frameworks = summary.data?.frameworks || [];
  const rows = (controls.data || []).filter((c) => c.framework === framework);

  return (
    <>
      <PageHeader title="Compliance readiness" description="Framework controls mapped to automated checks on live telemetry, assets, incidents and exposure.">
        <button className="btn primary" disabled={busy} onClick={evaluate}>{busy ? "Evaluating…" : "Re-evaluate now"}</button>
      </PageHeader>
      <ErrorState error={summary.error || controls.error} />
      <div className="grid grid-main-side">
        <Card title="Audit readiness by framework">
          <BarChart labels={frameworks.map((f) => f.label)} values={frameworks.map((f) => f.readiness)} label="Readiness %"
            colors={frameworks.map((f) => (f.readiness >= 80 ? "#22c55e" : f.readiness >= 50 ? "#eab308" : "#ef4444"))} />
        </Card>
        <Card title="Control status">
          <div className="stack" style={{ gap: 10 }}>
            {frameworks.map((f) => (
              <button key={f.framework} className={`btn ${framework === f.framework ? "primary" : ""}`} style={{ justifyContent: "space-between" }}
                onClick={() => setFramework(f.framework)}>
                <span>{f.label}</span><span>{f.readiness}% · {f.counts.pass || 0}✓ {f.counts.partial || 0}~ {f.counts.fail || 0}✗</span>
              </button>
            ))}
          </div>
          <p className="faint small">Readiness is point-in-time evidence for audit preparation, not a certification.</p>
        </Card>
      </div>
      <Card title={frameworks.find((f) => f.framework === framework)?.label} flush className="mt">
        <DataTable rows={rows} columns={[
          { key: "control_id", label: "Control", render: (r) => <span className="mono">{r.control_id}</span> },
          { key: "title", label: "Requirement" },
          { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "score", label: "Score", render: (r) => (r.check_key || r.manual_override ? `${r.score}%` : "—") },
          { key: "evidence", label: "Evidence", render: (r) => <span className="small muted">{r.evidence || (r.check_key ? "" : "Manual control — record evidence during the audit.")}</span> },
          { key: "evaluated", label: "Evaluated", render: (r) => (r.last_evaluated ? timeAgo(r.last_evaluated) : "—") },
          { key: "override", label: "Override", render: (r) => (
            <select value={r.manual_override || !r.check_key ? r.status : ""} onChange={(e) => e.target.value && override(r, e.target.value)} aria-label={`Override ${r.control_id}`}>
              {r.check_key && !r.manual_override && <option value="">Automated</option>}
              {["pass", "partial", "fail", "manual", "not_applicable"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
            </select>
          ) },
        ]} />
      </Card>
    </>
  );
}
