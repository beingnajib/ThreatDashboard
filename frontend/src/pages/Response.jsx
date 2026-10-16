import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { StatusBadge } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { useList } from "../hooks/useList";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/format";

function Terminal({ assetId }) {
  const toast = useToast();
  const [lines, setLines] = useState([]);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);
  const [cursor, setCursor] = useState(-1);
  const [busy, setBusy] = useState(false);
  const scroller = useRef(null);
  const asset = useApi(assetId ? `/assets/${assetId}/` : null);

  useEffect(() => {
    setLines([{ type: "info", text: "Live response session. Commands are allow-listed, executed through the response connector and recorded in the audit log. Type 'help'." }]);
  }, [assetId]);
  useEffect(() => {
    if (scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [lines]);

  async function run(event) {
    event.preventDefault();
    const text = command.trim();
    if (!text) return;
    setBusy(true);
    setHistory((h) => [text, ...h].slice(0, 50));
    setCursor(-1);
    setCommand("");
    setLines((l) => [...l, { type: "cmd", text }]);
    try {
      const result = await api.post("/response-actions/terminal/", { asset: assetId, command: text });
      setLines((l) => [...l, { type: result.status === "succeeded" ? "out" : "err", text: result.output || result.error }]);
    } catch (err) {
      const detail = err.data?.command;
      setLines((l) => [...l, { type: "err", text: (Array.isArray(detail) ? detail[0] : detail) || err.message }]);
      if (err.status === 403) toast("Live response requires the forensics group.", "error");
    } finally {
      setBusy(false);
    }
  }

  function onKeyDown(event) {
    if (event.key === "ArrowUp" && history.length) {
      event.preventDefault();
      const next = Math.min(cursor + 1, history.length - 1);
      setCursor(next);
      setCommand(history[next]);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = cursor - 1;
      setCursor(next);
      setCommand(next >= 0 ? history[next] : "");
    }
  }

  const name = asset.data ? asset.data.hostname || asset.data.ip_address : `asset ${assetId}`;
  return (
    <div>
      <div className="terminal" ref={scroller} aria-live="polite">
        {lines.map((line, i) => line.type === "cmd" ? (
          <div key={i}><span className="prompt">{name}&gt;</span> {line.text}</div>
        ) : <pre key={i} className={line.type === "err" ? "err" : undefined}>{line.text}</pre>)}
        {busy && <span className="spinner" />}
      </div>
      <form className="terminal-input" onSubmit={run}>
        <input value={command} onChange={(e) => setCommand(e.target.value)} onKeyDown={onKeyDown} placeholder="ps, netstat, memdump, hash <path>…"
          aria-label="Command" autoComplete="off" spellCheck="false" disabled={busy} autoFocus />
        <button className="btn primary" disabled={busy || !command.trim()}>Run</button>
      </form>
    </div>
  );
}

export default function Response() {
  const toast = useToast();
  const { canRespond, canUseTerminal } = useAuth();
  const [params, setParams] = useSearchParams();
  const terminalAsset = params.get("terminal");
  const capabilities = useApi("/response-actions/capabilities/");
  const playbooks = useApi("/playbooks/");
  const managedAssets = useApi("/assets/", { managed: "true", page_size: 200, ordering: "hostname" });
  const allAssets = useApi("/assets/", { page_size: 200, ordering: "-risk_score" });
  const actions = useList("/response-actions/", { initialFilters: { top_level: "true" }, ordering: "-created_at", pollMs: 15000 });
  const [runModal, setRunModal] = useState(null);
  const [target, setTarget] = useState({});
  const [busy, setBusy] = useState(false);

  async function runPlaybook() {
    setBusy(true);
    try {
      const body = { ...target };
      if (runModal.target_kind === "global") body.confirm = true;
      const result = await api.post(`/playbooks/${runModal.id}/run/`, body);
      toast(`${runModal.name}: ${result.status}`, result.status === "succeeded" ? "success" : "error");
      setRunModal(null);
      setTarget({});
      actions.reload();
      playbooks.reload(true);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  const connector = capabilities.data?.connector;
  return (
    <>
      <PageHeader title="Response center" description="One-click containment, SOAR playbooks and live forensic response." />
      {connector === "simulated" && (
        <div className="alert-banner info">
          <span>Response connector is in <strong>simulated</strong> mode: actions update the platform and the audit log but do not touch real devices.
            Set <code>THREATDASH_RESPONSE_CONNECTOR=webhook</code> to forward signed actions to your EDR/SOAR.</span>
        </div>
      )}
      {!canRespond && <div className="alert-banner warn">You can view response activity. Running actions requires the <strong>responders</strong> group.</div>}

      <div className="grid grid-3">
        {(playbooks.data?.results || []).map((p) => (
          <Card key={p.id} title={p.name} subtitle={`${p.steps.length} steps · runs against ${p.target_kind} · run ${p.run_count}×`}>
            <p className="muted small" style={{ marginTop: 0 }}>{p.description}</p>
            <ol className="small muted" style={{ paddingLeft: 18 }}>
              {p.steps.map((s, i) => <li key={i}>{s.action.replace(/_/g, " ")}{s.continue_on_error ? " (optional)" : ""}</li>)}
            </ol>
            <button className={`btn ${p.target_kind === "global" ? "danger" : "primary"}`} disabled={!canRespond || !p.enabled}
              onClick={() => { setRunModal(p); setTarget({}); }}><Icon name="play" />Run playbook</button>
          </Card>
        ))}
      </div>

      <Card title="Live response console" subtitle="Remote forensic shell on a managed endpoint" className="mt"
        actions={<select value={terminalAsset || ""} onChange={(e) => setParams(e.target.value ? { terminal: e.target.value } : {})} aria-label="Endpoint" disabled={!canUseTerminal}>
          <option value="">Select an endpoint…</option>
          {(managedAssets.data?.results || []).map((a) => <option key={a.id} value={a.id}>{a.hostname || a.ip_address}{a.is_isolated ? " (isolated)" : ""}</option>)}
        </select>}>
        {!canUseTerminal ? <div className="muted">Live response requires the <strong>forensics</strong> group.</div>
          : terminalAsset ? <Terminal assetId={Number(terminalAsset)} /> : <div className="muted">Choose an endpoint to open a session.</div>}
      </Card>

      <Card title="Action history" flush className="mt">
        <DataTable rows={actions.rows} loading={actions.loading} emptyText="No response actions yet." columns={[
          { key: "created_at", label: "Time", render: (r) => formatDate(r.created_at) },
          { key: "action_type", label: "Action", render: (r) => r.playbook_name ? `Playbook: ${r.playbook_name}` : r.action_type.replace(/_/g, " ") },
          { key: "target", label: "Target", render: (r) => r.asset_name || r.target_user || r.indicator_value || "global" },
          { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "connector", label: "Connector" },
          { key: "by", label: "By", render: (r) => r.requested_by_username || "system" },
          { key: "output", label: "Output", render: (r) => <pre className="small muted" style={{ margin: 0, whiteSpace: "pre-wrap", maxWidth: 420 }}>{(r.output || r.error).split("\n").slice(0, 4).join("\n")}</pre> },
        ]} />
        <Pagination page={actions.page} count={actions.count} pageSize={actions.pageSize} onPage={actions.setPage} />
      </Card>

      {runModal && (
        <Modal title={`Run: ${runModal.name}`} onClose={() => setRunModal(null)} footer={<>
          <button className="btn" onClick={() => setRunModal(null)}>Cancel</button>
          <button className={`btn ${runModal.target_kind === "global" ? "danger" : "primary"}`} disabled={busy} onClick={runPlaybook}>
            {runModal.target_kind === "global" ? "I understand — run for everyone" : "Run"}
          </button>
        </>}>
          <p className="muted" style={{ margin: 0 }}>{runModal.description}</p>
          {runModal.target_kind === "asset" && (
            <label className="field">Target asset
              <select value={target.asset || ""} onChange={(e) => setTarget({ asset: Number(e.target.value) })}>
                <option value="">Select…</option>
                {(allAssets.data?.results || []).map((a) => <option key={a.id} value={a.id}>{a.hostname || a.ip_address} (risk {a.risk_score})</option>)}
              </select>
            </label>
          )}
          {runModal.target_kind === "user" && (
            <label className="field">User principal<input value={target.target_user || ""} onChange={(e) => setTarget({ target_user: e.target.value })} placeholder="user@example.com" /></label>
          )}
          {runModal.target_kind === "indicator" && (
            <label className="field">Indicator ID<input type="number" value={target.indicator || ""} onChange={(e) => setTarget({ indicator: Number(e.target.value) })} /></label>
          )}
          {runModal.target_kind === "global" && <div className="alert-banner danger">This affects every identity in the organisation.</div>}
        </Modal>
      )}
    </>
  );
}
