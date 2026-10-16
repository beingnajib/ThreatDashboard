import { useState } from "react";

import { StatusBadge } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable from "../components/DataTable";
import { useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { DOMAINS, formatNumber, timeAgo } from "../lib/format";

const PROVIDERS = {
  generic: "Generic JSON", aws_cloudtrail: "AWS CloudTrail", azure_signin: "Microsoft Entra ID sign-ins",
  azure_activity: "Azure activity log", edr: "EDR / endpoint agent", firewall: "Firewall / NDR",
  email_gateway: "Email security gateway", dark_web: "Dark-web / external risk",
};

export default function Feeds() {
  const toast = useToast();
  const { isStaff } = useAuth();
  const feeds = useApi("/feeds/", { page_size: 100 });
  const connectors = useApi("/connectors/", { page_size: 100 });
  const [pulling, setPulling] = useState(null);
  const [newConnector, setNewConnector] = useState(null);
  const [createdKey, setCreatedKey] = useState(null);

  async function toggleFeed(feed) {
    try {
      await api.patch(`/feeds/${feed.id}/`, { enabled: !feed.enabled });
      feeds.reload(true);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function pull(feed) {
    setPulling(feed.id);
    try {
      const result = await api.post(`/feeds/${feed.id}/pull/`);
      toast(`${feed.name}: ${result.feed.last_status}`, result.feed.last_status.startsWith("Failed") ? "error" : "success");
      feeds.reload(true);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setPulling(null);
    }
  }

  async function createConnector(event) {
    event.preventDefault();
    try {
      const result = await api.post("/connectors/", newConnector);
      setCreatedKey(result);
      setNewConnector(null);
      connectors.reload();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function rotate(connector) {
    try {
      setCreatedKey(await api.post(`/connectors/${connector.id}/rotate_key/`));
    } catch (err) {
      toast(err.message, "error");
    }
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return (
    <>
      <PageHeader title="Feeds & connectors" description="Global IoC feeds pulled on a schedule, and log connectors that push telemetry with their own keys.">
        {isStaff && <button className="btn primary" onClick={() => setNewConnector({ name: "", provider: "generic", domain: "endpoint" })}><Icon name="plus" />New connector</button>}
      </PageHeader>
      {!isStaff && <div className="alert-banner info">Feeds and connectors can be changed by staff only.</div>}
      <Card title="Threat intelligence feeds" subtitle="The scheduler worker pulls enabled feeds at their interval" flush>
        <DataTable rows={feeds.data?.results} loading={feeds.loading} columns={[
          { key: "name", label: "Feed", render: (r) => <div><strong>{r.name}</strong><div className="faint small mono truncate" style={{ maxWidth: 380 }}>{r.url}</div></div> },
          { key: "format", label: "Format", render: (r) => r.file_format || "auto" },
          { key: "interval", label: "Every", render: (r) => `${r.interval_minutes} min` },
          { key: "last", label: "Last pull", render: (r) => r.last_fetched_at ? <div>{timeAgo(r.last_fetched_at)}<div className="faint small">{r.last_status}</div></div> : "never" },
          { key: "enabled", label: "Enabled", render: (r) => <label className="check"><input type="checkbox" checked={r.enabled} disabled={!isStaff} onChange={() => toggleFeed(r)} />{r.enabled ? "on" : "off"}</label> },
          { key: "pull", label: "", render: (r) => isStaff && <button className="btn small" disabled={pulling === r.id} onClick={() => pull(r)}>{pulling === r.id ? "Pulling…" : "Pull now"}</button> },
        ]} />
      </Card>
      <Card title="Log connectors" subtitle={`Ship events to POST ${origin}/api/events/ingest/ with header X-Ingest-Key`} flush className="mt">
        <DataTable rows={connectors.data?.results} loading={connectors.loading} emptyText="No connectors yet." columns={[
          { key: "name", label: "Connector", render: (r) => <strong>{r.name}</strong> },
          { key: "provider", label: "Format", render: (r) => PROVIDERS[r.provider] },
          { key: "domain", label: "Domain", render: (r) => DOMAINS[r.domain] },
          { key: "key", label: "Key", render: (r) => <span className="mono small">{r.key_prefix}…</span> },
          { key: "events", label: "Events", render: (r) => formatNumber(r.events_received) },
          { key: "last", label: "Last event", render: (r) => r.last_event_at ? timeAgo(r.last_event_at) : "never" },
          { key: "state", label: "State", render: (r) => <StatusBadge value={r.enabled ? "active" : "dismissed"} label={r.enabled ? "enabled" : "disabled"} /> },
          { key: "rotate", label: "", render: (r) => isStaff && <button className="btn small" onClick={() => rotate(r)}>Rotate key</button> },
        ]} />
      </Card>
      {newConnector && (
        <Modal title="New log connector" onClose={() => setNewConnector(null)} footer={<button className="btn primary" type="submit" form="new-connector">Create</button>}>
          <form id="new-connector" className="stack" style={{ gap: 12 }} onSubmit={createConnector}>
            <label className="field">Name<input required value={newConnector.name} onChange={(e) => setNewConnector({ ...newConnector, name: e.target.value })} /></label>
            <label className="field">Format<select value={newConnector.provider} onChange={(e) => setNewConnector({ ...newConnector, provider: e.target.value })}>
              {Object.entries(PROVIDERS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            <label className="field">Default domain<select value={newConnector.domain} onChange={(e) => setNewConnector({ ...newConnector, domain: e.target.value })}>
              {Object.entries(DOMAINS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          </form>
        </Modal>
      )}
      {createdKey && (
        <Modal title={`Ingestion key for ${createdKey.name}`} onClose={() => setCreatedKey(null)} footer={<button className="btn primary" onClick={() => setCreatedKey(null)}>I have stored the key</button>}>
          <p style={{ margin: 0 }}>Copy this key now — only its hash is stored and it will not be shown again.</p>
          <div className="key-box">{createdKey.ingest_key}</div>
          <pre className="terminal" style={{ height: "auto" }}>{`curl -X POST ${origin}/api/events/ingest/ \\
  -H "X-Ingest-Key: ${createdKey.ingest_key}" \\
  -H "Content-Type: application/json" \\
  -d '[{"domain": "endpoint", "event_type": "process_start", "hostname": "ws-01"}]'`}</pre>
        </Modal>
      )}
    </>
  );
}
