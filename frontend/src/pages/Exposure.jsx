import { useState } from "react";

import { SeverityBadge, StatusBadge } from "../components/Badges";
import { Card, Kpi, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { ErrorState, useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { Modal } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { useList } from "../hooks/useList";
import { api } from "../lib/api";
import { EXPOSURE_KINDS, formatDate } from "../lib/format";

const STATUSES = { open: "Open", investigating: "Investigating", remediated: "Remediated", accepted: "Risk accepted", false_positive: "False positive" };

export default function Exposure() {
  const toast = useToast();
  const list = useList("/exposures/", { ordering: "-observed_at" });
  const openCounts = useApi("/exposures/", { status: "open", page_size: 200 });
  const [modal, setModal] = useState(null);
  const [domain, setDomain] = useState("");
  const [resolve, setResolve] = useState(false);
  const [dump, setDump] = useState("");
  const [breach, setBreach] = useState("");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const open = openCounts.data?.results || [];
  const count = (kind) => open.filter((e) => e.kind === kind).length;

  async function setStatus(row, status) {
    try {
      await api.patch(`/exposures/${row.id}/`, { status });
      list.reload(true);
      openCounts.reload(true);
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function scan() {
    setBusy(true);
    try {
      const result = await api.post("/exposures/scan-typosquats/", { domains: domain ? [domain] : undefined, resolve });
      toast(`Typosquat scan: ${result.count} finding(s)`, "success");
      setModal(null);
      list.reload();
      openCounts.reload();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function loadPreview() {
    try {
      setPreview(await api.get("/exposures/typosquat-candidates/", { domain }));
    } catch (err) {
      toast(err.message, "error");
    }
  }

  async function ingestCredentials() {
    setBusy(true);
    try {
      const result = await api.post("/exposures/ingest-credentials/", { records: dump, breach });
      toast(`${result.matched_org} credential(s) for your domains, ${result.created} new. Plaintext passwords were discarded.`, "success");
      setModal(null);
      setDump("");
      list.reload();
      openCounts.reload();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="External risk" description="Leaked credentials, dark-web chatter and look-alike domains targeting the organisation.">
        <button className="btn" onClick={() => setModal("typo")}><Icon name="globe" />Typosquat scan</button>
        <button className="btn" onClick={() => setModal("creds")}><Icon name="upload" />Ingest credential dump</button>
      </PageHeader>
      <div className="grid grid-kpi">
        <Kpi label="Open exposures" value={open.length} tone={open.length ? "high" : "ok"} />
        <Kpi label="Leaked credentials" value={count("leaked_credential")} tone={count("leaked_credential") ? "critical" : "ok"} />
        <Kpi label="Dark-web mentions" value={count("dark_web_mention") + count("data_leak")} />
        <Kpi label="Look-alike domains" value={count("typosquat")} />
      </div>
      <Card flush className="mt">
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <div className="filters">
            <input type="search" placeholder="Search findings" value={list.search} onChange={(e) => list.setSearch(e.target.value)} aria-label="Search exposures" />
            <select value={list.filters.kind || ""} onChange={(e) => list.setFilter("kind", e.target.value)} aria-label="Kind">
              <option value="">All kinds</option>{Object.entries(EXPOSURE_KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select value={list.filters.status || ""} onChange={(e) => list.setFilter("status", e.target.value)} aria-label="Status">
              <option value="">Any status</option>{Object.entries(STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
        </div>
        <ErrorState error={list.error} onRetry={list.reload} />
        <DataTable rows={list.rows} loading={list.loading} ordering={list.ordering} onSort={list.setOrdering} columns={[
          { key: "severity", label: "Severity", sortKey: "severity", render: (r) => <SeverityBadge value={r.severity} /> },
          { key: "kind", label: "Kind", render: (r) => EXPOSURE_KINDS[r.kind] },
          { key: "title", label: "Finding", render: (r) => <div><div>{r.title}</div><div className="faint small">{r.detail}</div></div> },
          { key: "source", label: "Source" },
          { key: "observed_at", label: "Observed", sortKey: "observed_at", render: (r) => formatDate(r.observed_at) },
          { key: "status", label: "Status", render: (r) => (
            <span className="row" style={{ flexWrap: "nowrap" }}><StatusBadge value={r.status} />
              <select value={r.status} onChange={(e) => setStatus(r, e.target.value)} aria-label="Change status">
                {Object.entries(STATUSES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select></span>
          ) },
        ]} />
        <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
      </Card>

      {modal === "typo" && (
        <Modal title="Typosquat scan" onClose={() => setModal(null)} footer={<>
          <button className="btn" onClick={loadPreview}>Preview permutations</button>
          <button className="btn primary" disabled={busy} onClick={scan}>{busy ? "Scanning…" : "Scan"}</button>
        </>}>
          <label className="field">Domain (blank = organisation domains)<input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" /></label>
          <label className="check"><input type="checkbox" checked={resolve} onChange={(e) => setResolve(e.target.checked)} />Resolve candidates in DNS (slower, finds registered look-alikes)</label>
          <p className="muted small" style={{ margin: 0 }}>Without DNS resolution, only look-alikes already seen in your traffic or threat intelligence are reported.</p>
          {preview && <div className="small"><strong>{preview.count} candidates</strong><div className="mono faint" style={{ maxHeight: 160, overflowY: "auto" }}>{preview.results.slice(0, 80).map((c) => `${c.domain} (${c.technique})`).join(" · ")}</div></div>}
        </Modal>
      )}
      {modal === "creds" && (
        <Modal title="Ingest leaked credentials" onClose={() => setModal(null)} footer={<button className="btn primary" disabled={busy || !dump.trim()} onClick={ingestCredentials}>Ingest</button>}>
          <label className="field">Breach / source name<input value={breach} onChange={(e) => setBreach(e.target.value)} placeholder="Combolist 2026-10" /></label>
          <label className="field">Records (email:password per line, or JSON)<textarea className="mono" rows="7" value={dump} onChange={(e) => setDump(e.target.value)} /></label>
          <p className="muted small" style={{ margin: 0 }}>Only addresses on your organisation&apos;s domains are kept. Passwords are never stored — only a 5-character SHA-1 prefix.</p>
        </Modal>
      )}
    </>
  );
}
