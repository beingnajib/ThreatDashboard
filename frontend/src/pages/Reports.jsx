import { useState } from "react";

import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { useList } from "../hooks/useList";
import { api, download } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate, SEVERITY } from "../lib/format";

const FORMATS = { pdf: "PDF", docx: "Word (DOCX)", xlsx: "Excel (XLSX)", csv: "CSV", json: "JSON" };

function isoDaysAgo(days) {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return date.toISOString().slice(0, 10);
}

export default function Reports() {
  const toast = useToast();
  const { isStaff } = useAuth();
  const list = useList("/reports/", { ordering: "-created_at" });
  const [form, setForm] = useState({ name: "Weekly threat report", file_format: "pdf", date_from: isoDaysAgo(6), date_to: isoDaysAgo(0), min_severity: 1 });
  const [busy, setBusy] = useState(false);
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  async function generate(event) {
    event.preventDefault();
    setBusy(true);
    try {
      const report = await api.post("/reports/", { ...form, min_severity: Number(form.min_severity), date_from: form.date_from || null, date_to: form.date_to || null });
      toast("Report generated", "success");
      list.reload();
      await download(report.download_url, null, `${form.name}.${form.file_format}`);
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function remove(report) {
    if (!window.confirm(`Delete "${report.name}"?`)) return;
    try {
      await api.del(`/reports/${report.id}/`);
      list.reload();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  return (
    <>
      <PageHeader title="Reports" description="Executive summaries, incidents, exposure, compliance and top indicators in PDF, Word, Excel, CSV or JSON." />
      <Card title="Generate a report">
        <form className="form-grid" onSubmit={generate} style={{ alignItems: "end" }}>
          <label className="field">Title<input required maxLength={150} value={form.name} onChange={set("name")} /></label>
          <label className="field">Format<select value={form.file_format} onChange={set("file_format")}>{Object.entries(FORMATS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">From<input type="date" value={form.date_from} onChange={set("date_from")} /></label>
          <label className="field">To<input type="date" value={form.date_to} onChange={set("date_to")} /></label>
          <label className="field">Minimum severity<select value={form.min_severity} onChange={set("min_severity")}>{Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}+</option>)}</select></label>
          <button className="btn primary" disabled={busy}><Icon name="file" />{busy ? "Generating…" : "Generate & download"}</button>
        </form>
      </Card>
      <Card title="Report archive" flush className="mt">
        <DataTable rows={list.rows} loading={list.loading} emptyText="No reports generated yet." columns={[
          { key: "name", label: "Report", render: (r) => <strong>{r.name}</strong> },
          { key: "file_format", label: "Format", render: (r) => FORMATS[r.file_format] },
          { key: "period", label: "Period", render: (r) => `${r.parameters.date_from || "start"} → ${r.parameters.date_to || "now"}` },
          { key: "summary", label: "Contents", render: (r) => <span className="small muted">{r.summary.indicator_count} IoCs · {r.summary.alert_count} alerts · {r.summary.incident_count ?? 0} incidents</span> },
          { key: "created_at", label: "Created", render: (r) => formatDate(r.created_at) },
          { key: "actions", label: "", render: (r) => <span className="row" style={{ flexWrap: "nowrap" }}>
            <button className="btn small" onClick={() => download(r.download_url, null, `${r.name}.${r.file_format}`).catch((e) => toast(e.message, "error"))}><Icon name="download" />Download</button>
            {isStaff && <button className="btn small ghost" onClick={() => remove(r)}>Delete</button>}
          </span> },
        ]} />
        <Pagination page={list.page} count={list.count} pageSize={list.pageSize} onPage={list.setPage} />
      </Card>
    </>
  );
}
