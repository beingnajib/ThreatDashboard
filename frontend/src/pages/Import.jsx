import { useRef, useState } from "react";

import { StatusBadge } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import DataTable, { Pagination } from "../components/DataTable";
import { useToast } from "../components/Feedback";
import { useList } from "../hooks/useList";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";

const FORMATS = { "": "Auto-detect", csv: "CSV", json: "JSON / JSON Lines", xml: "XML", stix: "STIX 2.1 bundle", text: "Plain text (one IoC per line)" };

export default function Import() {
  const toast = useToast();
  const input = useRef(null);
  const [file, setFile] = useState(null);
  const [format, setFormat] = useState("");
  const [source, setSource] = useState("");
  const [reliability, setReliability] = useState("F");
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const jobs = useList("/imports/", { ordering: "-created_at" });

  async function submit(event) {
    event.preventDefault();
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    if (format) body.append("file_format", format);
    if (source) {
      body.append("source_name", source);
      body.append("source_reliability", reliability);
    }
    setBusy(true);
    try {
      const job = await api.post("/imports/", body);
      setResult(job);
      toast(job.message, job.status === "completed" ? "success" : "info");
    } catch (err) {
      setResult(err.data && typeof err.data === "object" && err.data.status ? err.data : null);
      toast(err.message, "error");
    } finally {
      setBusy(false);
      jobs.reload();
    }
  }

  return (
    <>
      <PageHeader title="Import threat data" description="CSV, JSON, XML, STIX 2.1 and plain-text lists. Defanged values and common column names from most feeds are recognised." />
      <div className="grid grid-main-side">
        <Card title="Upload">
          <form className="stack" onSubmit={submit}>
            <div className={`dropzone${dragging ? " active" : ""}`} role="button" tabIndex={0}
              onClick={() => input.current?.click()} onKeyDown={(e) => e.key === "Enter" && input.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); setFile(e.dataTransfer.files[0] || null); }}>
              {file ? <><strong>{file.name}</strong><div className="small">{(file.size / 1024).toFixed(1)} KB</div></> : "Drop a file here or click to choose"}
              <input ref={input} type="file" hidden accept=".csv,.tsv,.json,.jsonl,.ndjson,.xml,.txt,.stix,.stix2" onChange={(e) => setFile(e.target.files[0] || null)} />
            </div>
            <div className="form-grid">
              <label className="field">Format<select value={format} onChange={(e) => setFormat(e.target.value)}>{Object.entries(FORMATS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
              <label className="field">Source name (optional)<input value={source} onChange={(e) => setSource(e.target.value)} placeholder="Partner ISAC" /></label>
              <label className="field">Source reliability<select value={reliability} onChange={(e) => setReliability(e.target.value)} disabled={!source}>
                {["A", "B", "C", "D", "E", "F"].map((r) => <option key={r} value={r}>{r}</option>)}</select></label>
            </div>
            <div><button className="btn primary" disabled={!file || busy}>{busy ? "Importing…" : "Import"}</button></div>
          </form>
          {result && (
            <div className="mt">
              <div className="row"><StatusBadge value={result.status} /><span>{result.message}</span></div>
              <div className="small muted mt">{result.total_rows} rows · {result.created_count} new · {result.updated_count} merged · {result.error_count} errors · {result.alert_count} alerts raised</div>
              {result.errors?.length > 0 && (
                <ul className="small" style={{ maxHeight: 200, overflowY: "auto" }}>
                  {result.errors.map((e, i) => <li key={i}>Row {e.row}: {e.error}</li>)}
                </ul>
              )}
            </div>
          )}
        </Card>
        <Card title="Accepted columns">
          <div className="small muted stack" style={{ gap: 6 }}>
            <div><strong>value</strong> (indicator, ioc, observable, ip, domain, url, hash…)</div>
            <div><strong>type</strong> — optional, auto-detected</div>
            <div><strong>threat_type</strong>, <strong>severity</strong> (low…critical or 1-4), <strong>threat_level</strong> (1-10)</div>
            <div><strong>confidence</strong> (0-100 or 0-1), <strong>tags</strong>, <strong>mitre</strong></div>
            <div><strong>first_seen</strong>/<strong>date_detected</strong>, <strong>last_seen</strong>, <strong>expires</strong></div>
            <div><strong>country</strong>, <strong>tlp</strong>, <strong>source</strong>, <strong>description</strong></div>
            <div>Existing indicators are merged: sightings increase and the highest severity wins.</div>
          </div>
        </Card>
      </div>
      <Card title="Import history" flush className="mt">
        <DataTable rows={jobs.rows} loading={jobs.loading} columns={[
          { key: "created_at", label: "When", render: (r) => formatDate(r.created_at) },
          { key: "filename", label: "File", render: (r) => <span className="mono small">{r.filename}</span> },
          { key: "file_format", label: "Format" },
          { key: "source_name", label: "Source", render: (r) => r.source_name || "—" },
          { key: "status", label: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "counts", label: "New / merged / errors", render: (r) => `${r.created_count} / ${r.updated_count} / ${r.error_count}` },
          { key: "alerts", label: "Alerts", render: (r) => r.alert_count },
        ]} />
        <Pagination page={jobs.page} count={jobs.count} pageSize={jobs.pageSize} onPage={jobs.setPage} />
      </Card>
    </>
  );
}
