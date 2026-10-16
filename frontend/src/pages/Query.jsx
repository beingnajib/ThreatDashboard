import { useState } from "react";

import { Card, PageHeader } from "../components/Card";
import { BarChart, TrendChart } from "../components/Charts";
import DataTable from "../components/DataTable";
import { useToast } from "../components/Feedback";
import Icon from "../components/Icon";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";

const EXAMPLES = [
  "Failed sign-ins by country in the last 24 hours",
  "Top 5 countries with critical indicators",
  "Open alerts by severity",
  "Alert trend over time this month",
  "List shadow IT devices",
  "Leaked credentials",
  "Events by provider in the last 7 days",
  "Ransomware indicators by source",
];

function renderCell(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return formatDate(value);
  return String(value);
}

export default function Query() {
  const toast = useToast();
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  async function ask(text) {
    const q = (text ?? question).trim();
    if (!q) return;
    setQuestion(q);
    setBusy(true);
    try {
      setResult(await api.post("/query/", { question: q }));
    } catch (err) {
      toast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Ask the data" description="Ask a question in plain English; it is translated into a safe, whitelisted query and charted." />
      <Card>
        <form className="row" onSubmit={(e) => { e.preventDefault(); ask(); }}>
          <input style={{ flex: 1, minWidth: 220 }} value={question} onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. failed sign-ins by country in the last 24 hours" aria-label="Question" />
          <button className="btn primary" disabled={busy || !question.trim()}><Icon name="search" />{busy ? "Thinking…" : "Ask"}</button>
        </form>
        <div className="row mt">
          {EXAMPLES.map((ex) => <button key={ex} className="btn small ghost" onClick={() => ask(ex)}>{ex}</button>)}
        </div>
      </Card>
      {result && (
        <Card className="mt" title={result.interpretation}
          subtitle={`${result.total.toLocaleString()} matching records · translated by ${result.engine === "claude" ? "Claude" : "keyword parser"}`}>
          {result.chart === "line" && <TrendChart height="chart-box tall" labels={result.series.map((s) => s.label)} datasets={[{ label: "Count", data: result.series.map((s) => s.value) }]} />}
          {result.chart === "bar" && <BarChart height="chart-box tall" horizontal={result.series.length > 6} labels={result.series.map((s) => s.label)} values={result.series.map((s) => s.value)} />}
          {result.chart === "table" && (
            <DataTable rows={result.rows} columns={(result.columns || []).map((c) => ({ key: c, label: c.replace(/_/g, " "), render: (r) => renderCell(r[c]) }))} />
          )}
          {result.chart !== "table" && result.series.length === 0 && <div className="empty">No data for this question.</div>}
          <details className="mt small muted"><summary>Query spec</summary><pre className="mono">{JSON.stringify(result.spec, null, 2)}</pre></details>
        </Card>
      )}
    </>
  );
}
