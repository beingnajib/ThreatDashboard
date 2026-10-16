import { SEVERITY, SEVERITY_KEYS, riskBand } from "../lib/format";

export function SeverityBadge({ value }) {
  if (!value) return <span className="faint">—</span>;
  return <span className={`badge dot sev-${SEVERITY_KEYS[value]}`}>{SEVERITY[value]}</span>;
}

const STATUS_TONE = {
  open: "danger", new: "danger", active: "danger", acknowledged: "warn", triage: "warn", investigating: "warn",
  contained: "info", eradicated: "info", running: "info", pending: "info", partial: "warn",
  resolved: "ok", closed: "ok", mitigated: "ok", succeeded: "ok", pass: "ok", remediated: "ok", completed: "ok",
  dismissed: "", false_positive: "", expired: "", accepted: "", manual: "info", not_applicable: "",
  failed: "danger", fail: "danger", completed_with_errors: "warn",
};

export function StatusBadge({ value, label }) {
  if (!value) return <span className="faint">—</span>;
  const text = label || String(value).replace(/_/g, " ");
  return <span className={`badge ${STATUS_TONE[value] ?? ""}`}>{text.charAt(0).toUpperCase() + text.slice(1)}</span>;
}

export function RiskScore({ score }) {
  const band = riskBand(score || 0);
  return (
    <span className="risk" title={`Risk ${score} (${band})`}>
      <span className="risk-bar"><span style={{ width: `${score}%`, background: `var(--sev-${band})` }} /></span>
      {score}
    </span>
  );
}

export function Tags({ items: raw, max = 4 }) {
  const items = [...new Set(raw || [])];
  if (!items.length) return <span className="faint">—</span>;
  const shown = items.slice(0, max);
  return (
    <span>
      {shown.map((tag) => <span className="tag" key={tag}>{tag}</span>)}
      {items.length > max && <span className="faint small">+{items.length - max}</span>}
    </span>
  );
}

export function Techniques({ items: raw, max = 4 }) {
  const items = [...new Set(raw || [])];
  if (!items.length) return <span className="faint">—</span>;
  return (
    <span>
      {items.slice(0, max).map((t) => (
        <a key={t} className="tag mono" href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
          target="_blank" rel="noreferrer noopener">{t}</a>
      ))}
      {items.length > max && <span className="faint small">+{items.length - max}</span>}
    </span>
  );
}
