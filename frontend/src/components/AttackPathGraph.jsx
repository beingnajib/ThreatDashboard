import { useMemo, useState } from "react";

const COLUMN_WIDTH = 190;
const ROW_HEIGHT = 74;
const TOP = 52;
const LEFT = 40;
const RADIUS = 17;

const TYPE_STYLE = {
  external_ip: { color: "#f97316", label: "External IP" },
  external_domain: { color: "#fb923c", label: "External domain" },
  asset: { color: "#38bdf8", label: "Asset" },
  user: { color: "#a78bfa", label: "Identity" },
  cloud: { color: "#2dd4bf", label: "Cloud control plane" },
};
const STAGE_COLORS = {
  reconnaissance: "#94a3b8", initial_access: "#f472b6", execution: "#fbbf24", persistence: "#a3e635",
  privilege_escalation: "#facc15", defense_evasion: "#c084fc", credential_access: "#fb7185",
  discovery: "#67e8f9", lateral_movement: "#f97316", collection: "#2dd4bf", command_and_control: "#ef4444",
  exfiltration: "#dc2626", impact: "#b91c1c",
};

function shortLabel(text, max = 24) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export default function AttackPathGraph({ graph, onSelectNode }) {
  const [alertedOnly, setAlertedOnly] = useState(false);
  const [hovered, setHovered] = useState(null);

  const layout = useMemo(() => {
    if (!graph?.nodes?.length) return null;
    const stageKeys = graph.stages.map((s) => s.key);
    const edges = alertedOnly ? graph.edges.filter((e) => e.alerted) : graph.edges;
    const used = new Set(edges.flatMap((e) => [e.source, e.target]));
    const nodes = graph.nodes.filter((n) => used.has(n.id));
    const allColumns = stageKeys.length ? stageKeys : ["execution"];
    // A node sits in the stage where the attacker first reached it (its
    // earliest incoming edge); entry points sit where they first acted.
    const columnOf = {};
    nodes.forEach((node) => {
      const incoming = edges.filter((e) => e.target === node.id).map((e) => allColumns.indexOf(e.stage));
      const outgoing = edges.filter((e) => e.source === node.id).map((e) => allColumns.indexOf(e.stage));
      const candidates = (incoming.length ? incoming : outgoing).filter((i) => i >= 0);
      columnOf[node.id] = candidates.length ? Math.min(...candidates) : 0;
    });
    const usedColumns = [...new Set(Object.values(columnOf))].sort((a, b) => a - b);
    const columns = usedColumns.map((i) => allColumns[i]);
    const buckets = columns.map(() => []);
    nodes
      .slice()
      .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""))
      .forEach((node) => buckets[usedColumns.indexOf(columnOf[node.id])].push(node));
    const positions = {};
    buckets.forEach((bucket, col) => {
      bucket.forEach((node, row) => {
        positions[node.id] = { x: LEFT + col * COLUMN_WIDTH + COLUMN_WIDTH / 2, y: TOP + row * ROW_HEIGHT + 30, node };
      });
    });
    const rows = Math.max(...buckets.map((b) => b.length), 1);
    return {
      columns, positions, edges,
      width: LEFT * 2 + columns.length * COLUMN_WIDTH,
      height: TOP + rows * ROW_HEIGHT + 30,
    };
  }, [graph, alertedOnly]);

  if (!layout) return <div className="empty">No telemetry is linked to this incident yet.</div>;
  const labels = Object.fromEntries((graph.stages || []).map((s) => [s.key, s.label]));
  const entry = new Set(graph.entry_points || []);
  const exfil = new Set(graph.exfiltration_targets || []);

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <span className="muted small">
          {graph.nodes.length} entities, {graph.edges.length} observed paths across {graph.stages.length} ATT&CK tactics
          {graph.truncated ? " (truncated)" : ""}
        </span>
        <label className="check">
          <input type="checkbox" checked={alertedOnly} onChange={(e) => setAlertedOnly(e.target.checked)} />
          Alerted paths only
        </label>
      </div>
      <div className="attack-graph">
        <svg width={layout.width} height={layout.height} role="img" aria-label="Attack path graph">
          <defs>
            {Object.entries(STAGE_COLORS).map(([stage, color]) => (
              <marker key={stage} id={`arrow-${stage}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7"
                markerHeight="7" orient="auto-start-reverse">
                <path d="M0 0L10 5L0 10z" fill={color} />
              </marker>
            ))}
          </defs>
          {layout.columns.map((stage, i) => (
            <g key={stage}>
              <rect x={LEFT + i * COLUMN_WIDTH + 6} y={8} width={COLUMN_WIDTH - 12} height={layout.height - 16} rx="8"
                fill={STAGE_COLORS[stage] || "#64748b"} opacity="0.05" />
              <text className="stage-label" x={LEFT + i * COLUMN_WIDTH + COLUMN_WIDTH / 2} y={30} textAnchor="middle">
                {labels[stage] || stage}
              </text>
            </g>
          ))}
          {layout.edges.map((edge) => {
            const a = layout.positions[edge.source];
            const b = layout.positions[edge.target];
            if (!a || !b) return null;
            const color = STAGE_COLORS[edge.stage] || "#94a3b8";
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const length = Math.hypot(dx, dy) || 1;
            const ex = b.x - (dx / length) * (RADIUS + 3);
            const ey = b.y - (dy / length) * (RADIUS + 3);
            const sx = a.x + (dx / length) * RADIUS;
            const sy = a.y + (dy / length) * RADIUS;
            const bend = dx === 0 ? 50 : Math.min(Math.abs(dx) / 4, 40);
            const path = `M${sx},${sy} Q${(sx + ex) / 2 + (dx === 0 ? bend : 0)},${(sy + ey) / 2 - (dx === 0 ? 0 : bend)} ${ex},${ey}`;
            const highlighted = hovered && (hovered === edge.source || hovered === edge.target);
            return (
              <path key={edge.id} d={path} fill="none" stroke={color} markerEnd={`url(#arrow-${edge.stage})`}
                strokeWidth={edge.alerted ? 2.6 : 1.4} strokeDasharray={edge.alerted ? undefined : "4 4"}
                opacity={hovered ? (highlighted ? 1 : 0.15) : 0.85}>
                <title>{`${edge.label} (${edge.count}×) — ${labels[edge.stage] || edge.stage}${edge.techniques.length ? ` — ${edge.techniques.join(", ")}` : ""}`}</title>
              </path>
            );
          })}
          {Object.values(layout.positions).map(({ x, y, node }) => {
            const style = TYPE_STYLE[node.type] || TYPE_STYLE.asset;
            const danger = node.malicious || exfil.has(node.id);
            return (
              <g key={node.id} transform={`translate(${x},${y})`} style={{ cursor: onSelectNode ? "pointer" : "default" }}
                onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)}
                onClick={() => onSelectNode?.(node)}>
                <circle r={RADIUS} fill={style.color} fillOpacity="0.2" stroke={danger ? "#ef4444" : style.color}
                  strokeWidth={danger || node.compromised ? 3 : 1.5} />
                {node.isolated && <circle r={RADIUS + 5} fill="none" stroke="#22c55e" strokeDasharray="3 3" />}
                {entry.has(node.id) && <text y={-RADIUS - 6} textAnchor="middle" style={{ fontSize: 10, fill: "#f472b6" }}>ENTRY</text>}
                <text y="4" textAnchor="middle" style={{ fontSize: 11, fontWeight: 700 }}>
                  {{ external_ip: "IP", external_domain: "DNS", asset: "H", user: "U", cloud: "☁" }[node.type] || "?"}
                </text>
                <text y={RADIUS + 15} textAnchor="middle">{shortLabel(node.label)}</text>
                <title>{`${style.label}: ${node.label}${node.compromised ? " (compromised)" : ""}${node.malicious ? " (known malicious)" : ""}${node.isolated ? " (isolated)" : ""}`}</title>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="legend">
        {Object.values(TYPE_STYLE).map((t) => <span key={t.label}><i style={{ background: t.color }} />{t.label}</span>)}
        <span><i style={{ background: "transparent", border: "2px solid #ef4444" }} />Malicious / exfil target</span>
        <span><i style={{ background: "transparent", border: "2px dashed #22c55e" }} />Isolated</span>
        <span>Solid = alerted, dashed = related activity</span>
      </div>
    </div>
  );
}
