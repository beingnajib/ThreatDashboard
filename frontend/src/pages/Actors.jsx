import { useState } from "react";

import { RiskScore, Techniques } from "../components/Badges";
import { Card, PageHeader } from "../components/Card";
import { ErrorState, Loading } from "../components/Feedback";
import { Drawer } from "../components/Overlay";
import { useApi } from "../hooks/useApi";
import { formatDate } from "../lib/format";

const TYPE_LABEL = { nation_state: "Nation-state", ransomware: "Ransomware", cybercrime: "Cybercrime", hacktivist: "Hacktivist", insider: "Insider", unknown: "Unknown" };

export default function Actors() {
  const actors = useApi("/actors/", { page_size: 100, ordering: "name" });
  const [selected, setSelected] = useState(null);
  const iocs = useApi(selected ? `/actors/${selected.id}/indicators/` : null);
  if (actors.loading && !actors.data) return <Loading />;

  return (
    <>
      <PageHeader title="Threat actors" description="Known APT groups and ransomware syndicates; incidents and indicators are matched against their TTPs and infrastructure." />
      <ErrorState error={actors.error} onRetry={actors.reload} />
      <div className="grid grid-3">
        {(actors.data?.results || []).map((a) => (
          <section key={a.id} className="card" style={{ cursor: "pointer" }} onClick={() => setSelected(a)} tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && setSelected(a)}>
            <div className="card-header">
              <div><h2>{a.name}</h2><div className="faint small">{a.aliases.slice(0, 3).join(" · ")}</div></div>
              <span className={`badge ${a.actor_type === "ransomware" ? "danger" : a.actor_type === "nation_state" ? "warn" : "info"}`}>{TYPE_LABEL[a.actor_type]}</span>
            </div>
            <div className="card-body">
              <div className="small muted">{a.motivation}{a.origin_country ? ` · origin ${a.origin_country}` : ""}{a.mitre_group_id ? ` · ${a.mitre_group_id}` : ""}</div>
              <div className="mt"><Techniques items={a.mitre_techniques} max={6} /></div>
              <div className="small mt">{a.indicator_count} linked indicators · targets {a.target_sectors.slice(0, 3).join(", ") || "—"}</div>
            </div>
          </section>
        ))}
      </div>
      {selected && (
        <Drawer title={selected.name} subtitle={selected.aliases.join(", ")} onClose={() => setSelected(null)}>
          <p style={{ margin: 0 }}>{selected.description}</p>
          <dl className="dl">
            <dt>Type</dt><dd>{TYPE_LABEL[selected.actor_type]}</dd>
            <dt>Motivation</dt><dd>{selected.motivation || "—"}</dd>
            <dt>Malware</dt><dd>{selected.malware_families.join(", ") || "—"}</dd>
            <dt>Targets</dt><dd>{selected.target_sectors.join(", ") || "—"}</dd>
            <dt>Last activity</dt><dd>{formatDate(selected.last_activity, false)}</dd>
            <dt>Techniques</dt><dd><Techniques items={selected.mitre_techniques} max={30} /></dd>
            <dt>References</dt><dd>{selected.references.map((r) => <div key={r}><a href={r} target="_blank" rel="noreferrer noopener">{r}</a></div>)}</dd>
          </dl>
          <Card title={`Attributed infrastructure (${iocs.data?.length ?? 0})`} flush>
            <div className="card-body stack" style={{ gap: 6 }}>
              {(iocs.data || []).slice(0, 50).map((i) => (
                <div key={i.id} className="row small" style={{ justifyContent: "space-between" }}><span className="mono truncate">{i.value}</span><RiskScore score={i.risk_score} /></div>
              ))}
            </div>
          </Card>
        </Drawer>
      )}
    </>
  );
}
