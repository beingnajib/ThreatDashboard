export function Card({ title, subtitle, actions, children, flush, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <div className="muted small">{subtitle}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={`card-body${flush ? " flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, tone }) {
  return (
    <div className={`card kpi ${tone || ""}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value ?? "—"}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

export function BarList({ items, max, format = (v) => v, colorFor }) {
  if (!items?.length) return <div className="muted small">No data.</div>;
  const top = max || Math.max(...items.map((i) => i.count), 1);
  return (
    <div className="bar-list">
      {items.map((item) => (
        <div className="bar-item" key={item.key ?? item.label}>
          <span className="truncate" title={item.label}>{item.label}</span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${(item.count / top) * 100}%`, background: colorFor?.(item) }} />
          </span>
          <span className="small muted" style={{ textAlign: "right" }}>{format(item.count)}</span>
        </div>
      ))}
    </div>
  );
}

export function PageHeader({ title, description, children }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </div>
  );
}
