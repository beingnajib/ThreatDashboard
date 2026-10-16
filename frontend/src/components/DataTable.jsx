import { Empty, Loading } from "./Feedback";

/**
 * columns: [{ key, label, render?(row), sortKey?, className? }]
 * ordering: current ordering string ("-risk_score"); onSort(newOrdering)
 */
export default function DataTable({ columns, rows, loading, onRowClick, ordering, onSort, emptyText, rowKey = "id",
  selectedKey }) {
  if (loading && !rows) return <Loading />;
  if (!rows?.length) return <Empty>{emptyText || "No records match the current filters."}</Empty>;
  const sortField = ordering?.replace(/^-/, "");
  const descending = ordering?.startsWith("-");
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {columns.map((col) => {
              const sortable = Boolean(col.sortKey && onSort);
              const active = sortable && sortField === col.sortKey;
              return (
                <th key={col.key} className={sortable ? "sortable" : undefined}
                  aria-sort={active ? (descending ? "descending" : "ascending") : undefined}
                  onClick={sortable ? () => onSort(active && descending ? col.sortKey : `-${col.sortKey}`) : undefined}>
                  {col.label}{active ? (descending ? " ↓" : " ↑") : ""}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row[rowKey]} className={[onRowClick ? "clickable" : "", selectedKey === row[rowKey] ? "selected" : ""].join(" ")}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={onRowClick ? (e) => e.key === "Enter" && onRowClick(row) : undefined}>
              {columns.map((col) => (
                <td key={col.key} className={col.className}>{col.render ? col.render(row) : row[col.key] ?? "—"}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({ page, count, pageSize = 25, onPage }) {
  if (!count) return null;
  const pages = Math.max(Math.ceil(count / pageSize), 1);
  return (
    <div className="pagination">
      <span>{count.toLocaleString()} result{count === 1 ? "" : "s"}</span>
      <span className="row">
        <button className="btn small" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span>Page {page} of {pages}</span>
        <button className="btn small" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </span>
    </div>
  );
}
