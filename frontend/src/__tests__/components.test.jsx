import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AttackPathGraph from "../components/AttackPathGraph";
import { RiskScore, SeverityBadge, Techniques } from "../components/Badges";
import DataTable, { Pagination } from "../components/DataTable";

describe("badges", () => {
  it("renders severity labels", () => {
    render(<SeverityBadge value={4} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("deduplicates techniques and links to ATT&CK", () => {
    render(<Techniques items={["T1059.001", "T1059.001", "T1071"]} />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/001/");
  });

  it("shows risk score", () => {
    render(<RiskScore score={87} />);
    expect(screen.getByTitle("Risk 87 (critical)")).toBeInTheDocument();
  });
});

describe("DataTable", () => {
  const columns = [{ key: "name", label: "Name", sortKey: "name" }, { key: "score", label: "Score" }];

  it("renders rows and sorts", async () => {
    const onSort = vi.fn();
    render(<DataTable columns={columns} rows={[{ id: 1, name: "alpha", score: 3 }]} ordering="name" onSort={onSort} />);
    expect(screen.getByText("alpha")).toBeInTheDocument();
    await userEvent.click(screen.getByText(/^Name/));
    expect(onSort).toHaveBeenCalledWith("-name");
  });

  it("shows the empty state", () => {
    render(<DataTable columns={columns} rows={[]} emptyText="Nothing here" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("paginates", async () => {
    const onPage = vi.fn();
    render(<Pagination page={1} count={60} pageSize={25} onPage={onPage} />);
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Previous")).toBeDisabled();
    await userEvent.click(screen.getByText("Next"));
    expect(onPage).toHaveBeenCalledWith(2);
  });
});

describe("AttackPathGraph", () => {
  const graph = {
    stages: [{ key: "initial_access", label: "Initial Access" }, { key: "exfiltration", label: "Exfiltration" }],
    nodes: [
      { id: "ip:1", type: "external_ip", label: "198.51.100.1", stage: "initial_access", malicious: true },
      { id: "asset:1", type: "asset", label: "srv-1", stage: "initial_access", compromised: true },
      { id: "ip:2", type: "external_ip", label: "203.0.113.9", stage: "exfiltration" },
    ],
    edges: [
      { id: "e1", source: "ip:1", target: "asset:1", stage: "initial_access", label: "login", count: 1, alerted: true, techniques: [] },
      { id: "e2", source: "asset:1", target: "ip:2", stage: "exfiltration", label: "upload", count: 2, alerted: false, techniques: ["T1048"] },
    ],
    entry_points: ["ip:1"], exfiltration_targets: ["ip:2"],
  };

  it("draws stages, nodes and filters to alerted paths", async () => {
    const { container } = render(<AttackPathGraph graph={graph} />);
    expect(screen.getByText("Exfiltration")).toBeInTheDocument();
    expect(screen.getByText("ENTRY")).toBeInTheDocument();
    expect(container.querySelectorAll("path[marker-end]")).toHaveLength(2);
    await userEvent.click(screen.getByLabelText("Alerted paths only"));
    expect(container.querySelectorAll("path[marker-end]")).toHaveLength(1);
  });

  it("handles incidents without telemetry", () => {
    render(<AttackPathGraph graph={{ stages: [], nodes: [], edges: [] }} />);
    expect(screen.getByText(/No telemetry/)).toBeInTheDocument();
  });
});
