import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import App from "../App";
import { ToastProvider } from "../components/Feedback";
import { AuthProvider } from "../lib/auth";

function jsonResponse(body, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

function renderApp() {
  return render(
    <MemoryRouter initialEntries={["/query"]}>
      <AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider>
    </MemoryRouter>,
  );
}

describe("App", () => {
  beforeEach(() => window.localStorage.clear());

  it("shows the sign-in form and reports bad credentials", async () => {
    vi.spyOn(global, "fetch").mockImplementation(() => jsonResponse({ non_field_errors: ["bad"] }, 400));
    renderApp();
    await userEvent.type(screen.getByLabelText("Username"), "a");
    await userEvent.type(screen.getByLabelText("Password"), "b");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password.");
  });

  it("signs in and answers a natural-language question", async () => {
    vi.spyOn(global, "fetch").mockImplementation((url, options = {}) => {
      const path = String(url);
      if (path.startsWith("/api/auth/token/")) {
        return jsonResponse({ token: "t0k", user: { id: 1, username: "ana", is_staff: false, groups: [] } });
      }
      if (path.startsWith("/api/query/") && options.method === "POST") {
        return jsonResponse({ interpretation: "Count of indicators grouped by country", engine: "keyword", total: 3,
          chart: "bar", series: [{ label: "RU", value: 2 }], rows: [], spec: {} });
      }
      return jsonResponse({ count: 0, results: [] });
    });
    renderApp();
    await userEvent.type(screen.getByLabelText("Username"), "ana");
    await userEvent.type(screen.getByLabelText("Password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Ask the data" })).toBeInTheDocument();
    expect(window.localStorage.getItem("threatdash.token")).toBe("t0k");
    await userEvent.type(screen.getByLabelText("Question"), "indicators by country");
    await userEvent.click(screen.getByRole("button", { name: /Ask/ }));
    await waitFor(() => expect(screen.getByText("Count of indicators grouped by country")).toBeInTheDocument());
    const call = global.fetch.mock.calls.find(([u]) => String(u).startsWith("/api/query/"));
    expect(call[1].headers.Authorization).toBe("Token t0k");
  });
});
