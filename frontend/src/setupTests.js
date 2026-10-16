import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// Chart.js needs a canvas; jsdom has none, so render charts as no-ops in tests.
vi.mock("react-chartjs-2", () => ({
  Bar: () => null,
  Line: () => null,
  Doughnut: () => null,
}));
