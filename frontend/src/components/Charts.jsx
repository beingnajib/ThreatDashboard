import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, LineElement, PointElement, Tooltip, Legend, Filler);

function cssVar(name, fallback) {
  if (typeof window === "undefined") return fallback;
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

export function themeColors() {
  return {
    text: cssVar("--text-muted", "#93a3bd"),
    grid: cssVar("--border", "#26344f"),
    accent: cssVar("--accent", "#38bdf8"),
    low: cssVar("--sev-low", "#22c55e"),
    medium: cssVar("--sev-medium", "#eab308"),
    high: cssVar("--sev-high", "#f97316"),
    critical: cssVar("--sev-critical", "#ef4444"),
    info: cssVar("--info", "#60a5fa"),
  };
}

export const SERIES_COLORS = ["#38bdf8", "#a78bfa", "#f472b6", "#34d399", "#fbbf24", "#fb923c", "#60a5fa", "#f87171",
  "#2dd4bf", "#c084fc", "#94a3b8", "#facc15"];

function baseOptions(extra = {}) {
  const c = themeColors();
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 300 },
    plugins: {
      legend: { labels: { color: c.text, boxWidth: 10, boxHeight: 10, usePointStyle: true } },
      tooltip: { mode: "index", intersect: false },
    },
    scales: {
      x: { ticks: { color: c.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 }, grid: { color: c.grid, display: false } },
      y: { ticks: { color: c.text, precision: 0 }, grid: { color: c.grid }, beginAtZero: true },
    },
    ...extra,
  };
}

export function TrendChart({ labels, datasets, height = "chart-box" }) {
  const options = baseOptions({ interaction: { mode: "index", intersect: false } });
  const data = {
    labels,
    datasets: datasets.map((d, i) => ({
      borderColor: d.color || SERIES_COLORS[i],
      backgroundColor: `${d.color || SERIES_COLORS[i]}33`,
      fill: d.fill ?? i === 0,
      tension: 0.3,
      pointRadius: d.pointRadius ?? 0,
      pointHoverRadius: 4,
      borderWidth: 2,
      ...d,
    })),
  };
  return <div className={height}><Line data={data} options={options} aria-label="Trend chart" role="img" /></div>;
}

export function BarChart({ labels, values, label = "Count", colors, horizontal = false, height = "chart-box" }) {
  const options = baseOptions({ indexAxis: horizontal ? "y" : "x", plugins: { legend: { display: false } } });
  if (horizontal) {
    options.scales.x = { ...options.scales.y };
    options.scales.y = { ticks: { color: themeColors().text, autoSkip: false }, grid: { display: false } };
  }
  const data = {
    labels,
    datasets: [{ label, data: values, backgroundColor: colors || SERIES_COLORS[0], borderRadius: 4, maxBarThickness: 36 }],
  };
  return <div className={height}><Bar data={data} options={options} aria-label={`${label} bar chart`} role="img" /></div>;
}

export function DoughnutChart({ labels, values, colors, height = "chart-box" }) {
  const c = themeColors();
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "62%",
    plugins: { legend: { position: "bottom", labels: { color: c.text, boxWidth: 10, usePointStyle: true } } },
  };
  const data = { labels, datasets: [{ data: values, backgroundColor: colors || SERIES_COLORS, borderWidth: 0 }] };
  return <div className={height}><Doughnut data={data} options={options} aria-label="Distribution chart" role="img" /></div>;
}

export function severityColors() {
  const c = themeColors();
  return [c.low, c.medium, c.high, c.critical];
}
