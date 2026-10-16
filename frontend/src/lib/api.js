const TOKEN_KEY = "threatdash.token";

function readToken() {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

let token = readToken();
let onUnauthorized = () => {};

export function setToken(value) {
  token = value;
  try {
    if (value) window.localStorage.setItem(TOKEN_KEY, value);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode); keep the token in memory only */
  }
}

export function getToken() {
  return token;
}

export function setUnauthorizedHandler(handler) {
  onUnauthorized = handler;
}

export class ApiError extends Error {
  constructor(status, data) {
    super(formatError(data) || `Request failed (${status})`);
    this.status = status;
    this.data = data;
  }
}

export function formatError(data) {
  if (!data) return "";
  if (typeof data === "string") return data.slice(0, 300);
  if (Array.isArray(data)) return data.map(formatError).join(" ");
  if (data.detail) return String(data.detail);
  return Object.entries(data)
    .map(([key, value]) => {
      const text = Array.isArray(value) ? value.map(formatError).join(" ") : formatError(value);
      return key === "non_field_errors" ? text : `${key}: ${text}`;
    })
    .join(" ");
}

function buildUrl(path, params) {
  const url = new URL(path.startsWith("/api") ? path : `/api${path}`, window.location.origin);
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, value);
  });
  return url.pathname + url.search;
}

export async function request(path, { method = "GET", params, body, raw = false, signal } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Token ${token}`;
  let payload = body;
  if (body !== undefined && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const response = await fetch(buildUrl(path, params), { method, headers, body: payload, signal });
  if (response.status === 401) {
    onUnauthorized();
  }
  if (raw) {
    if (!response.ok) throw new ApiError(response.status, await safeJson(response));
    return response;
  }
  const data = response.status === 204 ? null : await safeJson(response);
  if (!response.ok) throw new ApiError(response.status, data);
  return data;
}

async function safeJson(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export const api = {
  get: (path, params, options) => request(path, { params, ...options }),
  post: (path, body, options) => request(path, { method: "POST", body, ...options }),
  patch: (path, body) => request(path, { method: "PATCH", body }),
  del: (path) => request(path, { method: "DELETE" }),
};

export async function download(path, params, fallbackName = "download") {
  const response = await request(path, { params, raw: true });
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = match ? match[1] : fallbackName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
