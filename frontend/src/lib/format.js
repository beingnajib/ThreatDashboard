export const SEVERITY = { 1: "Low", 2: "Medium", 3: "High", 4: "Critical" };
export const SEVERITY_KEYS = { 1: "low", 2: "medium", 3: "high", 4: "critical" };

export const IOC_TYPES = {
  ipv4: "IPv4", ipv6: "IPv6", domain: "Domain", url: "URL", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256",
  email: "Email", cve: "CVE",
};
export const THREAT_TYPES = {
  malware: "Malware", ransomware: "Ransomware", phishing: "Phishing", c2: "Command & control", botnet: "Botnet",
  apt: "APT / targeted", exploit: "Exploit", scanner: "Scanning", brute_force: "Brute force", spam: "Spam",
  data_exfiltration: "Data exfiltration", other: "Other",
};
export const INDICATOR_STATUS = {
  active: "Active", investigating: "Investigating", mitigated: "Mitigated", false_positive: "False positive",
  expired: "Expired",
};
export const ALERT_STATUS = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved", dismissed: "Dismissed" };
export const INCIDENT_STATUS = { new: "New", triage: "Triage", contained: "Contained", eradicated: "Eradicated", closed: "Closed" };
export const DETECTION_TYPES = {
  rule: "Detection rule", ioc_match: "IoC match", behavioral: "Behavioural", external: "External", telemetry: "Source detection",
};
export const DOMAINS = { endpoint: "Endpoint", cloud: "Cloud", identity: "Identity", network: "Network", email: "Email" };
export const ASSET_TYPES = {
  workstation: "Workstation", laptop: "Laptop", server: "Server", mobile: "Mobile", network_device: "Network device",
  iot: "IoT / OT", cloud_instance: "Cloud instance", container: "Container", saas: "SaaS", unknown: "Unknown",
};
export const EXPOSURE_KINDS = {
  leaked_credential: "Leaked credential", dark_web_mention: "Dark-web mention", typosquat: "Typosquat",
  exposed_service: "Exposed service", brand_abuse: "Brand abuse", data_leak: "Data leak",
};
export const TLP = { clear: "TLP:CLEAR", green: "TLP:GREEN", amber: "TLP:AMBER", amber_strict: "TLP:AMBER+STRICT", red: "TLP:RED" };

export function formatDate(value, withTime = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return withTime
    ? date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function timeAgo(value) {
  if (!value) return "—";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (Number.isNaN(seconds)) return "—";
  if (seconds < 60) return "just now";
  const units = [["d", 86400], ["h", 3600], ["m", 60]];
  for (const [label, size] of units) {
    if (Math.abs(seconds) >= size) return `${Math.floor(seconds / size)}${label} ago`;
  }
  return "just now";
}

export function formatNumber(value) {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat().format(value);
}

export function riskBand(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function defang(value) {
  return String(value || "").replace(/^http/i, "hxxp").replace(/\.(?=[^.]*$)/, "[.]");
}
