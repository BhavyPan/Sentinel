/**
 * Threat intel context for the demo (spec: "Malware/known malicious IOC" scoring signal).
 * In a real system this would come from a TI feed; here it is a curated list.
 */

/** Known-malicious external IPs (C2 / botnet nodes) */
export const MALICIOUS_IPS: string[] = [
  "185.220.101.44", // Story B C2
  "45.33.22.10", // Story C botnet node
  "103.44.17.9", // Story A attacker IP
  "88.12.44.5", // Story D scanner
  "91.240.118.6",
  "193.142.146.88",
];

/** Known-malicious domains */
export const MALICIOUS_DOMAINS: string[] = [
  "updates-cdn.duckdns.org",
  "secure-login.verify-account.net",
  "cdn-metrics.top",
  "mail-attachments.xyz",
];

/** Known-malware hashes (SHA-256 demo values) */
export const MALICIOUS_HASHES: string[] = [
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "d41d8cd98f00b204e9800998ecf8427e",
];

/** Privileged / high-value account names (+20 scoring signal) */
export const PRIVILEGED_ACCOUNTS: string[] = [
  "admin",
  "administrator",
  "root",
  "svc_backup",
  "svc_sql",
  "domain_admin",
  "sysadmin",
];

/** Internal RFC1918 ranges — external (non-matching) IPs count as "unusual source" */
export function isInternalIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip.startsWith("127.") ||
    ip.startsWith("169.254.")
  );
}

/** Keywords in descriptions that suggest approved/routine activity (FP heuristics) */
export const BENIGN_KEYWORDS: string[] = [
  "approved",
  "maintenance window",
  "scheduled",
  "routine",
  "planned",
  "telemetry sync",
  "nightly backup",
  "authorized",
  "change request",
  "nessus",
  "authorized scanner",
];

/** Pair correlation window in minutes (spec §6: same user/IP within 30 minutes) */
export const CORRELATION_WINDOW_MINUTES = 30;

/** Pair correlation score needed to link two alerts into the same incident */
export const CORRELATION_THRESHOLD = 5;

// ============================================================
// Analyst watchlist extension (server-side runtime intel)
// The static lists above are the built-in feed; analyst-curated
// IOCs (DB watchlist) are merged at runtime via refreshIntel().
// ============================================================

const extraIps = new Set<string>();
const extraDomains = new Set<string>();
const extraHashes = new Set<string>();

export interface IntelMerge {
  ips: string[];
  domains: string[];
  hashes: string[];
}

/** Replace the runtime-extra intel sets (server only). */
export function setExtraIntel(intel: IntelMerge): void {
  extraIps.clear();
  extraDomains.clear();
  extraHashes.clear();
  for (const v of intel.ips) extraIps.add(v);
  for (const v of intel.domains) extraDomains.add(v);
  for (const v of intel.hashes) extraHashes.add(v);
}

export function clearExtraIntel(): void {
  setExtraIntel({ ips: [], domains: [], hashes: [] });
}

/** Full merged list (static + watchlist) — for UI/graph flagging. */
export function getMaliciousIps(): string[] {
  return [...MALICIOUS_IPS, ...extraIps];
}
export function getMaliciousDomains(): string[] {
  return [...MALICIOUS_DOMAINS, ...extraDomains];
}
export function getMaliciousHashes(): string[] {
  return [...MALICIOUS_HASHES, ...extraHashes];
}

export function isMaliciousIp(v: string): boolean {
  return MALICIOUS_IPS.includes(v) || extraIps.has(v);
}
export function isMaliciousDomain(v: string): boolean {
  return MALICIOUS_DOMAINS.includes(v) || extraDomains.has(v);
}
export function isMaliciousHash(v: string): boolean {
  return MALICIOUS_HASHES.includes(v) || extraHashes.has(v);
}
