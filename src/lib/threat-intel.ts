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

/** Correlation window in minutes (spec §6: same user/IP within 30 minutes) */
export const CORRELATION_WINDOW_MINUTES = 30;

/** Pair correlation score needed to link two alerts into the same incident */
export const CORRELATION_THRESHOLD = 5;
