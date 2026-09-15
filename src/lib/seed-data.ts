/**
 * SentinelAI demo dataset (spec §11).
 * Builds RAW multi-format feeds (SIEM JSON, EDR JSON with a different schema,
 * cyber-sensor CSV, satellite ground-station text, plain-text intel report).
 * The normalizer (backend) must parse all five formats.
 *
 * Stories encoded (offsets are minutes before "now" so the demo always looks fresh):
 *  - Story A (Critical): brute-force admin -> successful login -> 4.2 GB download -> beacon   [-350..-315]
 *  - Story B (High):     encoded PowerShell -> process injection -> C2 HTTPS -> DGA DNS -> file deletion [-230..-215]
 *  - Story C (High):     two IoT devices contact known botnet IP 45.33.22.10                   [-180..-175]
 *  - Story D (Low):      DMZ port scan from 88.12.44.5 (blocked)                               [-120..-116]
 *  - FP A:               employee rpatel wrong password 3x then success (internal IP)          [-90..-88]
 *  - FP B:               approved Nessus vulnerability scan (maintenance window)               [-60..-45]
 *  - Noise/FP C:         routine satellite telemetry passes + daily intel report               [-30..-15]
 *  - Background normal:  vpn logins, backups, deploys (stay uncorrelated)                      [-400..-10]
 */

function iso(minutesAgo: number): string {
  const d = new Date(Date.now() - minutesAgo * 60_000);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface DemoFeeds {
  siemJson: string; // SIEM batch — canonical schema (spec §5)
  edrJson: string; // EDR batch — vendor schema with different field names
  sensorCsv: string; // cyber-sensor CSV export
  satelliteText: string; // satellite ground-station text feed
  intelText: string; // plain-text intelligence report
}

export function buildDemoFeeds(now: Date = new Date()): DemoFeeds {
  const t = (minutesAgo: number) => new Date(+now - minutesAgo * 60000).toISOString().replace(/\.\d{3}Z$/, "Z");

  // ---------- 1) SIEM JSON — canonical normalized-ish schema ----------
  const siem = [
    // --- Story A: admin account compromise (Critical) ---
    {
      alert_id: "A1001",
      source: "firewall",
      timestamp: t(350),
      user: "admin",
      device: "server-01",
      ip: "103.44.17.9",
      event: "multiple_failed_logins",
      description: "23 failed login attempts against admin account from external IP 103.44.17.9",
      raw_severity: "high",
    },
    {
      alert_id: "A1002",
      source: "siem",
      timestamp: t(349),
      user: "admin",
      device: "server-01",
      ip: "103.44.17.9",
      event: "brute_force_anomaly",
      description: "Anomaly rule: login failure rate for admin exceeded baseline by 12x",
      raw_severity: "medium",
    },
    {
      alert_id: "A1003",
      source: "auth",
      timestamp: t(346),
      user: "admin",
      device: "server-01",
      ip: "103.44.17.9",
      event: "successful_login",
      description: "Successful SSH login for admin from 103.44.17.9 (first login from this country)",
      raw_severity: "high",
    },
    {
      alert_id: "A1004",
      source: "file-server",
      timestamp: t(340),
      user: "admin",
      device: "server-01",
      ip: "103.44.17.9",
      event: "large_data_download",
      description: "4.2 GB downloaded by admin account from /exports/finance (unusual volume)",
      raw_severity: "critical",
    },
    {
      alert_id: "A1005",
      source: "firewall",
      timestamp: t(332),
      user: "admin",
      device: "server-01",
      ip: "91.240.118.6",
      event: "outbound_connection",
      description: "Outbound connection from server-01 to 91.240.118.6 on port 4444 (uncommon destination)",
      raw_severity: "high",
    },
    {
      alert_id: "A1006",
      source: "auth",
      timestamp: t(335),
      user: "admin",
      device: "server-01",
      ip: "103.44.17.9",
      event: "account_manipulation",
      description: "New SSH key added to admin account authorized_keys from session on server-01",
      raw_severity: "high",
    },
    // --- FP A: employee wrong password 3x (internal IP, no privilege) ---
    {
      alert_id: "F5001",
      source: "auth",
      timestamp: t(90),
      user: "rpatel",
      device: "ws-2214",
      ip: "10.1.8.22",
      event: "failed_logins",
      description: "3 failed login attempts for rpatel from internal IP 10.1.8.22",
      raw_severity: "low",
    },
    {
      alert_id: "F5002",
      source: "auth",
      timestamp: t(88),
      user: "rpatel",
      device: "ws-2214",
      ip: "10.1.8.22",
      event: "successful_login",
      description: "Successful login for rpatel from internal IP 10.1.8.22 after password reset",
      raw_severity: "info",
    },
    // --- FP B: approved vulnerability scan ---
    {
      alert_id: "F6001",
      source: "scanner",
      timestamp: t(60),
      user: "svc_scan",
      device: "scanner-01",
      ip: "10.1.2.5",
      event: "vulnerability_scan",
      description: "Nessus authorized vulnerability scan started (approved maintenance window CHG-8841)",
      raw_severity: "info",
    },
    {
      alert_id: "F6002",
      source: "waf",
      timestamp: t(50),
      user: "svc_scan",
      device: "scanner-01",
      ip: "10.1.2.5",
      event: "scan_pattern",
      description: "Scanner pattern alerts from 10.1.2.5 against web cluster (authorized scan in progress)",
      raw_severity: "low",
    },
    // --- Background normal activity ---
    {
      alert_id: "N8001",
      source: "auth",
      timestamp: t(400),
      user: "kmorgan",
      device: "ws-1103",
      ip: "10.1.5.61",
      event: "successful_login",
      description: "Successful VPN login for kmorgan",
      raw_severity: "info",
    },
    {
      alert_id: "N8002",
      source: "siem",
      timestamp: t(380),
      user: "svc_backup",
      device: "backup-01",
      ip: "10.1.9.9",
      event: "scheduled_backup",
      description: "Nightly backup job completed successfully (routine)",
      raw_severity: "info",
    },
    {
      alert_id: "N8003",
      source: "siem",
      timestamp: t(120),
      user: "deploy-bot",
      device: "ci-runner-02",
      ip: "10.1.4.7",
      event: "deployment",
      description: "Scheduled application deployment v2.14.1 completed (change request CR-2231)",
      raw_severity: "info",
    },
    {
      alert_id: "N8004",
      source: "auth",
      timestamp: t(15),
      user: "achen",
      device: "ws-3305",
      ip: "10.1.6.18",
      event: "successful_login",
      description: "Successful VPN login for achen",
      raw_severity: "info",
    },
  ];

  // ---------- 2) EDR JSON — vendor schema (different field names on purpose) ----------
  const edr = [
    // --- Story B: suspicious PowerShell chain (High) ---
    {
      id: "B2001",
      sensor: "edr",
      "@timestamp": t(230),
      hostname: "WS-4471",
      account: "jsmith",
      src_ip: "10.1.7.44",
      event_type: "suspicious_process",
      message: "Encoded PowerShell command executed (-enc SQBFAFgA…) spawning from winword.exe",
      severity: "critical",
    },
    {
      id: "B2002",
      sensor: "edr",
      "@timestamp": t(228),
      hostname: "WS-4471",
      account: "jsmith",
      src_ip: "10.1.7.44",
      event_type: "process_injection",
      message: "Process injection detected into rundll32.exe from unsigned module",
      severity: "high",
    },
    {
      id: "B2003",
      sensor: "firewall",
      "@timestamp": t(222),
      hostname: "WS-4471",
      account: "jsmith",
      src_ip: "10.1.7.44",
      event_type: "outbound_connection",
      message: "Outbound HTTPS beacon to 193.142.146.88 every 60s (C2 pattern)",
      severity: "high",
    },
    {
      id: "B2004",
      sensor: "dns-sensor",
      "@timestamp": t(220),
      hostname: "WS-4471",
      account: "jsmith",
      src_ip: "10.1.7.44",
      event_type: "dns_query",
      message: "DNS query to dynamic DNS domain updates-cdn.duckdns.org resolved to 193.142.146.88",
      severity: "medium",
    },
    {
      id: "B2005",
      sensor: "edr",
      "@timestamp": t(215),
      hostname: "WS-4471",
      account: "jsmith",
      src_ip: "10.1.7.44",
      event_type: "file_deletion",
      message: "Mass file deletion in C:\\Users\\jsmith\\Downloads (shadow copy artifacts)",
      severity: "medium",
    },
  ];

  // ---------- 3) Cyber-sensor CSV ----------
  const csvRows: string[] = [
    "alert_id,source,timestamp,user,device,ip,event,description,severity",
    // --- Story C: two devices contact known botnet IP ---
    `C3001,ids,${t(180)},,camera-07,45.33.22.10,outbound_connection,IoT camera camera-07 contacted external botnet IP 45.33.22.10 on port 6667,high`,
    `C3002,ids,${t(178)},,printer-03,45.33.22.10,outbound_connection,Office printer printer-03 contacted same botnet IP 45.33.22.10 on port 6667,high`,
    `C3003,threat-intel,${t(175)},,soc-edge,45.33.22.10,malware_ioc_match,Threat feed match: IP 45.33.22.10 is a known botnet command-and-control node (botnet Satori),critical`,
    // --- Story D: DMZ port scan (blocked) ---
    `D4001,ids,${t(120)},,dmz-gw,88.12.44.5,port_scan,TCP SYN scan from 88.12.44.5 against DMZ subnet ports 21-25,80,443,3389 (40 attempts),medium`,
    `D4002,firewall,${t(116)},,dmz-gw,88.12.44.5,blocked_connections,Firewall blocked 40 connection attempts from 88.12.44.5 (deny policy),low`,
    // --- FP B continues: scanner activity seen by IDS ---
    `F6003,ids,${t(45)},,scanner-01,10.1.2.5,network_scan,High-volume connection alerts from internal scanner 10.1.2.5 (authorized Nessus maintenance window),low`,
  ];

  // ---------- 4) Satellite ground-station text feed ----------
  const satelliteText = [
    `[SATCOM-7] ${t(30)} SEV:info GROUND-STATION-2 :: Routine telemetry sync completed for pass 1184. Link quality nominal. No anomalies detected.`,
    `[SATCOM-7] ${t(22)} SEV:info GROUND-STATION-3 :: Scheduled downlink of imaging payload finished. 12.4 GB transferred over encrypted ground link (planned operation).`,
    `[SATCOM-9] ${t(15)} SEV:info GROUND-STATION-2 :: Routine orbit telemetry received. All subsystems nominal.`,
  ].join("\n");

  // ---------- 5) Plain-text intelligence report ----------
  const intelText = `INTELLIGENCE REPORT — DAILY DIGEST
Source: OPEN-SOURCE THREAT INTEL FEED
Published: ${t(18)}

SUMMARY: APT-41 continues credential-harvesting campaigns against telecom and satellite
operators in the region. Phishing emails impersonate VPN portals. One infrastructure
indicator: phishing domain secure-login.verify-account.net observed hosting a fake SSO page.
Recommended: review mail gateway logs and enforce MFA on remote access.

LOCAL RELEVANCE: No direct matches against local assets in this digest.
Analyst note: routine context report — no action required unless indicators overlap.`;

  return {
    siemJson: JSON.stringify(siem, null, 2),
    edrJson: JSON.stringify(edr, null, 2),
    sensorCsv: csvRows.join("\n"),
    satelliteText,
    intelText,
  };
}

/** Combined human-readable description of the demo bundle (for UI copy) */
export const DEMO_FEED_LABELS = [
  { key: "siemJson", label: "SIEM batch", format: "JSON", source: "siem / firewall / auth / file-server" },
  { key: "edrJson", label: "EDR batch", format: "JSON (vendor schema)", source: "edr / dns-sensor" },
  { key: "sensorCsv", label: "Cyber-sensor export", format: "CSV", source: "ids / threat-intel / waf" },
  { key: "satelliteText", label: "Satellite ground feed", format: "Text", source: "satellite" },
  { key: "intelText", label: "Intel report", format: "Text", source: "intel-report" },
] as const;
