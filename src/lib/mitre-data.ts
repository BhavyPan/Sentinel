import type { MitreTechnique } from "./types";

/**
 * Curated MITRE ATT&CK technique list for demo mapping (spec §10 "MITRE data").
 * The correlator maps alert events to techniques via keywords (deterministic),
 * and the LLM is constrained to pick from this list.
 */
export const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access" },
  { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access" },
  { id: "T1078.002", name: "Valid Accounts: Domain Accounts", tactic: "Defense Evasion, Persistence" },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion, Privilege Escalation" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution, Persistence, Privilege Escalation" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" },
  { id: "T1090", name: "Proxy", tactic: "Command and Control" },
  { id: "T1090.003", name: "Proxy: Multi-hop Proxy", tactic: "Command and Control" },
  { id: "T1568", name: "Dynamic Resolution", tactic: "Command and Control" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  { id: "T1213", name: "Data from Information Repositories", tactic: "Collection" },
  { id: "T1087", name: "Account Discovery", tactic: "Discovery" },
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { id: "T1046.001", name: "Network Service Scanning", tactic: "Discovery" },
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  { id: "T1595.002", name: "Active Scanning: Vulnerability Scanning", tactic: "Reconnaissance" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access, Persistence" },
  { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  { id: "T1204", name: "User Execution", tactic: "Execution" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence, Privilege Escalation" },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
  { id: "T1070.004", name: "Indicator Removal: File Deletion", tactic: "Defense Evasion" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion" },
  { id: "T1219", name: "Remote Access Software", tactic: "Command and Control" },
  { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" },
  { id: "T1619", name: "Cloud Storage Object Discovery", tactic: "Discovery" },
  { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development" },
  { id: "T1588", name: "Obtain Capabilities", tactic: "Resource Development" },
];

/** Deterministic event-keyword → MITRE mapping used by the scoring engine */
export const EVENT_MITRE_RULES: { keywords: string[]; techniqueId: string }[] = [
  { keywords: ["failed_login", "failed_logins", "brute", "password"], techniqueId: "T1110" },
  { keywords: ["successful_login", "valid_account", "login_success"], techniqueId: "T1078" },
  { keywords: ["powershell", "encoded_command", "script", "cmd", "shell"], techniqueId: "T1059.001" },
  { keywords: ["process_injection", "injection"], techniqueId: "T1055" },
  { keywords: ["outbound_connection", "c2", "beacon", "command_and_control"], techniqueId: "T1071" },
  { keywords: ["dynamic_dns", "dga", "dynamic_domain"], techniqueId: "T1568" },
  { keywords: ["data_download", "large_transfer", "exfiltration", "data_upload", "gb_download"], techniqueId: "T1041" },
  { keywords: ["port_scan", "network_scan", "scanning"], techniqueId: "T1046" },
  { keywords: ["vulnerability_scan", "vuln_scan"], techniqueId: "T1595.002" },
  { keywords: ["malware", "trojan", "botnet"], techniqueId: "T1588.001" },
  { keywords: ["remote_desktop", "rdp", "ssh", "remote_service"], techniqueId: "T1021" },
  { keywords: ["dns_query", "dns"], techniqueId: "T1071" },
  { keywords: ["suspicious_process", "process_event"], techniqueId: "T1059" },
  { keywords: ["lateral_movement", "internal_connection"], techniqueId: "T1021" },
  { keywords: ["satellite_telemetry", "telemetry"], techniqueId: "T1619" },
];

export function mitreById(id: string): MitreTechnique | undefined {
  return MITRE_TECHNIQUES.find((t) => t.id === id);
}

/**
 * Canonical ATT&CK tactic progression (kill-chain order) used by the
 * Incident Analysis kill-chain strip. Techniques may map to several tactics
 * (their `tactic` field is comma-separated) — every listed tactic lights up.
 */
export const ATTACK_TACTIC_ORDER: string[] = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];
