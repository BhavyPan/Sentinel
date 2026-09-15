/**
 * Live threat simulation (spec §15 nice-to-have: "Live threat simulation that
 * continues to ingest new alerts").
 *
 * Stateless scenario engine: each call inspects recent alerts in the DB to pick
 * a believable next event (mostly benign noise, occasionally an escalating
 * attack story), then the new alert is correlated through the shared engine — existing
 * incidents and their AI analysis / analyst feedback are never wiped.
 */
import { db } from "@/lib/db";
import {
  CORRELATION_THRESHOLD,
  CORRELATION_WINDOW_MINUTES,
  getMaliciousIps,
} from "./threat-intel";
import { refreshIntel } from "./watchlist";
import { runCorrelation } from "./correlator";

// ---------------------------------------------------------------- scenarios

const NORMAL_USERS = ["kmorgan", "achen", "lbrown", "twhite", "snguyen", "dgarcia"];
const INTERNAL_HOSTS = ["ws-1103", "ws-2214", "ws-3305", "ws-4102", "ws-5231"];
const INTERNAL_IPS = ["10.1.5.61", "10.1.8.22", "10.1.6.18", "10.1.7.12", "10.1.9.31"];
const ATTACK_USERS = ["-dev-deploy", "jsmith", "mkeller", "backup-admin"];
const ATTACK_EXTERNAL_IPS = ["203.0.113.42", "198.51.100.77", "192.0.2.146", "45.33.22.10"];

interface RawAlert {
  alert_id: string;
  source: string;
  timestamp: string;
  user: string | null;
  device: string | null;
  ip: string | null;
  event: string;
  description: string;
  raw_severity: string;
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function ago(seconds: number): string {
  return new Date(Date.now() - seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function recentAlerts(windowSeconds: number) {
  const since = new Date(Date.now() - windowSeconds * 1000);
  return db.alert.findMany({ where: { timestamp: { gte: since } }, orderBy: { timestamp: "desc" } });
}

// ---------------------------------------------------------------- scenarios

/** Generate the next raw alert. ~55% benign noise, ~45% story escalation. */
async function generateRaw(): Promise<{ raw: RawAlert; note: string }> {
  const rows = await recentAlerts(CORRELATION_WINDOW_MINUTES * 60);
  const plain = rows.map((r) => ({ event: r.event, user: r.user, ip: r.ip, metadata: r.metadata }));

  // ---- story: brute-force ramp -> success -> large download ----
  const bf = plain.filter((r) => /fail|brute/.test(r.event) && (r.user ?? "").startsWith("svc-"));
  if (bf.length >= 2 && Math.random() < 0.75) {
    const user = bf[0].user ?? pick(ATTACK_USERS);
    const ip = bf[0].ip ?? pick(ATTACK_EXTERNAL_IPS);
    if (Math.random() < 0.5) {
      return {
        raw: {
          alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
          source: "auth",
          timestamp: ago(0),
          user,
          device: "server-02",
          ip,
          event: "successful_login",
          description: `Successful SSH login for ${user} from ${ip} outside of normal hours`,
          raw_severity: "high",
        },
        note: "Brute-force story escalated: account access gained",
      };
    }
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "file-server",
        timestamp: ago(0),
        user,
        device: "server-02",
        ip,
        event: "large_data_download",
        description: `2.8 GB downloaded by ${user} from /exports/hr (volume 9x user baseline)`,
        raw_severity: "critical",
      },
      note: "Brute-force story escalated: mass data download",
    };
  }

  // ---- story: port scan ramp ----
  const scans = plain.filter((r) => r.event === "port_scan");
  if (scans.length === 1 && Math.random() < 0.5) {
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "ids",
        timestamp: ago(0),
        user: null,
        device: "dmz-gw",
        ip: "203.0.113.66",
        event: "port_scan",
        description: "Follow-up TCP SYN scan from 203.0.113.66 targeting database ports 1433, 5432, 6379 (87 attempts)",
        raw_severity: "medium",
      },
      note: "Scan story escalated: database ports probed",
    };
  }

  // ---- story: phishing -> C2 beacon ----
  const phish = plain.filter((r) => r.event === "phishing_report" || r.event === "suspicious_email");
  if (phish.length >= 1 && Math.random() < 0.6) {
    const user = phish[0].user ?? pick(NORMAL_USERS);
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "edr",
        timestamp: ago(0),
        user,
        device: pick(INTERNAL_HOSTS).toUpperCase(),
        ip: pick(INTERNAL_IPS),
        event: "outbound_connection",
        description: `Periodic HTTPS beacon from ${user}'s workstation to 193.142.146.88 (60s interval, C2 pattern)`,
        raw_severity: "high",
      },
      note: "Phishing story escalated: C2 beacon detected",
    };
  }

  // ---- weighted fresh events ----
  const roll = Math.random();
  if (roll < 0.30) {
    const user = pick(NORMAL_USERS);
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "auth",
        timestamp: ago(0),
        user,
        device: pick(INTERNAL_HOSTS),
        ip: pick(INTERNAL_IPS),
        event: "successful_login",
        description: `Successful VPN login for ${user} from office network`,
        raw_severity: "info",
      },
      note: "Routine VPN login",
    };
  }
  if (roll < 0.42) {
    const user = `svc-${pick(ATTACK_USERS)}`;
    const ip = pick(ATTACK_EXTERNAL_IPS);
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "firewall",
        timestamp: ago(0),
        user,
        device: "server-02",
        ip,
        event: "failed_logins",
        description: `${5 + Math.floor(Math.random() * 20)} failed login attempts against ${user} from external IP ${ip}`,
        raw_severity: "medium",
      },
      note: "Failed-login burst against a service account",
    };
  }
  if (roll < 0.52) {
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "ids",
        timestamp: ago(0),
        user: null,
        device: "dmz-gw",
        ip: "203.0.113.66",
        event: "port_scan",
        description: "TCP SYN scan from 203.0.113.66 against DMZ subnet ports 22, 80, 443 (33 attempts)",
        raw_severity: "medium",
      },
      note: "Reconnaissance scan against the DMZ",
    };
  }
  if (roll < 0.62) {
    const user = pick(NORMAL_USERS);
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "mail-gateway",
        timestamp: ago(0),
        user,
        device: pick(INTERNAL_HOSTS),
        ip: pick(INTERNAL_IPS),
        event: "suspicious_email",
        description: `User ${user} reported phishing email impersonating the VPN portal (quarantined)`,
        raw_severity: "low",
      },
      note: "Phishing email reported by user",
    };
  }
  if (roll < 0.72) {
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "satellite",
        timestamp: ago(0),
        user: null,
        device: "GROUND-STATION-2",
        ip: null,
        event: "satellite_telemetry",
        description: "Routine telemetry pass completed. All subsystems nominal.",
        raw_severity: "info",
      },
      note: "Routine satellite telemetry",
    };
  }
  if (roll < 0.80) {
    return {
      raw: {
        alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
        source: "siem",
        timestamp: ago(0),
        user: "svc_backup",
        device: "backup-01",
        ip: "10.1.9.9",
        event: "scheduled_backup",
        description: "Nightly backup job completed successfully (routine)",
        raw_severity: "info",
      },
      note: "Routine backup job",
    };
  }
  // rare: standalone high-signal C2 match on a known-malicious IP
  const ip = pick(getMaliciousIps());
  return {
    raw: {
      alert_id: `SIM-${Date.now().toString(36).toUpperCase()}`,
      source: "threat-intel",
      timestamp: ago(0),
      user: null,
      device: "soc-edge",
      ip,
      event: "malware_ioc_match",
      description: `Threat feed match: IP ${ip} contacted by internal asset (known botnet command-and-control node)`,
      raw_severity: "critical",
    },
    note: "Threat-intel match on known-malicious IP",
  };
}

// ------------------------------------------------- incremental correlation

export interface SimulateResult {
  action: "attached" | "new-incident" | "ungrouped";
  alert: {
    alertId: string;
    source: string;
    sourceLabel: string;
    event: string;
    description: string;
    rawSeverity: string;
    timestamp: string;
  };
  note: string;
  incident: {
    id: string;
    incidentId: string;
    severity: string;
    threatScore: number;
    alertCount: number;
  } | null;
}

/** Insert through the normalizer and update cases with stable correlation. */
export async function simulateOneAlert(): Promise<SimulateResult> {
  await refreshIntel(); // pick up analyst watchlist entries
  const { raw, note } = await generateRaw();

  // Normalize via the real pipeline (single canonical JSON object).
  const { parseAndNormalize } = await import("./normalizer");
  const normalized = parseAndNormalize(JSON.stringify(raw), "json");
  if (normalized.length === 0) throw new Error("Simulator produced an unparsable alert");
  const n = normalized[0];

  const created = await db.alert.create({
    data: {
      alertId: n.alertId,
      source: n.source,
      sourceLabel: n.sourceLabel,
      timestamp: n.timestamp,
      user: n.user ?? null,
      device: n.device ?? null,
      ip: n.ip ?? null,
      event: n.event,
      description: n.description,
      rawSeverity: n.rawSeverity,
      rawFormat: n.rawFormat,
      metadata: JSON.stringify(n.metadata ?? {}),
    },
  });

  const priorIds = new Set((await db.incident.findMany({ select: { id: true } })).map((i) => i.id));
  await runCorrelation();
  const linked = await db.alert.findUnique({ where: { id: created.id }, include: { incident: { include: { _count: { select: { alerts: true } } } } } });
  const incident = linked?.incident;
  return {
    action: incident ? priorIds.has(incident.id) ? "attached" : "new-incident" : "ungrouped",
    alert: simAlertDTO(created), note,
    incident: incident ? { id: incident.id, incidentId: incident.incidentId, severity: incident.severity, threatScore: incident.threatScore, alertCount: incident._count.alerts } : null,
  };
}

function simAlertDTO(a: {
  alertId: string;
  source: string;
  sourceLabel: string;
  event: string;
  description: string;
  rawSeverity: string;
  timestamp: Date;
}): SimulateResult["alert"] {
  return {
    alertId: a.alertId,
    source: a.source,
    sourceLabel: a.sourceLabel,
    event: a.event,
    description: a.description,
    rawSeverity: a.rawSeverity,
    timestamp: a.timestamp.toISOString(),
  };
}
