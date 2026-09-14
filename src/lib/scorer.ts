/**
 * SentinelAI deterministic threat scorer (spec §7, §8).
 * Pure function over normalized alert rows belonging to one correlated incident.
 */
import { mitreById, EVENT_MITRE_RULES } from "./mitre-data";
import {
  BENIGN_KEYWORDS,
  PRIVILEGED_ACCOUNTS,
  isInternalIp,
  isMaliciousDomain,
  isMaliciousHash,
  isMaliciousIp,
} from "./threat-intel";
import type { Classification, MitreTechnique, RiskSignal, Severity } from "./types";
import { sourceLabelFor } from "./normalizer";

export interface ScorerAlert {
  alertId: string;
  source: string;
  sourceLabel?: string | null;
  timestamp: Date;
  user?: string | null;
  device?: string | null;
  ip?: string | null;
  event: string;
  description: string;
  rawSeverity?: string | null;
  metadata?: Record<string, unknown> | string | null;
}

export interface ScorerResult {
  threatScore: number;
  severity: Severity;
  classification: Classification;
  riskSignals: RiskSignal[];
  mitre: MitreTechnique[];
  evidence: string[];
  bluf: string;
  confidence: number;
  title: string;
}

interface AlertMeta {
  iocs?: { ips?: string[]; domains?: string[]; hashes?: string[] };
  iocMatch?: boolean;
  iocMatches?: unknown[];
}

function parseMeta(metadata: ScorerAlert["metadata"]): AlertMeta {
  if (!metadata) return {};
  if (typeof metadata === "string") {
    try {
      return JSON.parse(metadata) as AlertMeta;
    } catch {
      return {};
    }
  }
  return metadata as AlertMeta;
}

function isFailedLogin(a: ScorerAlert): boolean {
  return /fail|brute/.test(a.event);
}

function isSuccessLogin(a: ScorerAlert): boolean {
  return a.event.includes("successful_login") || a.event.includes("login_success");
}

function isLargeTransfer(a: ScorerAlert): boolean {
  return (
    /download|transfer|exfil|upload/.test(a.event) ||
    /(\d+(?:\.\d+)?)\s*gb/i.test(a.description) ||
    /large data|mass file|exfiltration/i.test(a.description)
  );
}

function mentionedFailureCount(a: ScorerAlert): number {
  const m = /(\d+)\s*failed/i.exec(a.description);
  return m ? parseInt(m[1], 10) : 0;
}

function maliciousIocValues(a: ScorerAlert): string[] {
  const meta = parseMeta(a.metadata);
  const out: string[] = [];
  for (const v of meta.iocs?.ips ?? []) if (isMaliciousIp(v)) out.push(v);
  for (const v of meta.iocs?.domains ?? []) if (isMaliciousDomain(v)) out.push(v);
  for (const v of meta.iocs?.hashes ?? []) if (isMaliciousHash(v)) out.push(v);
  return [...new Set(out)];
}

function hasPrivilegedAccount(alerts: ScorerAlert[]): string | null {
  for (const a of alerts) {
    const u = (a.user || "").toLowerCase();
    if (!u) continue;
    if (PRIVILEGED_ACCOUNTS.includes(u) || u.includes("admin") || u.includes("svc_")) return a.user as string;
  }
  return null;
}

function externalIps(alerts: ScorerAlert[]): string[] {
  const out = new Set<string>();
  for (const a of alerts) {
    if (a.ip && !isInternalIp(a.ip)) out.add(a.ip);
    for (const v of parseMeta(a.metadata).iocs?.ips ?? []) {
      if (!isInternalIp(v)) out.add(v);
    }
  }
  return [...out];
}

function matchMitre(sorted: ScorerAlert[]): MitreTechnique[] {
  const seen = new Set<string>();
  const techniques: MitreTechnique[] = [];
  const resolve = (id: string): MitreTechnique | undefined =>
    mitreById(id) ?? mitreById(id.split(".")[0]);
  const add = (id: string): void => {
    if (seen.has(id)) return;
    const t = resolve(id);
    if (!t || seen.has(t.id)) return;
    seen.add(t.id);
    techniques.push({ id: t.id, name: t.name, tactic: t.tactic });
  };
  for (const a of sorted) {
    const haystacks = [a.event, a.description.toLowerCase()];
    for (const rule of EVENT_MITRE_RULES) {
      if (rule.keywords.some((k) => haystacks.some((h) => h.includes(k)))) add(rule.techniqueId);
    }
    if (techniques.length >= 4) break;
  }
  return techniques.slice(0, 4);
}

function buildTitle(
  alerts: ScorerAlert[],
  opts: { fp: boolean; privileged: string | null; failedSignal: boolean; successAfterFail: boolean; largeSignal: boolean; portScan: boolean; iocValues: string[] }
): string {
  const primary = alerts[0];
  const host = primary?.device || primary?.user || primary?.ip || "multiple assets";
  const truncate = (s: string) => (s.length > 70 ? `${s.slice(0, 67)}...` : s);
  if (opts.fp) return truncate(`Likely false positive - routine ${sourceLabelFor(primary?.source || "sensor")} activity`);
  if (opts.privileged && opts.failedSignal && opts.successAfterFail) {
    return truncate(`Possible administrator account compromise (${opts.privileged}@${primary?.device || host})`);
  }
  if (opts.portScan) return truncate(`Port scan activity from ${primary?.ip || host}`);
  if (opts.iocValues.length > 0) return truncate(`Possible C2/botnet activity involving ${opts.iocValues[0]}`);
  if (opts.largeSignal) return truncate(`Suspected large data exfiltration by ${opts.privileged || primary?.user || host}`);
  if (/process|injection|powershell|script/.test(alerts.map((a) => a.event).join(" "))) {
    return truncate(`Suspicious process activity on ${host}`);
  }
  return truncate(`Correlated suspicious activity on ${host}`);
}

function buildEvidence(sorted: ScorerAlert[], sig: {
  failedSignal: boolean;
  successAfterFail: boolean;
  largeSignal: boolean;
  iocValues: string[];
  privileged: string | null;
  external: string[];
  distinctSources: string[];
}): string[] {
  const out: string[] = [];
  if (sig.failedSignal) {
    const a = sorted.find((x) => isFailedLogin(x));
    if (a) {
      const n = sorted.reduce((acc, x) => Math.max(acc, mentionedFailureCount(x)), 0);
      out.push(
        n >= 5
          ? `${n} failed logins against ${a.user || "account"} from ${a.ip || "unknown IP"} (${a.alertId})`
          : `Multiple failed logins against ${a.user || "account"} (${a.alertId})`
      );
    }
  }
  if (sig.successAfterFail) {
    const a = sorted.find((x) => isSuccessLogin(x));
    if (a) out.push(`Successful login for ${a.user || "account"} from ${a.ip || "unknown IP"} after failures (${a.alertId})`);
  }
  if (sig.largeSignal) {
    const a = sorted.find((x) => isLargeTransfer(x));
    if (a) {
      const m = /(\d+(?:\.\d+)?)\s*gb/i.exec(a.description);
      out.push(
        m
          ? `${m[1]} GB data transfer by ${a.user || a.device || "host"} (${a.alertId})`
          : `Unusual bulk data activity: ${a.description.slice(0, 60)} (${a.alertId})`
      );
    }
  }
  if (sig.iocValues.length > 0) {
    const ids = sorted
      .filter((x) => maliciousIocValues(x).length > 0)
      .map((x) => x.alertId)
      .slice(0, 3);
    out.push(`Known malicious indicator(s): ${sig.iocValues.slice(0, 2).join(", ")} (${ids.join(", ")})`);
  }
  if (sig.privileged) {
    const ids = sorted.filter((x) => (x.user || "").toLowerCase() === sig.privileged?.toLowerCase()).map((x) => x.alertId).slice(0, 3);
    out.push(`Privileged account ${sig.privileged} involved (${ids.join(", ")})`);
  } else if (sig.external.length > 0) {
    out.push(`External source IP observed: ${sig.external[0]}`);
  }
  if (sig.distinctSources.length >= 3) {
    out.push(`Correlated across ${sig.distinctSources.length} sources: ${sig.distinctSources.slice(0, 4).join(", ")}`);
  }
  if (out.length < 2) {
    out.push(
      `${sorted.length} correlated alert(s): ${sorted.slice(0, 4).map((a) => a.alertId).join(", ")}`
    );
    out.push(`Event types: ${[...new Set(sorted.map((a) => a.event))].slice(0, 4).join(", ")}`);
  }
  return out.slice(0, 4);
}

function buildBluf(
  severity: Severity,
  confidence: number,
  evidence: string[],
  mitre: MitreTechnique[],
  title: string,
  fp: boolean,
  ctx: { user?: string | null; device?: string | null; ip?: string | null; iocValues: string[]; kind: string }
): string {
  const conclusions: Record<string, string> = {
    admin: `Possible compromised privileged account ${ctx.user || "admin"} on ${ctx.device || "internal host"} with follow-on suspicious activity.`,
    c2: `Internal assets may be communicating with known malicious infrastructure (${ctx.iocValues[0] || "external IOC"}).`,
    exfil: `Unusual large data transfer suggests possible data exfiltration by ${ctx.user || ctx.device || "an internal account"}.`,
    scan: `External host ${ctx.ip || ""} is scanning the perimeter; connection attempts appear blocked.`,
    fp: "Activity matches known-benign patterns (scheduled/authorized/routine) and is likely a false positive.",
    generic: `Multiple correlated alerts indicate suspicious activity on ${ctx.device || ctx.user || "internal assets"} requiring review.`,
  };
  const actions: Record<string, string> = {
    admin: `Disable ${ctx.user || "the account"}, terminate active sessions, and block ${ctx.ip || "the source IP"}.`,
    c2: `Isolate affected hosts and block ${ctx.iocValues.slice(0, 2).join(", ") || "malicious IPs"} at the firewall.`,
    exfil: `Suspend ${ctx.user || "the account"} access and preserve transfer logs for review.`,
    scan: `Block ${ctx.ip || "the source"} at the perimeter and verify DMZ exposure.`,
    fp: "Close as false positive / no action",
    generic: "Contain affected assets and review authentication and network logs.",
  };
  const next: Record<string, string> = {
    admin: `Review downloaded files, new SSH keys/credentials, and lateral movement from ${ctx.device || "the host"}.`,
    c2: "Hunt observed IOCs across all endpoints and check DNS/proxy logs for related domains.",
    exfil: "Identify what was accessed and confirm whether data left the environment.",
    scan: "Verify no services were compromised and review perimeter rule hits.",
    fp: "Confirm the change/approval record and close with an analyst note.",
    generic: "Correlate related logs and hunt for the observed indicators environment-wide.",
  };
  const kind = fp ? "fp" : ctx.kind;
  return [
    `BOTTOM LINE: ${conclusions[kind] || conclusions.generic}`,
    `SEVERITY: ${severity}`,
    `CONFIDENCE: ${confidence}%`,
    `KEY EVIDENCE: ${evidence.slice(0, 3).join("; ")}`,
    `MITRE ATT&CK: ${mitre.length ? mitre.map((m) => `${m.id} ${m.name}`).join("; ") : "None identified"}`,
    `IMMEDIATE ACTION: ${actions[kind] || actions.generic}`,
    `NEXT INVESTIGATION: ${next[kind] || next.generic}`,
  ].join("\n");
}

/**
 * Score one incident (a group of correlated alerts).
 * Signal points per spec §7: +20 privileged, +15 failed logins, +15 unusual IP,
 * +15 login-after-failures, +20 large transfer, +25 malicious IOC, +10 multi-source.
 */
export function scoreIncident(alerts: ScorerAlert[]): ScorerResult {
  const sorted = [...alerts].sort((a, b) => +a.timestamp - +b.timestamp);
  const descriptions = sorted.map((a) => a.description.toLowerCase());
  const iocMatch = sorted.some((a) => {
    const m = parseMeta(a.metadata);
    return m.iocMatch === true || maliciousIocValues(a).length > 0;
  });
  const iocValues = [...new Set(sorted.flatMap((a) => maliciousIocValues(a)))];

  const privileged = hasPrivilegedAccount(sorted);
  const failedEvents = sorted.filter((a) => isFailedLogin(a));
  const mentionedMax = sorted.reduce((acc, a) => Math.max(acc, mentionedFailureCount(a)), 0);
  const failedSignal = failedEvents.length >= 5 || mentionedMax >= 5;

  const external = externalIps(sorted);
  const unusualIp = external.length > 0;

  let successAfterFail = false;
  for (const s of sorted.filter(isSuccessLogin)) {
    const fail = sorted.find((f) => isFailedLogin(f) && +f.timestamp <= +s.timestamp);
    if (fail) {
      successAfterFail = true;
      break;
    }
  }

  const largeSignal = sorted.some((a) => isLargeTransfer(a));
  const distinctSources = [...new Set(sorted.map((a) => a.source))];
  const portScan = sorted.some((a) => /port_scan|network_scan|scan_pattern|network_scan/.test(a.event) || /scan/i.test(a.event));

  const riskSignals: RiskSignal[] = [];
  let score = 0;
  const add = (signal: string, points: number, hit: boolean): void => {
    if (hit) {
      riskSignals.push({ signal, points });
      score += points;
    }
  };
  add("Privileged account involved", 20, privileged !== null);
  add("Multiple failed logins", 15, failedSignal);
  add("Unknown/unusual source IP", 15, unusualIp);
  add("Successful login after failures", 15, successAfterFail);
  add("Large or unusual data transfer", 20, largeSignal);
  add("Known malicious IOC match", 25, iocMatch);
  add("Multiple correlated sources", 10, distinctSources.length >= 3);
  const threatScore = Math.min(100, score);

  // False-positive heuristics (spec F5)
  const benignHit = descriptions.some((d) => BENIGN_KEYWORDS.some((k) => d.includes(k)));
  const allInternal =
    !unusualIp && sorted.every((a) => !a.ip || isInternalIp(a.ip));
  const fpHit =
    threatScore < 45 &&
    (benignHit ||
      (allInternal && !iocMatch && failedEvents.length <= 3) ||
      (distinctSources.includes("scanner") && benignHit));

  let severity: Severity;
  let classification: Classification;
  if (fpHit) {
    severity = "False Positive";
    classification = "False Positive";
  } else if (threatScore >= 85) {
    severity = "Critical";
    classification = "Genuine Threat";
  } else if (threatScore >= 70) {
    severity = "High";
    classification = "Genuine Threat";
  } else if (threatScore >= 45) {
    severity = "Medium";
    classification = "Genuine Threat";
  } else if (threatScore >= 20) {
    severity = "Low";
    classification = "Genuine Threat";
  } else {
    severity = "Low";
    classification = "Under Review";
  }

  // Confidence heuristic (LLM bump added later by the analyze route)
  let confidence = 60;
  if (iocMatch) confidence += 10;
  if (sorted.length >= 4) confidence += 10;
  if (distinctSources.length >= 3) confidence += 5;
  if (privileged) confidence += 5;
  confidence = Math.min(96, confidence);

  const mitre = matchMitre(sorted);
  const title = buildTitle(sorted, {
    fp: fpHit,
    privileged,
    failedSignal,
    successAfterFail,
    largeSignal,
    portScan,
    iocValues,
  });
  const evidence = buildEvidence(sorted, {
    failedSignal,
    successAfterFail,
    largeSignal,
    iocValues,
    privileged,
    external,
    distinctSources: distinctSources.map((s) => sourceLabelFor(s)),
  });

  const primary = sorted[0];
  const kind = fpHit
    ? "fp"
    : privileged && (failedSignal || successAfterFail)
      ? "admin"
      : portScan
        ? "scan"
        : iocMatch && sorted.some((a) => /outbound|beacon|c2|connection/.test(a.event))
          ? "c2"
          : largeSignal
            ? "exfil"
            : "generic";

  const bluf = buildBluf(severity, confidence, evidence, mitre, title, fpHit, {
    user: privileged || primary?.user,
    device: primary?.device,
    ip: primary?.ip,
    iocValues,
    kind,
  });

  return {
    threatScore,
    severity,
    classification,
    riskSignals,
    mitre,
    evidence,
    bluf,
    confidence,
    title,
  };
}
