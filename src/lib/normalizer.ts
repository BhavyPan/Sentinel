/**
 * SentinelAI normalizer (spec §5, F2).
 * Converts raw multi-format feeds (SIEM/EDR JSON, CSV, satellite text, intel report)
 * into one common NormalizedAlertInput structure, extracting IOCs on the way.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { isMaliciousDomain, isMaliciousHash, isMaliciousIp } from "./threat-intel";

export type ParsedFormat = "json" | "csv" | "text";
export type RequestedFormat = "auto" | "json" | "csv" | "text";

export interface IocBundle {
  ips: string[];
  domains: string[];
  hashes: string[];
}

export interface NormalizedAlertInput {
  alertId: string;
  source: string;
  sourceLabel: string;
  timestamp: Date;
  user?: string;
  device?: string;
  ip?: string;
  event: string;
  description: string;
  rawSeverity: string;
  rawFormat: ParsedFormat;
  metadata: Record<string, unknown>;
}

/** Friendly display labels per source key */
export const SOURCE_LABELS: Record<string, string> = {
  siem: "SIEM Platform",
  firewall: "Firewall",
  auth: "Authentication",
  edr: "EDR Sensor",
  ids: "IDS Sensor",
  "dns-sensor": "DNS Sensor",
  "file-server": "File Server",
  satellite: "Satellite Feed",
  "intel-report": "Intel Report",
  waf: "WAF",
  scanner: "Vulnerability Scanner",
  "threat-intel": "Threat Intel Feed",
};

export function sourceLabelFor(source: string): string {
  const key = (source || "").trim().toLowerCase();
  if (!key) return "Unknown Source";
  const known = SOURCE_LABELS[key];
  if (known) return known;
  return key
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Normalize event key: lowercase, spaces/hyphens -> underscores */
export function normalizeEvent(event: string): string {
  return (event || "")
    .trim()
    .toLowerCase()
    .replace(/[\s\-]+/g, "_")
    .replace(/_+/g, "_");
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const HASH_RE = /\b[a-fA-F0-9]{32,64}\b/g;
/** File extensions that look like domains but are not (winword.exe etc.) */
const NON_DOMAIN_EXTS = new Set([
  "exe", "dll", "sys", "dat", "log", "tmp", "zip", "rar", "7z", "doc", "docx",
  "pdf", "txt", "cfg", "ini", "bin", "iso", "msi", "png", "jpg", "jpeg", "gif",
  "db", "bak", "enc", "ps1", "bat", "cmd", "vbs", "jar",
]);

function extractIocs(ipField: string | undefined, description: string): IocBundle {
  const text = description || "";
  const ips = new Set<string>();
  const domains = new Set<string>();
  const hashes = new Set<string>();

  for (const m of text.matchAll(IPV4_RE)) if (isIP(m[0])) ips.add(m[0]);
  if (ipField && isIP(ipField)) ips.add(ipField);

  for (const m of text.matchAll(DOMAIN_RE)) {
    const token = m[0].toLowerCase().replace(/\.+$/, "");
    const tld = token.split(".").pop() || "";
    if (NON_DOMAIN_EXTS.has(tld)) continue;
    domains.add(token);
  }

  for (const m of text.matchAll(HASH_RE)) hashes.add(m[0].toLowerCase());

  return { ips: [...ips], domains: [...domains], hashes: [...hashes] };
}

function buildMetadata(
  ipField: string | undefined,
  description: string,
  extra?: Record<string, unknown>
): Record<string, unknown> {
  const metadata: Record<string, unknown> = { ...(extra || {}) };
  delete metadata.iocMatch;
  delete metadata.iocMatches;
  const iocs = extractIocs(ipField, description + " " + JSON.stringify(extra ?? {}));
  metadata.iocs = iocs;
  if (iocs.ips.length || iocs.domains.length || iocs.hashes.length) {
    metadata.iocs = iocs;
    const matches = [
      ...iocs.ips.filter((v) => isMaliciousIp(v)),
      ...iocs.domains.filter((v) => isMaliciousDomain(v)),
      ...iocs.hashes.filter((v) => isMaliciousHash(v)),
    ];
    if (matches.length) {
      metadata.iocMatch = true;
      metadata.iocMatches = [...new Set(matches)];
    }
  }
  return metadata;
}

function parseTimestamp(value: unknown, context: string): Date {
  let input = String(value ?? "");
  // Zone-less ISO timestamps in imported feeds use UTC on every host.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(input)) input += "Z";
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`Invalid timestamp "${String(value)}" in ${context}`);
  }
  return d;
}

function opt(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  const s = String(v).trim();
  return s === "" ? undefined : s;
}

function required(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Missing or invalid ${field}`);
  return value.trim();
}

function checkedIp(value: unknown): string | undefined {
  const ip = opt(value);
  if (ip && !isIP(ip)) throw new Error(`Invalid IP address: ${ip}`);
  return ip;
}

function severityValue(value: unknown): string {
  const severity = String(value ?? "medium").trim().toLowerCase();
  if (!["info", "low", "medium", "high", "critical"].includes(severity)) throw new Error(`Invalid severity: ${severity}`);
  return severity;
}

// ---------------------------------------------------------------- JSON feeds

function normalizeJsonObject(obj: Record<string, unknown>, index: number): NormalizedAlertInput {
  const isCanonical = "alert_id" in obj;
  const isVendor = "id" in obj && ("sensor" in obj || "@timestamp" in obj);
  if (!isCanonical && !isVendor) {
    throw new Error(`Unrecognized JSON alert schema at index ${index}`);
  }

  const alertId = required(isCanonical ? obj.alert_id : obj.id, "alert_id");
  const source = required(isCanonical ? obj.source : obj.sensor, "source").toLowerCase();
  const timestamp = parseTimestamp(
    isCanonical ? obj.timestamp : obj["@timestamp"],
    `alert ${alertId}`
  );
  const user = opt(isCanonical ? obj.user : obj.account);
  const device = opt(isCanonical ? obj.device : obj.hostname);
  const ip = checkedIp(isCanonical ? obj.ip : obj.src_ip);
  const event = normalizeEvent(required(isCanonical ? obj.event : obj.event_type, "event"));
  const description = required(isCanonical ? obj.description : obj.message, "description");
  const rawSeverity = severityValue(isCanonical ? obj.raw_severity : obj.severity);

  return {
    alertId,
    source,
    sourceLabel: sourceLabelFor(source),
    timestamp,
    user,
    device,
    ip,
    event: event || "unknown_event",
    description,
    rawSeverity,
    rawFormat: "json",
    metadata: buildMetadata(ip, description, typeof obj.metadata === "object" && obj.metadata !== null && !Array.isArray(obj.metadata) ? obj.metadata as Record<string, unknown> : undefined),
  };
}

function parseJson(raw: string): NormalizedAlertInput[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Invalid JSON payload");
  }
  const arr: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  return arr.map((el, i) => {
    if (typeof el !== "object" || el === null || Array.isArray(el)) {
      throw new Error(`JSON alert at index ${i} is not an object`);
    }
    return normalizeJsonObject(el as Record<string, unknown>, i);
  });
}

// ---------------------------------------------------------------- CSV feeds

/** Quote-aware CSV line splitter (handles "quoted, fields" and "" escapes) */
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      out.push(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  if (inQuotes) throw new Error("Unclosed CSV quoted field");
  out.push(cur);
  return out;
}

/**
 * CSV header: alert_id,source,timestamp,user,device,ip,event,description,severity
 * Descriptions may contain commas; severity is always the LAST column, description
 * is everything between column 7 (event) and the last column.
 */
function parseCsv(raw: string): NormalizedAlertInput[] {
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+$/, ""))
    .filter((l) => l.trim().length > 0);
  if (lines.length === 0) throw new Error("Empty CSV payload");

  const start = /^alert_id\s*,/i.test(lines[0].trim()) ? 1 : 0;
  const out: NormalizedAlertInput[] = [];
  for (let i = start; i < lines.length; i++) {
    const parts = splitCsvLine(lines[i]).map((p) => p.trim());
    if (parts.length < 9) {
      throw new Error(`CSV line ${i + 1} has ${parts.length} columns, expected >= 9`);
    }
    const alertId = required(parts[0], "alert_id");
    const source = required(parts[1], "source").toLowerCase();
    const timestamp = parseTimestamp(parts[2], `CSV alert ${alertId}`);
    const user = opt(parts[3]);
    const device = opt(parts[4]);
    const ip = checkedIp(parts[5]);
    const event = normalizeEvent(required(parts[6], "event"));
    const severity = severityValue(parts[parts.length - 1]);
    const description = parts.slice(7, parts.length - 1).join(",");

    out.push({
      alertId,
      source,
      sourceLabel: sourceLabelFor(source),
      timestamp,
      user,
      device,
      ip,
      event: event || "unknown_event",
      description,
      rawSeverity: severity || "medium",
      rawFormat: "csv",
      metadata: buildMetadata(ip, description),
    });
  }
  return out;
}

// ---------------------------------------------------------------- Text feeds

const SATELLITE_RE =
  /^\[([^\]]+)\]\s+(\S+)\s+SEV:(\w+)\s+(\S+)\s+::\s+(.*)$/;
const SATELLITE_GROUP = { tag: 1, ts: 2, sev: 3, station: 4, text: 5 } as const;

function parseIntelReport(raw: string, seq: number): NormalizedAlertInput {
  const lines = raw.split(/\r?\n/);
  const published = raw.match(/^Published:\s*(\S+)/m);
  const timestamp = published
    ? parseTimestamp(published[1], "intel report Published field")
    : new Date();

  // Description: the paragraph starting with "SUMMARY:" (until blank line), else body after line 1.
  let description = "";
  const summaryStart = lines.findIndex((l) => /^SUMMARY:/i.test(l));
  if (summaryStart >= 0) {
    const para: string[] = [];
    for (let i = summaryStart; i < lines.length; i++) {
      if (i > summaryStart && lines[i].trim() === "") break;
      para.push(lines[i].trim());
    }
    description = para.join(" ");
  } else {
    description = lines.slice(1).join(" ").trim();
  }
  description = description.slice(0, 240).trim();

  const source = "intel-report";
  return {
    alertId: `INTL-${createHash("sha256").update(raw).digest("hex").slice(0, 16)}`,
    source,
    sourceLabel: sourceLabelFor(source),
    timestamp,
    user: undefined,
    device: undefined,
    ip: undefined,
    event: "intelligence_report",
    description: description || "Intelligence report received",
    rawSeverity: "info",
    rawFormat: "text",
    metadata: buildMetadata(undefined, raw),
  };
}

function parseText(raw: string): NormalizedAlertInput[] {
  if (/^INTELLIGENCE REPORT/i.test(raw.trim())) {
    return [parseIntelReport(raw.trim(), 0)];
  }

  const out: NormalizedAlertInput[] = [];
  let seq = 0;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const m = SATELLITE_RE.exec(trimmed);
    if (!m) throw new Error(`Unrecognized satellite line: ${trimmed.slice(0, 80)}`);
    const tag = m[SATELLITE_GROUP.tag];
    const ts = m[SATELLITE_GROUP.ts];
    const sev = m[SATELLITE_GROUP.sev];
    const station = m[SATELLITE_GROUP.station];
    const text = m[SATELLITE_GROUP.text];
    const source = "satellite";
    out.push({
      alertId: `SAT-${tag}-${createHash("sha256").update(trimmed).digest("hex").slice(0, 12)}`,
      source,
      sourceLabel: sourceLabelFor(source),
      timestamp: parseTimestamp(ts, `satellite line ${seq + 1}`),
      user: undefined,
      device: station,
      ip: undefined,
      event: "satellite_telemetry",
      description: text.trim(),
      rawSeverity: sev.toLowerCase(),
      rawFormat: "text",
      metadata: buildMetadata(undefined, text, { tag, station }),
    });
    seq++;
  }
  if (out.length === 0) {
    throw new Error(
      "Unrecognized text feed: expected satellite lines ([TAG] ts SEV:x STATION :: text) or an INTELLIGENCE REPORT"
    );
  }
  return out;
}

// ---------------------------------------------------------------- Auto detect

function detectFormat(raw: string): ParsedFormat {
  const first = raw.trimStart().charAt(0);
  if (first === "{" || first === "[") {
    try {
      JSON.parse(raw);
      return "json";
    } catch {
      // not valid JSON — fall through (e.g. satellite text starts with "[")
    }
  }
  if (/^alert_id\s*,/i.test(raw.trimStart().split(/\r?\n/)[0] || "")) return "csv";
  if (/^INTELLIGENCE REPORT/i.test(raw.trimStart())) return "text";
  const line = raw.split(/\r?\n/).find((l) => l.trim().length > 0) || "";
  if (SATELLITE_RE.test(line.trim())) return "text";
  return "text";
}

/**
 * Main entry: parse a raw feed (auto-detecting format unless forced) into
 * normalized alert inputs. Throws on structurally invalid items; the caller
 * (import route) counts thrown batches as failed.
 */
export function parseAndNormalize(
  raw: string,
  format: RequestedFormat = "auto"
): NormalizedAlertInput[] {
  const text = (raw ?? "").trim();
  if (!text) throw new Error("Empty payload");
  const fmt: ParsedFormat = format === "auto" ? detectFormat(text) : format;
  if (fmt === "json") return parseJson(text);
  if (fmt === "csv") return parseCsv(text);
  return parseText(text);
}

/** Parse rows independently so one malformed alert cannot discard valid siblings. */
export function normalizeBatch(raw: string, format: RequestedFormat = "auto"): {
  alerts: NormalizedAlertInput[]; errors: { row: number; message: string }[];
} {
  const text = raw.trim().replace(/^\uFEFF/, "");
  const fmt = format === "auto" ? detectFormat(text) : format;
  const alerts: NormalizedAlertInput[] = [];
  const errors: { row: number; message: string }[] = [];
  let records: unknown[];
  if (fmt === "json") {
    const parsed = JSON.parse(text);
    records = Array.isArray(parsed) ? parsed : [parsed];
  } else if (fmt === "csv") {
    records = text.split(/\r?\n/).filter((l) => l.trim());
    if (/^alert_id\s*,/i.test(String(records[0]))) records.shift();
  } else {
    records = /^INTELLIGENCE REPORT/i.test(text) ? [text] : text.split(/\r?\n/).filter((l) => l.trim());
  }
  records.forEach((record, i) => {
    try { alerts.push(...parseAndNormalize(fmt === "json" ? JSON.stringify(record) : String(record), fmt)); }
    catch (error) { errors.push({ row: i + 1, message: error instanceof Error ? error.message : "Invalid alert" }); }
  });
  if (!records.length) throw new Error("No alerts in payload");
  return { alerts, errors };
}
