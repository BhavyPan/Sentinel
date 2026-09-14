/**
 * Client-side-safe parsing helpers for bulk IOC paste.
 * Shared by the Watchlist bulk-import dialog (live preview) and the
 * /api/watchlist/bulk route (server-side import) so both count identically.
 */

export type BulkIocType = "ip" | "domain" | "hash";

export interface ParsedIocLine {
  line: number; // 1-based source line number
  type: BulkIocType;
  value: string;
}

export interface ParseIocTextResult {
  parsed: ParsedIocLine[];
  skipped: { line: number; reason: string }[];
}

const IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;
const HEX = /^[a-f0-9]{8,64}$/i;

export function detectIocType(raw: string): BulkIocType | null {
  const v = raw.trim();
  if (!v || v.length > 200) return null;
  if (IPV4.test(v)) return "ip";
  if (HEX.test(v)) return "hash";
  if (DOMAIN.test(v)) return "domain";
  return null;
}

/** Split one CSV line into max 2 columns (type,value or value). */
function splitColumns(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else quoted = !quoted;
    } else if ((ch === "," || ch === ";" || ch === "\t") && !quoted) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out.map((c) => c.trim()).slice(0, 2);
}

/**
 * Parse a pasted block of IOCs.
 * Accepted per line:
 *   - `type,value` (ip|domain|hash) — explicit type column wins
 *   - bare value — type auto-detected (IPv4 → ip, hex → hash, else domain)
 *   - blank lines and `#`/`//` comments are skipped (not errors)
 */
export function parseIocText(text: string, maxLines = 200): ParseIocTextResult {
  const parsed: ParsedIocLine[] = [];
  const skipped: { line: number; reason: string }[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length && parsed.length < maxLines; i++) {
    const raw = lines[i].trim();
    const lineNo = i + 1;
    if (!raw || raw.startsWith("#") || raw.startsWith("//")) continue;
    if (parsed.length >= maxLines) {
      skipped.push({ line: lineNo, reason: `exceeded ${maxLines}-line limit` });
      continue;
    }

    let type: BulkIocType | null = null;
    let value: string | null = null;
    const cols = splitColumns(raw);
    const first = cols[0] ?? "";
    const second = cols.length >= 2 ? cols[1] ?? "" : "";

    if (["ip", "domain", "hash"].includes(first.toLowerCase())) {
      // explicit `type,value` row — verify the value matches the claimed type
      type = first.toLowerCase() as BulkIocType;
      const probe = second ? detectIocType(second) : null;
      if (!probe || probe !== type) {
        skipped.push({ line: lineNo, reason: `value does not look like a ${type}` });
        continue;
      }
      value = second;
    } else {
      // bare row: prefer the first column if it auto-detects, else the second
      // (handles both `1.2.3.4,comment` and `comment,1.2.3.4`)
      const probeFirst = detectIocType(first);
      const probeSecond = second ? detectIocType(second) : null;
      if (probeFirst) {
        type = probeFirst;
        value = first;
      } else if (probeSecond) {
        type = probeSecond;
        value = second;
      }
    }

    if (!value) {
      skipped.push({ line: lineNo, reason: "empty value" });
      continue;
    }
    if (!type) {
      skipped.push({ line: lineNo, reason: `unrecognised format: "${value.slice(0, 40)}"` });
      continue;
    }
    const norm =
      type === "domain" || type === "hash" ? value.toLowerCase() : value;
    if (seen.has(norm)) {
      skipped.push({ line: lineNo, reason: "duplicate in paste" });
      continue;
    }
    seen.add(norm);
    parsed.push({ line: lineNo, type, value: norm });
  }

  if (lines.length > maxLines && parsed.length >= maxLines) {
    const rest = lines.length - maxLines;
    if (rest > 0) skipped.push({ line: maxLines + 1, reason: `+${rest} more line(s) ignored (limit ${maxLines})` });
  }
  return { parsed, skipped };
}
