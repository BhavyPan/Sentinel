/**
 * SentinelAI — client-side PDF incident report builder (jsPDF).
 *
 * This module is ONLY imported dynamically (`await import("@/lib/report-pdf")`)
 * from the incident analysis view, so jsPDF stays out of the initial bundle.
 */
import type { IncidentDetailDTO } from "./types";

// A4 portrait in pt
const PAGE_W = 595.28;
const PAGE_H = 841.89;
const M = 48; // page margin
const CW = PAGE_W - M * 2; // content width
const FOOTER_Y = PAGE_H - 34;

const SEV_HEX: Record<string, [number, number, number]> = {
  Critical: [239, 68, 68],
  High: [245, 158, 11],
  Medium: [234, 179, 8],
  Low: [16, 185, 129],
  "False Positive": [100, 116, 139],
};

const INK: [number, number, number] = [24, 32, 28];
const MUTED: [number, number, number] = [96, 106, 100];
const ACCENT: [number, number, number] = [16, 185, 129]; // emerald 500
const DARK: [number, number, number] = [10, 16, 13];

/**
 * Build the multi-page PDF for one incident and trigger the browser download.
 * A4 portrait, styled header band, numbered sections, per-page footers.
 */
export async function downloadIncidentPdf(incident: IncidentDetailDTO): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "pt", format: "a4", compress: true });

  const sev = SEV_HEX[incident.severity] ?? SEV_HEX["False Positive"];
  let y = 0;

  const setInk = () => doc.setTextColor(INK[0], INK[1], INK[2]);
  const setMuted = () => doc.setTextColor(MUTED[0], MUTED[1], MUTED[2]);

  const mono = (size: number, style: "normal" | "bold" = "normal") => {
    doc.setFont("courier", style);
    doc.setFontSize(size);
  };
  const sans = (size: number, style: "normal" | "bold" = "normal") => {
    doc.setFont("helvetica", style);
    doc.setFontSize(size);
  };

  const ensure = (needed: number) => {
    if (y + needed <= FOOTER_Y - 12) return;
    doc.addPage();
    doc.setFillColor(DARK[0], DARK[1], DARK[2]);
    doc.rect(0, 0, PAGE_W, 22, "F");
    mono(7.5, "bold");
    doc.setTextColor(160, 174, 165);
    doc.text(`SENTINELAI INCIDENT REPORT — ${incident.incidentId} (continued)`, M, 14.5);
    y = 44;
  };

  const sectionHeader = (num: string, title: string) => {
    ensure(46);
    y += 12;
    doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2]);
    doc.rect(M, y - 9, 16, 16, "F");
    mono(8.5, "bold");
    doc.setTextColor(255, 255, 255);
    doc.text(num, M + 3.5, y + 2.5);
    sans(11.5, "bold");
    setInk();
    const titleText = title.toUpperCase();
    doc.text(titleText, M + 24, y + 3);
    doc.setDrawColor(226, 232, 228);
    doc.setLineWidth(0.75);
    doc.line(M + 24 + doc.getTextWidth(titleText) + 10, y + 1, PAGE_W - M, y + 1);
    y += 20;
  };

  const wrapped = (text: string, opts?: { indent?: number; size?: number; leading?: number; useMono?: boolean; color?: [number, number, number] }) => {
    const indent = opts?.indent ?? 0;
    const size = opts?.size ?? 9.5;
    const leading = opts?.leading ?? size + 4.5;
    if (opts?.useMono === false) sans(size); else mono(size);
    if (opts?.color) doc.setTextColor(opts.color[0], opts.color[1], opts.color[2]);
    else setInk();
    const lines: string[] = doc.splitTextToSize(text, CW - indent);
    for (const line of lines) {
      ensure(leading);
      doc.text(line, M + indent, y);
      y += leading;
    }
  };

  const keyValue = (pairs: [string, string][]) => {
    const colW = CW / 2;
    for (let i = 0; i < pairs.length; i += 2) {
      ensure(16);
      const row = [pairs[i], pairs[i + 1]].filter(Boolean) as [string, string][];
      row.forEach(([k, v], c) => {
        const x = M + c * colW;
        mono(7.5);
        setMuted();
        doc.text(k.toUpperCase(), x, y);
        mono(9.5, "bold");
        setInk();
        doc.text(doc.splitTextToSize(v, colW - 14)[0] ?? "", x, y + 12);
      });
      y += 24;
    }
  };

  // ------------------------------------------------------------ cover header
  doc.setFillColor(DARK[0], DARK[1], DARK[2]);
  doc.rect(0, 0, PAGE_W, 108, "F");
  doc.setFillColor(sev[0], sev[1], sev[2]);
  doc.rect(0, 108, PAGE_W, 5, "F");

  mono(8, "bold");
  doc.setTextColor(110, 231, 183); // emerald 300
  doc.text("SENTINELAI  ·  INCIDENT REPORT", M, 34);

  sans(19, "bold");
  doc.setTextColor(255, 255, 255);
  doc.text(incident.incidentId, M, 62);

  // severity pill (right)
  sans(9.5, "bold");
  const pillW = doc.getTextWidth(incident.severity.toUpperCase()) * 1.15 + 28;
  doc.setFillColor(sev[0], sev[1], sev[2]);
  doc.roundedRect(PAGE_W - M - pillW, 40, pillW, 20, 10, 10, "F");
  doc.setTextColor(255, 255, 255);
  doc.text(incident.severity.toUpperCase(), PAGE_W - M - pillW + 14, 53.5);

  mono(7.5);
  doc.setTextColor(148, 163, 155);
  doc.text(`GENERATED ${new Date().toISOString().replace("T", " ").slice(0, 16)}Z  ·  SENTINELAI D2 THREAT PRIORITISATION`, M, 88);

  y = 138;

  // ------------------------------------------------------------ meta
  sans(13, "bold");
  setInk();
  const titleLines: string[] = doc.splitTextToSize(incident.title, CW);
  for (const t of titleLines) {
    doc.text(t, M, y);
    y += 17;
  }
  y += 4;
  // cap the source list so the value never clips mid-word
  const srcDisplay =
    incident.sources.length <= 2
      ? incident.sources.join(", ")
      : `${incident.sources[0]}, ${incident.sources[1]} +${incident.sources.length - 2} more`;
  keyValue([
    ["Severity", incident.severity],
    ["Classification", incident.classification],
    ["Threat score", `${incident.threatScore}/100`],
    ["Confidence", `${incident.confidence}%`],
    ["Status", incident.status],
    ["Related alerts", `${incident.alertCount}  (${srcDisplay || "n/a"})`],
  ]);

  // ------------------------------------------------------------ BLUF
  if (incident.bluf) {
    sectionHeader("1", "BLUF — Bottom Line Up Front");
    wrapped(incident.bluf, { indent: 6, leading: 15 });
  }

  // ------------------------------------------------------------ MITRE
  if (incident.mitre.length > 0) {
    sectionHeader("2", "MITRE ATT&CK Mapping");
    mono(9);
    const tacticMaxChars = Math.floor((CW - 240 - 6) / 5.05); // fit inside right margin
    for (const t of incident.mitre) {
      ensure(14);
      mono(9, "bold");
      doc.setTextColor(ACCENT[0], ACCENT[1], ACCENT[2]);
      doc.text(t.id, M + 6, y);
      mono(9);
      setInk();
      doc.text(t.name, M + 52, y);
      setMuted();
      const tactic = t.tactic.length > tacticMaxChars ? t.tactic.slice(0, tacticMaxChars - 1) + "…" : t.tactic;
      doc.text(`[${tactic}]`, M + 240, y);
      y += 14;
    }
  }

  // ------------------------------------------------------------ risk signals
  if (incident.riskSignals.length > 0) {
    sectionHeader("3", "Risk Signals");
    for (const r of incident.riskSignals) {
      ensure(14);
      mono(9, "bold");
      doc.setTextColor(sev[0], sev[1], sev[2]);
      doc.text(`+${r.points}`, M + 6, y);
      mono(9);
      setInk();
      doc.text(r.signal, M + 40, y);
      y += 14;
    }
  }

  // ------------------------------------------------------------ explanation
  if (incident.explanation) {
    sectionHeader("4", "Analyst Explanation");
    wrapped(incident.explanation, { indent: 6 });
  }

  // ------------------------------------------------------------ actions
  if (incident.recommendedActions.length > 0) {
    sectionHeader("5", "Recommended Actions");
    incident.recommendedActions.forEach((a, i) => {
      ensure(26);
      doc.setFillColor(236, 253, 245);
      doc.roundedRect(M + 4, y - 9.5, 14, 14, 3, 3, "F");
      mono(8, "bold");
      doc.setTextColor(5, 150, 105);
      doc.text(String(i + 1), M + 8, y + 1);
      wrapped(a, { indent: 26, size: 9.5 });
      y += 4;
    });
  }

  // ------------------------------------------------------------ evidence
  if (incident.evidence.length > 0) {
    sectionHeader("6", "Key Evidence");
    for (const e of incident.evidence) {
      ensure(14);
      mono(9);
      doc.setTextColor(ACCENT[0], ACCENT[1], ACCENT[2]);
      doc.text("+", M + 6, y);
      wrapped(e, { indent: 20 });
      y += 2;
    }
  }

  // ------------------------------------------------------------ timeline
  if (incident.alerts.length > 0) {
    sectionHeader("7", "Related Alert Timeline");
    for (const a of incident.alerts) {
      const head = `${a.timestamp.replace("T", " ").slice(0, 19)}Z  [${a.sourceLabel}]  ${a.event}  (${a.alertId})`;
      ensure(30);
      mono(8, "bold");
      setInk();
      const headLines: string[] = doc.splitTextToSize(head, CW - 6);
      for (const hl of headLines) {
        doc.text(hl, M + 6, y);
        y += 11.5;
      }
      wrapped(a.description, { indent: 20, size: 8.5, color: MUTED });
      y += 5;
    }
  }

  // ------------------------------------------------------------ footers
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setDrawColor(226, 232, 228);
    doc.setLineWidth(0.5);
    doc.line(M, FOOTER_Y, PAGE_W - M, FOOTER_Y);
    mono(7);
    setMuted();
    doc.text("SentinelAI — simulated demo data, not for operational use.", M, FOOTER_Y + 13);
    doc.text(`Page ${p} of ${pages}`, PAGE_W - M, FOOTER_Y + 13, { align: "right" });
  }

  doc.save(`SentinelAI-report-${incident.incidentId}.pdf`);
}
