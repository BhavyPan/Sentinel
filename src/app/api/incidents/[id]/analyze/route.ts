import { analystActions, reviewedBluf } from "@/lib/analyst-verdict";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { parseJsonSafe, toIncidentDetailDTO } from "@/lib/summary";
import { analyzeIncidentWithLLM, type LlmAlertContext, type LlmBaseline } from "@/lib/llm";
import { scoreIncident } from "@/lib/scorer";
import { refreshIntel } from "@/lib/watchlist";
import type { MitreTechnique } from "@/lib/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** POST /api/incidents/[id]/analyze — LLM analysis merged over deterministic baseline */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const incident = await db.incident.findFirst({
      where: { OR: [{ id }, { incidentId: id }] },
      include: {
        alerts: { orderBy: { timestamp: "asc" } },
        events: { orderBy: { createdAt: "desc" } },
      },
    });
    if (!incident) {
      return NextResponse.json({ error: `Incident ${id} not found` }, { status: 404 });
    }

    await refreshIntel();
    const baseline: LlmBaseline = {
      title: incident.title,
      classification: incident.classification,
      severity: incident.severity,
      threatScore: incident.threatScore,
      confidence: incident.confidence,
      evidence: parseJsonSafe<string[]>(incident.evidence, []),
      mitre: parseJsonSafe<MitreTechnique[]>(incident.mitre, []),
      bluf: incident.bluf,
    };

    const alertCtx: LlmAlertContext[] = incident.alerts.map((a) => ({
      alertId: a.alertId,
      source: a.sourceLabel || a.source,
      timestamp: a.timestamp.toISOString(),
      user: a.user,
      device: a.device,
      ip: a.ip,
      event: a.event,
      description: a.description,
      rawSeverity: a.rawSeverity,
    }));

    const llm = await analyzeIncidentWithLLM({
      incidentId: incident.incidentId,
      baseline,
      alerts: alertCtx,
    });

    let llmUsed = false;
    let message = "AI service unavailable — local rule-based report is ready. Configure your provider to enable AI analysis.";

    const current = await db.incident.findUnique({ where: { id: incident.id } });
    if (!current || +current.updatedAt !== +incident.updatedAt) return NextResponse.json({ error: "Incident changed during analysis. Refresh and run analysis again." }, { status: 409 });
    if (llm) {
      llmUsed = true;
      message = "AI analysis complete";

      // Preserve any analyst note appended to the explanation.
      // Matches both the legacy "[Analyst] …" suffix and the newer "[name · stamp] …" audit entries.
      let explanation = llm.explanation || incident.explanation || "";
      const noteMatch = /(?:^|\n\n)\[[^\]\n]+\]/.exec(incident.explanation || "");
      if (noteMatch && noteMatch.index >= 0) {
        explanation = `${explanation}${(incident.explanation || "").slice(noteMatch.index)}`;
      }

      // Use validated confidence without an arbitrary increase.
      const confidence = llm.confidence;

      const reviewed = incident.events.some((e) => e.kind === "classification");
      const classification = reviewed ? incident.classification : llm.classification;
      const severity = classification === "False Positive" ? "False Positive" : llm.severity === "False Positive" ? "Low" : llm.severity;
      await db.incident.update({
        where: { id: incident.id },
        data: {
          title: llm.title,
          classification,
          severity,
          threatScore: llm.threatScore,
          confidence,
          explanation: explanation || null,
          evidence: JSON.stringify(llm.evidence),
          mitre: JSON.stringify(llm.mitre),
          bluf: (reviewed ? reviewedBluf(llm.bluf, classification) : llm.bluf).replace(/^SEVERITY:.*$/m, `SEVERITY: ${severity}`),
          recommendedActions: reviewed ? JSON.stringify(analystActions(classification)) :
            llm.recommendedActions.length > 0
              ? JSON.stringify(llm.recommendedActions)
              : incident.recommendedActions,
          analyzed: true,
        },
      });

      // audit: record the analysis run (best effort)
      try {
        await db.incidentEvent.create({
          data: {
            incidentId: incident.id,
            kind: "analysis",
            actor: "SentinelAI",
            detail: llmUsed
              ? `AI analysis — score ${llm.threatScore}/100, ${llm.classification}, confidence ${llm.confidence}%`
              : "AI analysis run",
          },
        });
      } catch {
        // best-effort
      }
    }

    if (!llm) {
      const result = scoreIncident(incident.alerts);
      const note = incident.explanation?.match(/(?:^|\n\n)\[[^\]\n]+\][\s\S]*/)?.[0]?.trim();
      // Keep any successful prior AI assessment; the fallback never masquerades as an LLM run.
      if (!incident.analyzed) await db.incident.update({ where: { id: incident.id }, data: {
        explanation: [result.explanation, note].filter(Boolean).join("\n\n"),
      } });
    }

    const updated = await db.incident.findFirst({
      where: { id: incident.id },
      include: {
        alerts: { orderBy: { timestamp: "asc" } },
        events: { orderBy: { createdAt: "desc" } },
      },
    });

    return NextResponse.json({
      incident: updated ? toIncidentDetailDTO(updated) : null,
      llmUsed,
      message,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Analysis failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
