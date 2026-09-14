import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { parseJsonSafe, toIncidentDetailDTO } from "@/lib/summary";
import { analyzeIncidentWithLLM, type LlmAlertContext, type LlmBaseline } from "@/lib/llm";
import type { MitreTechnique } from "@/lib/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** POST /api/incidents/[id]/analyze — LLM analysis merged over deterministic baseline */
export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const incident = await db.incident.findFirst({
      where: { OR: [{ id }, { incidentId: id }] },
      include: { alerts: { orderBy: { timestamp: "asc" } } },
    });
    if (!incident) {
      return NextResponse.json({ error: `Incident ${id} not found` }, { status: 404 });
    }

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
    let message = "LLM unavailable — deterministic baseline retained";

    if (llm) {
      llmUsed = true;
      message = "AI analysis complete";

      // Preserve any analyst note appended to the explanation.
      // Matches both the legacy "[Analyst] …" suffix and the newer "[name · stamp] …" audit entries.
      let explanation = llm.explanation || incident.explanation || "";
      const noteMatch = /\n\n\[[^\]\n]+\]/.exec(incident.explanation || "");
      if (noteMatch && noteMatch.index >= 0) {
        explanation = `${explanation}${(incident.explanation || "").slice(noteMatch.index)}`;
      }

      // LLM values win when valid; confidence bump +5, cap 96
      const confidence = Math.min(96, llm.confidence + 5);

      await db.incident.update({
        where: { id: incident.id },
        data: {
          title: llm.title,
          classification: llm.classification,
          severity: llm.severity,
          threatScore: llm.threatScore,
          confidence,
          explanation: explanation || null,
          evidence: JSON.stringify(llm.evidence),
          mitre: JSON.stringify(llm.mitre),
          bluf: llm.bluf || incident.bluf,
          recommendedActions:
            llm.recommendedActions.length > 0
              ? JSON.stringify(llm.recommendedActions)
              : incident.recommendedActions,
          analyzed: true,
        },
      });
    }

    const updated = await db.incident.findFirst({
      where: { id: incident.id },
      include: { alerts: { orderBy: { timestamp: "asc" } } },
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
