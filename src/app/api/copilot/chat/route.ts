import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getDashboardSummary, rankIncidents } from "@/lib/summary";
import { copilotChat, localCopilot, type CopilotIncidentContext } from "@/lib/llm";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** GET /api/copilot/chat — history (asc, last 50) */
export async function GET() {
  try {
    const rows = await db.chatMessage.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
    });
    const messages = rows
      .reverse()
      .map((m) => ({
        id: m.id,
        role: m.role === "assistant" ? ("assistant" as const) : ("user" as const),
        content: m.content,
        createdAt: m.createdAt.toISOString(),
      }));
    return NextResponse.json({ messages });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to load chat history";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/** POST /api/copilot/chat — ask a question grounded in current incident data */
export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => null)) as { message?: unknown } | null;
    const question = typeof body?.message === "string" ? body.message.trim() : "";
    if (!question) {
      return NextResponse.json({ error: "Missing 'message'" }, { status: 400 });
    }

    if (question.length > 4000) return NextResponse.json({ error: "Question is limited to 4000 characters" }, { status: 400 });
    const summary = await getDashboardSummary();
    const allIncidents = rankIncidents(await db.incident.findMany({ include: { alerts: { orderBy: { timestamp: "asc" } } } }));
    const incidents: CopilotIncidentContext[] = allIncidents.map((i) => ({
      incidentId: i.incidentId, title: i.title, severity: i.severity, threatScore: i.threatScore,
      confidence: i.confidence, classification: i.classification, status: i.status,
      alertCount: i.alerts.length, keyEvents: [...new Set(i.alerts.map((a) => a.event))],
      blufExcerpt: i.bluf ?? "", evidence: JSON.parse(i.evidence), recommendedActions: JSON.parse(i.recommendedActions),
      alerts: i.alerts.slice(0, 30).map((a) => ({ ...a, timestamp: a.timestamp.toISOString() })),
    }));
    // Explicitly requested cases are included even when outside the priority shortlist.
    const requested = [...question.toUpperCase().matchAll(/(?:INC-|#)(\d+)/g)].map((m) => `INC-${m[1]}`);
    const relevant = incidents.filter((i) => requested.includes(i.incidentId));
    const snapshotIncidents = [...relevant, ...incidents.filter((i) => !requested.includes(i.incidentId))].slice(0, 20);

    const counts: Record<string, number | string | null> = {
      totalAlerts: summary.totalAlerts,
      correlatedAlerts: summary.correlatedAlerts,
      totalIncidents: summary.totalIncidents,
      critical: summary.counts.critical,
      high: summary.counts.high,
      medium: summary.counts.medium,
      low: summary.counts.low,
      falsePositive: summary.counts.falsePositive,
      open: summary.counts.open,
      lastUpdated: summary.lastUpdated,
    };

    const historyRows = await db.chatMessage.findMany({
      orderBy: { createdAt: "desc" },
      take: 6,
    });
    const history = historyRows
      .reverse()
      .map((m) => ({
        role: m.role === "assistant" ? ("assistant" as const) : ("user" as const),
        content: m.content,
      }));

    const aiReply = await copilotChat(question, { counts, incidents: snapshotIncidents }, history);
    const reply = aiReply ?? localCopilot(question, { counts, incidents });
    await db.$transaction([
      db.chatMessage.create({ data: { role: "user", content: question } }),
      db.chatMessage.create({ data: { role: "assistant", content: reply } }),
    ]);
    return NextResponse.json({ reply, mode: aiReply ? "llm" : "local" });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Chat failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/** DELETE /api/copilot/chat — clear history */
export async function DELETE() {
  try {
    await db.chatMessage.deleteMany({});
    return NextResponse.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to clear history";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
