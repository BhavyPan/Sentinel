import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getDashboardSummary } from "@/lib/summary";
import { copilotChat, type CopilotIncidentContext } from "@/lib/llm";

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
    const body = (await req.json()) as { message?: unknown } | null;
    const question = typeof body?.message === "string" ? body.message.trim() : "";
    if (!question) {
      return NextResponse.json({ error: "Missing 'message'" }, { status: 400 });
    }

    await db.chatMessage.create({ data: { role: "user", content: question } });

    const summary = await getDashboardSummary();
    const topWithAlerts = await db.incident.findMany({
      where: {
        id: { in: summary.topIncidents.map((i) => i.id) },
      },
      include: { alerts: true },
    });
    const eventsById = new Map<string, string[]>();
    for (const inc of topWithAlerts) {
      eventsById.set(
        inc.incidentId,
        [...new Set(inc.alerts.map((a) => a.event))].slice(0, 5)
      );
    }
    const incidents: CopilotIncidentContext[] = summary.topIncidents.slice(0, 8).map((i) => ({
      incidentId: i.incidentId,
      title: i.title,
      severity: i.severity,
      threatScore: i.threatScore,
      confidence: i.confidence,
      classification: i.classification,
      alertCount: i.alertCount,
      keyEvents: eventsById.get(i.incidentId) ?? [],
      blufExcerpt: (i.bluf ?? "").slice(0, 160),
    }));

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

    const reply = await copilotChat(question, { counts, incidents }, history);
    if (!reply) {
      return NextResponse.json(
        { error: "AI service unavailable — try again shortly" },
        { status: 502 }
      );
    }

    await db.chatMessage.create({ data: { role: "assistant", content: reply } });
    return NextResponse.json({ reply });
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
