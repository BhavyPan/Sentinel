import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { toIncidentDetailDTO } from "@/lib/summary";
import type { Classification, IncidentStatus, IncidentUpdatePayload } from "@/lib/types";

export const dynamic = "force-dynamic";

const STATUSES: IncidentStatus[] = ["Open", "Investigating", "Contained", "Resolved"];
const CLASSIFICATIONS: Classification[] = ["Genuine Threat", "False Positive", "Under Review"];

/** Record a case-activity event (best effort — audit must never break the request) */
async function recordEvent(incidentDbId: string, kind: string, actor: string, detail: string) {
  try {
    await db.incidentEvent.create({
      data: { incidentId: incidentDbId, kind, actor: actor || "Analyst", detail },
    });
  } catch {
    // audit trail is best-effort
  }
}

async function findIncident(idOrIncidentId: string) {
  return db.incident.findFirst({
    where: { OR: [{ id: idOrIncidentId }, { incidentId: idOrIncidentId }] },
    include: {
      alerts: { orderBy: { timestamp: "asc" } },
      events: { orderBy: { createdAt: "desc" }, take: 15 },
    },
  });
}

/** GET /api/incidents/[id] — detail by cuid or INC-XXXX */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const incident = await findIncident(id);
    if (!incident) {
      return NextResponse.json({ error: `Incident ${id} not found` }, { status: 404 });
    }
    return NextResponse.json({ incident: toIncidentDetailDTO(incident) });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to load incident";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/** PATCH /api/incidents/[id] — analyst feedback: status, classification, note */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const body = (await req.json()) as IncidentUpdatePayload | null;
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
    }

    const data: {
      status?: string;
      classification?: string;
      explanation?: string;
    } = {};

    if (body.status !== undefined) {
      if (!STATUSES.includes(body.status)) {
        return NextResponse.json(
          { error: `Invalid status. Allowed: ${STATUSES.join(", ")}` },
          { status: 400 }
        );
      }
      data.status = body.status;
    }

    if (body.classification !== undefined) {
      if (!CLASSIFICATIONS.includes(body.classification)) {
        return NextResponse.json(
          { error: `Invalid classification. Allowed: ${CLASSIFICATIONS.join(", ")}` },
          { status: 400 }
        );
      }
      data.classification = body.classification;
    }

    const existing = await findIncident(id);
    if (!existing) {
      return NextResponse.json({ error: `Incident ${id} not found` }, { status: 404 });
    }

    const actor = String(body.analyst ?? "").trim() || "Analyst";

    if (body.analystNote !== undefined) {
      const note = String(body.analystNote).trim();
      if (!note) {
        return NextResponse.json({ error: "analystNote cannot be empty" }, { status: 400 });
      }
      const who = actor;
      const stamp = new Date().toISOString().slice(0, 16).replace("T", " ") + "Z";
      const entry = `[${who} · ${stamp}] ${note}`;
      data.explanation = existing.explanation
        ? `${existing.explanation}\n\n${entry}`
        : entry;
    }

    if (Object.keys(data).length === 0) {
      return NextResponse.json({ incident: toIncidentDetailDTO(existing) });
    }

    await db.incident.update({ where: { id: existing.id }, data });

    // audit trail entries (best effort)
    if (data.classification !== undefined && data.classification !== existing.classification) {
      await recordEvent(existing.id, "classification", actor, `Classification set to ${data.classification}`);
    }
    if (data.status !== undefined && data.status !== existing.status) {
      await recordEvent(existing.id, "status", actor, `Status changed ${existing.status} → ${data.status}`);
    }
    if (data.explanation !== undefined) {
      const noteOnly = String(body.analystNote ?? "").trim();
      await recordEvent(existing.id, "note", actor, `Note added: "${noteOnly.slice(0, 120)}${noteOnly.length > 120 ? "…" : ""}"`);
    }

    const updated = await findIncident(id);
    return NextResponse.json({ incident: updated ? toIncidentDetailDTO(updated) : null });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to update incident";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
