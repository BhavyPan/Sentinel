/**
 * SentinelAI LLM service (backend only) — z-ai-web-dev-sdk.
 * Never throws: callers fall back to deterministic values on any failure.
 */
import ZAI from "z-ai-web-dev-sdk";
import { MITRE_TECHNIQUES, mitreById } from "./mitre-data";
import type { MitreTechnique } from "./types";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "False Positive"] as const;
const CLASSIFICATIONS = ["Genuine Threat", "False Positive"] as const;

export interface LlmAlertContext {
  alertId: string;
  source: string;
  timestamp: string;
  user?: string | null;
  device?: string | null;
  ip?: string | null;
  event: string;
  description: string;
  rawSeverity: string;
}

export interface LlmBaseline {
  title: string;
  classification: string;
  severity: string;
  threatScore: number;
  confidence: number;
  evidence: string[];
  mitre: MitreTechnique[];
  bluf: string | null;
}

export interface IncidentAnalysisContext {
  incidentId: string;
  baseline: LlmBaseline;
  alerts: LlmAlertContext[];
}

export interface LlmAnalysisResult {
  title: string;
  classification: string;
  severity: string;
  threatScore: number;
  confidence: number;
  explanation: string;
  evidence: string[];
  mitre: MitreTechnique[];
  bluf: string;
  recommendedActions: string[];
}

const ANALYSIS_SYSTEM_PROMPT = `You are a senior cyber threat analyst working a security operations center incident queue.
You will receive one correlated incident: its alerts (already normalized), a deterministic baseline assessment, and a curated MITRE ATT&CK technique list.

Respond with STRICT JSON ONLY — no markdown fences, no prose before or after. Exact fields:
{
  "title": string (<=80 chars, incident name),
  "classification": "Genuine Threat" | "False Positive",
  "severity": "Critical" | "High" | "Medium" | "Low" | "False Positive",
  "threat_score": integer 0-100,
  "confidence": integer 0-100,
  "explanation": string (2-4 sentences),
  "evidence": string[] (2-4 short strings citing concrete alerts by ID),
  "mitre_techniques": [{"id": string, "name": string}] (ONLY ids from the supplied list),
  "bluf": string (must follow this template with line breaks:
    "BOTTOM LINE: [one-sentence conclusion]\\nSEVERITY: [level]\\nCONFIDENCE: [0-100%]\\nKEY EVIDENCE: [2-4 short points]\\nMITRE ATT&CK: [technique IDs + names]\\nIMMEDIATE ACTION: [first recommended response]\\nNEXT INVESTIGATION: [what analyst should check next]"),
  "recommended_actions": string[] (2-4 short imperative strings)
}

Rules:
- Use ONLY the supplied alert data. Never invent IPs, users, devices, hashes or events that are not present.
- If evidence is weak, say so in the explanation and LOWER the confidence.
- If the activity matches approved/scheduled/routine patterns, classify it as False Positive.
- mitre_techniques ids MUST be picked from the supplied curated list.`;

function extractJson(content: string): unknown | null {
  let text = (content || "").trim();
  text = text.replace(/```(?:json)?/gi, "");
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1)) as unknown;
  } catch {
    return null;
  }
}

function asStringArray(v: unknown, max: number): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x): x is string => typeof x === "string" && x.trim().length > 0)
    .map((x) => x.trim())
    .slice(0, max);
}

function clampScore(v: unknown, fallback: number): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/**
 * Ask the LLM to analyze one incident. Returns validated fields or null
 * (caller then keeps the deterministic baseline). Retries once on parse failure.
 */
export async function analyzeIncidentWithLLM(
  ctx: IncidentAnalysisContext
): Promise<LlmAnalysisResult | null> {
  const mitreList = MITRE_TECHNIQUES.map((t) => `${t.id} ${t.name}`).join("; ");
  const userPayload = {
    incident_id: ctx.incidentId,
    deterministic_baseline: {
      title: ctx.baseline.title,
      classification: ctx.baseline.classification,
      severity: ctx.baseline.severity,
      threat_score: ctx.baseline.threatScore,
      confidence: ctx.baseline.confidence,
      mitre: ctx.baseline.mitre.map((m) => m.id),
    },
    alerts: ctx.alerts,
    curated_mitre_list: mitreList,
  };

  const messages = [
    { role: "system" as const, content: ANALYSIS_SYSTEM_PROMPT },
    {
      role: "user" as const,
      content: `Analyze this incident.\n${JSON.stringify(userPayload)}`,
    },
  ];

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const zai = await ZAI.create();
      const res = await zai.chat.completions.create({
        messages:
          attempt === 0
            ? messages
            : [
                ...messages,
                {
                  role: "user" as const,
                  content:
                    "Your previous reply was not parseable JSON. Respond again with STRICT JSON ONLY — a single JSON object, no markdown fences, no extra text.",
                },
              ],
        thinking: { type: "disabled" },
      });
      const content =
        (res as { choices?: { message?: { content?: string } }[] })?.choices?.[0]?.message
          ?.content ?? "";
      const parsed = extractJson(content);
      if (!parsed || typeof parsed !== "object") continue;
      const obj = parsed as Record<string, unknown>;

      const title = typeof obj.title === "string" && obj.title.trim() ? obj.title.trim().slice(0, 80) : ctx.baseline.title;
      const classification =
        typeof obj.classification === "string" &&
        (CLASSIFICATIONS as readonly string[]).includes(obj.classification)
          ? obj.classification
          : ctx.baseline.classification;
      const severity =
        typeof obj.severity === "string" && (SEVERITIES as readonly string[]).includes(obj.severity)
          ? obj.severity
          : ctx.baseline.severity;
      const explanation = typeof obj.explanation === "string" && obj.explanation.trim() ? obj.explanation.trim() : "";
      const evidence = asStringArray(obj.evidence, 4);
      const recommendedActions = asStringArray(obj.recommended_actions, 4);
      const bluf = typeof obj.bluf === "string" && obj.bluf.trim() ? obj.bluf.trim() : ctx.baseline.bluf || "";
      const mitreRaw = Array.isArray(obj.mitre_techniques) ? obj.mitre_techniques : [];
      const mitre: MitreTechnique[] = [];
      for (const t of mitreRaw) {
        if (typeof t === "object" && t !== null && "id" in t) {
          const known = mitreById(String((t as { id: unknown }).id));
          if (known && !mitre.some((m) => m.id === known.id)) {
            mitre.push({ id: known.id, name: known.name, tactic: known.tactic });
          }
        }
        if (mitre.length >= 4) break;
      }

      return {
        title,
        classification,
        severity,
        threatScore: clampScore(obj.threat_score, ctx.baseline.threatScore),
        confidence: clampScore(obj.confidence, ctx.baseline.confidence),
        explanation,
        evidence: evidence.length ? evidence : ctx.baseline.evidence,
        mitre: mitre.length ? mitre : ctx.baseline.mitre,
        bluf,
        recommendedActions: recommendedActions.length ? recommendedActions : [],
      };
    } catch {
      // network/SDK error — retry once, then give up
    }
  }
  return null;
}

// ---------------------------------------------------------------- Copilot

export interface CopilotIncidentContext {
  incidentId: string;
  title: string;
  severity: string;
  threatScore: number;
  confidence: number;
  classification: string;
  alertCount: number;
  keyEvents: string[];
  blufExcerpt: string;
}

export interface CopilotContextData {
  counts: Record<string, number | string | null>;
  incidents: CopilotIncidentContext[];
}

const COPILOT_SYSTEM_PROMPT = `You are SentinelAI Copilot, an AI assistant for a security operations commander.
Rules:
- Answer ONLY from the incidents and alerts supplied in the context. Never invent an alert, IP, user, or event that is not in the supplied data.
- Always mention the incident ID (e.g. INC-1001) when discussing a specific incident.
- Keep commander answers short (<=120 words) unless the user explicitly asks for more depth.
- If the available evidence is weak, say confidence is low instead of pretending certainty.`;

export async function copilotChat(
  question: string,
  contextData: CopilotContextData,
  history: { role: "user" | "assistant"; content: string }[]
): Promise<string | null> {
  const context = {
    dashboard_counts: contextData.counts,
    top_incidents: contextData.incidents,
  };
  const historyText =
    history.length > 0
      ? history
          .slice(-6)
          .map((m) => `${m.role === "user" ? "Commander" : "Copilot"}: ${m.content}`)
          .join("\n")
      : "(no prior messages)";

  try {
    const zai = await ZAI.create();
    const res = await zai.chat.completions.create({
      messages: [
        { role: "system", content: COPILOT_SYSTEM_PROMPT },
        {
          role: "user",
          content: `CURRENT DATA SNAPSHOT:\n${JSON.stringify(context)}\n\nRECENT CONVERSATION:\n${historyText}\n\nCommander question: ${question}\n\nAnswer strictly from the snapshot.`,
        },
      ],
      thinking: { type: "disabled" },
    });
    const content =
      (res as { choices?: { message?: { content?: string } }[] })?.choices?.[0]?.message?.content ??
      "";
    const text = typeof content === "string" ? content.trim() : "";
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}
