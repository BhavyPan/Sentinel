// ============================================================
// SentinelAI — Shared API Contract (binding for backend & frontend)
// ============================================================

export type Severity = "Critical" | "High" | "Medium" | "Low" | "False Positive";
export type Classification = "Genuine Threat" | "False Positive" | "Under Review";
export type IncidentStatus = "Open" | "Investigating" | "Contained" | "Resolved";

export interface MitreTechnique {
  id: string; // e.g. "T1110"
  name: string; // e.g. "Brute Force"
  tactic: string; // e.g. "Credential Access"
}

export interface RiskSignal {
  signal: string;
  points: number;
}

/** Normalized alert object (F2) */
export interface AlertDTO {
  id: string; // db cuid
  alertId: string; // e.g. "A1042"
  source: string; // machine key: "siem" | "firewall" | ...
  sourceLabel: string; // display: "Firewall"
  timestamp: string; // ISO string
  user: string | null;
  device: string | null;
  ip: string | null;
  event: string; // e.g. "multiple_failed_logins"
  description: string;
  rawSeverity: string; // "low" | "medium" | "high" | "critical" | "info"
  rawFormat: string; // "json" | "csv" | "text"
  metadata: Record<string, unknown>;
  incidentId: string | null; // db id of parent incident
  /** populated in feed views: whether this alert is part of a correlated incident */
  correlated?: boolean;
}

/** Incident object (F3..F9) — list view */
export interface IncidentDTO {
  id: string; // db cuid
  incidentId: string; // e.g. "INC-1001"
  title: string;
  classification: Classification;
  severity: Severity;
  threatScore: number; // 0..100 deterministic
  confidence: number; // 0..100
  mitre: MitreTechnique[];
  bluf: string | null;
  explanation: string | null;
  evidence: string[];
  recommendedActions: string[];
  status: IncidentStatus;
  analyzed: boolean;
  riskSignals: RiskSignal[];
  alertCount: number;
  sources: string[]; // distinct source labels in this incident
  createdAt: string;
  updatedAt: string;
}

/** Incident detail = list view + full related alerts */
export interface IncidentDetailDTO extends IncidentDTO {
  alerts: AlertDTO[]; // sorted by timestamp ascending (attack timeline)
}

/** GET /api/dashboard/summary */
export interface DashboardSummary {
  totalAlerts: number;
  correlatedAlerts: number;
  uncorrelatedAlerts: number;
  totalIncidents: number;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    falsePositive: number;
    genuineThreats: number;
    analyzed: number;
    open: number;
  };
  alertsBySeverity: { severity: string; count: number }[];
  alertsBySource: { source: string; sourceLabel: string; count: number }[];
  alertsByHour: { hour: string; count: number }[]; // "HH:00"
  topIncidents: IncidentDTO[]; // top 5 by priority
  lastUpdated: string | null; // ISO of newest alert
}

/** GET /api/incidents/correlate → response */
export interface CorrelateResult {
  incidentsBefore: number;
  incidentsAfter: number;
  alertsGrouped: number;
  alertsUngrouped: number;
  summary: DashboardSummary;
}

/** POST /api/incidents/[id]/analyze → response */
export interface AnalyzeResult {
  incident: IncidentDetailDTO;
  llmUsed: boolean;
  message: string;
}

/** POST /api/copilot/chat → response */
export interface CopilotChatResult {
  reply: string;
}

/** POST /api/alerts/import body */
export interface ImportPayload {
  raw?: string; // raw text: JSON array/object, CSV, or free text
  format?: "auto" | "json" | "csv" | "text";
}

/** POST /api/alerts/import → response */
export interface ImportResult {
  imported: number;
  failed: number;
  alerts: AlertDTO[];
  message: string;
}

/** POST /api/alerts/seed → response */
export interface SeedResult {
  seeded: number;
  correlated: number;
  incidents: number;
  message: string;
}

/** PATCH /api/incidents/[id] body — analyst feedback */
export interface IncidentUpdatePayload {
  status?: IncidentStatus;
  classification?: Classification;
  analystNote?: string;
}

/** GET /api/copilot/chat → response */
export interface ChatHistory {
  messages: { id: string; role: "user" | "assistant"; content: string; createdAt: string }[];
}

// ============================================================
// Threat Graph (entity / attack-cluster view)
// ============================================================

export type GraphEntityType = "user" | "device" | "ip";

/** GET /api/graph → node. Incident nodes sit in the inner ring, entities in the outer ring. */
export interface GraphNode {
  /** "inc:<dbId>" or "ent:<type>:<value>" */
  id: string;
  kind: "incident" | "entity";
  /** entity nodes only */
  entityType?: GraphEntityType;
  /** display text: "INC-1001", "admin", "server-01", "203.0.113.66" */
  label: string;
  /** secondary line under the label */
  sublabel: string;
  /** incident: own severity · entity: worst connected incident severity */
  severity: Severity | "Info";
  /** incident nodes: threat score · entity nodes: connected incident count */
  weight: number;
  /** alerts touching this node */
  alertCount: number;
  /** incidents this node participates in (db ids) — for navigation */
  incidentDbIds: string[];
  /** incident nodes only */
  classification?: Classification;
  /** ip entities only */
  internal?: boolean;
  /** ip entities only: value appears in MALICIOUS_IPS intel list */
  malicious?: boolean;
}

export interface GraphLink {
  source: string; // node id
  target: string; // node id
  severity: Severity; // edge color source (incident severity)
  incidentDbId: string; // for click-through
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  stats: {
    entityCount: number;
    incidentCount: number;
    linkCount: number;
    unlinkedAlerts: number;
  };
  generatedAt: string;
}
