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
  /** triage: analyst has reviewed this alert */
  acknowledged: boolean;
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

/** Case-activity audit entry (who did what, when) */
export interface IncidentEventDTO {
  id: string;
  kind: "status" | "classification" | "note" | "analysis" | "created" | "correlation";
  actor: string;
  detail: string;
  createdAt: string;
}

/** Incident detail = list view + full related alerts */
export interface IncidentDetailDTO extends IncidentDTO {
  alerts: AlertDTO[]; // sorted by timestamp ascending (attack timeline)
  /** case activity, newest first (capped) */
  events: IncidentEventDTO[];
}

/** GET /api/watchlist → response */
export interface WatchlistItemDTO {
  id: string;
  type: "ip" | "domain" | "hash";
  value: string;
  note: string;
  createdAt: string;
  /** number of stored alerts referencing this IOC (ip column or metadata/description text) */
  hits: number;
}

export interface WatchlistHitStats {
  itemCount: number;
  totalHits: number;
  itemsWithHits: number;
  lastAddedAt: string | null;
}

export interface WatchlistListResult {
  items: WatchlistItemDTO[];
  stats?: WatchlistHitStats;
}

/** POST /api/watchlist/bulk → response */
export interface WatchlistBulkResult {
  added: number;
  duplicatesCount: number;
  duplicates: { line: number; reason: string }[];
  items: WatchlistItemDTO[];
  message: string;
}

/** POST /api/watchlist + DELETE /api/watchlist/[id] → response */
export interface WatchlistResult {
  item?: WatchlistItemDTO;
  removed?: string;
  message: string;
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
    /** alerts not yet acknowledged by an analyst */
    unacknowledgedAlerts: number;
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
  mode: "llm" | "local";
}

/** POST /api/alerts/import body */
export interface ImportPayload {
  raw?: string; // raw text: JSON array/object, CSV, or free text
  format?: "auto" | "json" | "csv" | "text";
}

/** POST /api/alerts/import → response */
export interface ImportResult {
  errors?: { row: number; message: string }[];
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

/** PATCH /api/alerts/[id] body — triage acknowledgement */
export interface AlertUpdatePayload {
  acknowledged?: boolean;
}

/** PATCH /api/alerts/[id] → response */
export interface AlertUpdateResult {
  alert: AlertDTO;
  message: string;
}

/** PATCH /api/incidents/[id] body — analyst feedback */
export interface IncidentUpdatePayload {
  status?: IncidentStatus;
  classification?: Classification;
  analystNote?: string;
  /** display name recorded with the note (audit trail); defaults to "Analyst" */
  analyst?: string;
}

/** POST /api/alerts/bulk-ack body — bulk triage */
export interface BulkAckPayload {
  ids: string[]; // db cuids or alertIds
  acknowledged: boolean;
}

/** POST /api/alerts/bulk-ack → response */
export interface BulkAckResult {
  updated: number;
  requested: number;
  alerts: AlertDTO[];
  message: string;
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
  /** how many of the entity's alerts live inside the target incident */
  alertCount: number;
  /** up to 3 example alert ids backing this relationship (evidence) */
  sampleAlertIds: string[];
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
