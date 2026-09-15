import test from "node:test";
import assert from "node:assert/strict";
import { parseAndNormalize, normalizeBatch } from "../src/lib/normalizer";
import { scoreIncident, isLargeTransfer } from "../src/lib/scorer";
import { pairScore, type CorrAlert } from "../src/lib/correlator";
import { buildDemoFeeds } from "../src/lib/seed-data";
import { mitreById } from "../src/lib/mitre-data";
import { localCopilot, validateAnalysis, type IncidentAnalysisContext, type CopilotIncidentContext } from "../src/lib/llm";

const raw = (overrides: Record<string, unknown> = {}) => ({ alert_id: "TEST-1", source: "auth", timestamp: "2026-09-15T10:00:00Z", user: "employee", device: "host-1", ip: "10.0.0.2", event: "failed_login", description: "One failed login", raw_severity: "low", ...overrides });
const alert = (overrides: Record<string, unknown> = {}): CorrAlert => ({ id: "db-test", ...parseAndNormalize(JSON.stringify(raw(overrides)))[0] });

test("all five demo formats normalize to at least 25 alerts and three sources", () => {
  const feeds = buildDemoFeeds(new Date("2026-09-15T12:00:00Z"));
  const alerts = Object.values(feeds).flatMap((f) => parseAndNormalize(f));
  assert.ok(alerts.length >= 25);
  assert.ok(new Set(alerts.map((a) => a.source)).size >= 3);
  assert.equal(new Set(alerts.map((a) => a.alertId)).size, alerts.length);
  assert.ok(alerts.every((a) => a.timestamp <= new Date("2026-09-15T12:00:00Z")));
});
test("normalization retains extra metadata and extracts nested IOC evidence", () => {
  const a = alert({ metadata: { ticket: "CHG-1", iocs: { domains: ["updates-cdn.duckdns.org"] }, iocMatch: false } });
  assert.equal(a.metadata.ticket, "CHG-1");
  assert.equal(a.metadata.iocMatch, true);
  assert.ok(scoreIncident([a]).riskSignals.some((s) => s.points === 25));
});
test("caller cannot assert a malicious match with an untrusted boolean", () => {
  const a = alert({ metadata: { iocMatch: true } });
  assert.ok(!scoreIncident([a]).riskSignals.some((s) => s.points === 25));
});
test("malformed rows are reported while valid siblings survive", () => {
  const result = normalizeBatch(JSON.stringify([raw(), raw({ alert_id: "bad", timestamp: "oops" }), raw({ alert_id: "TEST-2" })]));
  assert.equal(result.alerts.length, 2); assert.equal(result.errors[0].row, 2);
});
test("required fields and IP ranges are validated", () => {
  for (const overrides of [{ source: null }, { event: null }, { alert_id: "" }, { ip: "999.1.1.1" }, { raw_severity: "weird" }]) assert.throws(() => alert(overrides));
});
test("zone-less timestamps use UTC", () => assert.equal(alert({ timestamp: "2026-09-15T10:00:00" }).timestamp.toISOString(), "2026-09-15T10:00:00.000Z"));
test("distinct intelligence reports do not collide", () => {
  const make = (body: string) => parseAndNormalize(`INTELLIGENCE REPORT\nPublished: 2026-09-15T10:00:00Z\nSUMMARY: ${body}`)[0].alertId;
  assert.notEqual(make("first report"), make("second report")); assert.equal(make("first report"), make("first report"));
});
test("CSV handles quoted commas and rejects unterminated quotes", () => {
  assert.equal(parseAndNormalize('C1,siem,2026-09-15T10:00:00Z,u,d,10.0.0.1,login,"hello, world",low', "csv")[0].description, "hello, world");
  assert.throws(() => parseAndNormalize('C1,siem,2026-09-15T10:00:00Z,u,d,10.0.0.1,login,"unterminated,low', "csv"));
});
test("sequence correlation needs shared entity evidence and respects 30 minutes", () => {
  const a = alert();
  assert.equal(pairScore(a, alert({ user: "other", device: "other", ip: "10.0.0.3", event: "successful_login" })), 0);
  assert.ok(pairScore(a, alert({ event: "successful_login", timestamp: "2026-09-15T10:29:00Z" })) >= 5);
  assert.equal(pairScore(a, alert({ timestamp: "2026-09-15T10:31:00Z" })), 0);
});
test("ordinary small downloads do not receive exfiltration points", () => {
  assert.equal(isLargeTransfer(alert({ event: "file_download", description: "0.2 GB downloaded" })), false);
  assert.equal(isLargeTransfer(alert({ event: "file_download", description: "4.2 GB downloaded" })), true);
});
test("internal suspicious execution is never dismissed as a password mistake", () => {
  const result = scoreIncident([alert({ event: "encoded_powershell", description: "Encoded PowerShell execution" })]);
  assert.equal(result.classification, "Genuine Threat"); assert.ok(result.confidence < 60);
});
test("three ordinary password mistakes are false positives with explanation", () => {
  const result = scoreIncident([alert({ description: "3 failed logins" })]);
  assert.equal(result.classification, "False Positive"); assert.match(result.explanation, /password mistakes/);
});
test("unauthorized does not match authorized and large bursts are not harmless", () => {
  assert.notEqual(scoreIncident([alert({ event: "network_activity", description: "unauthorized access" })]).classification, "False Positive");
  assert.notEqual(scoreIncident([alert({ description: "23 failed logins" })]).classification, "False Positive");
});
test("demo admin story scores Critical with valid MITRE and a complete BLUF", () => {
  const group = parseAndNormalize(buildDemoFeeds().siemJson).filter((a) => a.user === "admin");
  const result = scoreIncident(group); assert.equal(result.severity, "Critical"); assert.equal(result.threatScore, 100);
  assert.ok(result.mitre.length > 0 && result.mitre.every((t) => mitreById(t.id)?.name === t.name));
  assert.equal(result.bluf.split("\n").length, 7);
});
const ctx: IncidentAnalysisContext = { incidentId: "INC-1001", alerts: [{ ...alert(), timestamp: alert().timestamp.toISOString(), rawSeverity: "low" }], baseline: { ...scoreIncident([alert()]), bluf: "baseline" } };
const valid = () => ({ title: "Account activity", classification: "Genuine Threat", severity: "High", threat_score: 75, confidence: 65, explanation: "Investigate TEST-1.", evidence: ["TEST-1 login observed", "TEST-1 involves employee"], mitre_techniques: [{ id: "T1110", name: "Wrong model name" }], bluf: "BOTTOM LINE: Review this activity\nSEVERITY: High\nCONFIDENCE: 65%\nKEY EVIDENCE: TEST-1\nMITRE ATT&CK: T1110\nIMMEDIATE ACTION: Review logs\nNEXT INVESTIGATION: Verify account", recommended_actions: ["Review logs", "Verify account"] });
test("AI contract rejects partial JSON, unknown techniques, invented IPs and inconsistent severity", () => {
  assert.equal(validateAnalysis({}, ctx), null);
  assert.equal(validateAnalysis({ ...valid(), mitre_techniques: [{ id: "T9999", name: "fake" }] }, ctx), null);
  assert.equal(validateAnalysis({ ...valid(), explanation: "Contact 8.8.8.8" }, ctx), null);
  assert.equal(validateAnalysis({ ...valid(), severity: "Critical" }, ctx), null);
  assert.equal(validateAnalysis({ ...valid(), confidence: "65" }, ctx), null);
  assert.equal(validateAnalysis({ ...valid(), evidence: ["unbacked", "claim"] }, ctx), null);
  assert.equal(validateAnalysis(valid(), ctx)?.mitre[0].name, "Brute Force");
});
test("local Copilot references requested lower-ranked incident and refuses absent IDs", () => {
  const incidents: CopilotIncidentContext[] = Array.from({ length: 8 }, (_, i) => ({ incidentId: `INC-${1001+i}`, title: `Case ${i}`, severity: "Low", threatScore: 20, confidence: 40, classification: "Genuine Threat", status: "Open", alertCount: 1, keyEvents: [], blufExcerpt: "", evidence: ["TEST-1"], recommendedActions: ["Review logs"], alerts: [] }));
  assert.match(localCopilot("Brief me on INC-1008", { counts: {}, incidents }), /INC-1008/);
  assert.match(localCopilot("Why #9999?", { counts: {}, incidents }), /No stored incident/);
  assert.match(localCopilot("What first?", { counts: {}, incidents }), /Local SOC mode/);
  assert.match(localCopilot("hello how are you?", { counts: {}, incidents }), /Hello!/);
});


test("OpenAI-compatible transport sends structured schema and chat roles", async () => {
  const { completeChat } = await import("../src/lib/llm-client");
  const oldFetch = globalThis.fetch;
  const env = {
    AI_MODE: process.env.AI_MODE,
    AI_API_KEY: process.env.AI_API_KEY,
    AI_BASE_URL: process.env.AI_BASE_URL,
    AI_MODEL: process.env.AI_MODEL,
    AI_FALLBACK_MODELS: process.env.AI_FALLBACK_MODELS,
  };
  process.env.AI_MODE = "auto";
  process.env.AI_API_KEY = "test-key-not-a-real-credential";
  process.env.AI_BASE_URL = "https://api.groq.com/openai/v1";
  process.env.AI_MODEL = "openai/gpt-oss-20b";
  process.env.AI_FALLBACK_MODELS = "";
  globalThis.fetch = (async (url: string | URL | Request, options?: RequestInit) => {
    assert.equal(String(url), "https://api.groq.com/openai/v1/chat/completions");
    assert.equal((options?.headers as Record<string, string>).Authorization, "Bearer test-key-not-a-real-credential");
    assert.ok(options?.signal);
    const body = JSON.parse(String(options?.body));
    assert.equal(body.messages[0].role, "system");
    assert.equal(body.messages[1].role, "assistant");
    assert.equal(body.response_format.type, "json_schema");
    assert.equal(body.response_format.json_schema.schema.type, "object");
    return Response.json({ choices: [{ finish_reason: "stop", message: { content: '{"ok":true}' } }] });
  }) as typeof fetch;
  try {
    assert.equal(await completeChat([{ role: "system", content: "system" }, { role: "assistant", content: "prior" }, { role: "user", content: "question" }], true, { type: "object" }), '{"ok":true}');
    globalThis.fetch = (async () => Response.json({ error: "quota" }, { status: 429 })) as typeof fetch;
    await assert.rejects(() => completeChat([{ role: "user", content: "hello" }]), /HTTP 429/);
    globalThis.fetch = (async () => Response.json({ choices: [{ finish_reason: "length", message: { content: "partial" } }] })) as typeof fetch;
    await assert.rejects(() => completeChat([{ role: "user", content: "hello" }]), /incomplete/);
  } finally {
    globalThis.fetch = oldFetch;
    for (const [key, value] of Object.entries(env)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});

test("OpenAI-compatible transport falls back after a rate limit", async () => {
  const { completeChat } = await import("../src/lib/llm-client");
  const oldFetch = globalThis.fetch;
  const env = {
    AI_MODE: process.env.AI_MODE,
    AI_API_KEY: process.env.AI_API_KEY,
    AI_BASE_URL: process.env.AI_BASE_URL,
    AI_MODEL: process.env.AI_MODEL,
    AI_FALLBACK_MODELS: process.env.AI_FALLBACK_MODELS,
  };
  process.env.AI_MODE = "auto";
  process.env.AI_API_KEY = "test-key-not-a-real-credential";
  process.env.AI_BASE_URL = "https://api.groq.com/openai/v1";
  process.env.AI_MODEL = "openai/gpt-oss-20b";
  process.env.AI_FALLBACK_MODELS = "qwen/qwen3.8-27b,openai/gpt-oss-120b";
  const attemptedModels: string[] = [];
  globalThis.fetch = (async (_url: string | URL | Request, options?: RequestInit) => {
    const model = JSON.parse(String(options?.body)).model;
    attemptedModels.push(model);
    if (attemptedModels.length === 1) return Response.json({ error: "rate limit" }, { status: 429 });
    return Response.json({ choices: [{ finish_reason: "stop", message: { content: "fallback worked" } }] });
  }) as typeof fetch;
  try {
    assert.equal(await completeChat([{ role: "user", content: "hello" }]), "fallback worked");
    assert.deepEqual(attemptedModels, ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"]);
  } finally {
    globalThis.fetch = oldFetch;
    for (const [key, value] of Object.entries(env)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});


test("manual false-positive verdict updates the briefing and action", async () => {
  const { reviewedBluf, analystActions } = await import("../src/lib/analyst-verdict");
  const report = reviewedBluf("BOTTOM LINE: Suspicious compromise\nIMMEDIATE ACTION: Disable account", "False Positive");
  assert.match(report, /analyst classified this incident as a false positive/);
  assert.doesNotMatch(report, /Disable account/);
  assert.match(analystActions("False Positive")[0], /confirmed benign/);
});
