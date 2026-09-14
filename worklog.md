# SentinelAI — Worklog (D2: Threat Intelligence Correlation & Alert Prioritisation Assistant)

Project: Next.js 16 + TypeScript + Tailwind 4 + shadcn/ui + Prisma (SQLite) + z-ai-web-dev-sdk (backend LLM).
Goal: Build the D2 hackathon MVP "SentinelAI" — ingest multi-source alerts, normalize, correlate into incidents, classify genuine threats vs false positives, prioritize, map MITRE ATT&CK, generate BLUF summaries, AI Copilot. Four screens in a single page route: Command Center, Threat Feed, Incident Analysis, AI Copilot.

---
Task ID: 1
Agent: Z.ai Code (main)
Task: Foundation setup — worklog, Prisma schema, db push, shared types, MITRE data, IOC lists, seed demo dataset.

Work Log:
- Reviewed project scaffold (Next.js 16 App Router, shadcn/ui present, Prisma + SQLite at db/custom.db, z-ai-web-dev-sdk installed).
- Rewrote prisma/schema.prisma with Alert, Incident, ChatMessage models.
- Pushed schema to SQLite via `bun run db:push`.
- Defined shared TypeScript API contract in src/lib/types.ts (AlertDTO, IncidentDTO, dashboard summary shapes) — this is the binding contract for backend (Task 2-a) and frontend (Task 2-b) agents.
- Curated local MITRE ATT&CK technique list in src/lib/mitre-data.ts (~35 techniques with id/name/tactic).
- Created threat intel IOC lists in src/lib/threat-intel.ts (malicious IPs/domains/hashes, privileged account names, internal IP ranges, FP keywords).
- Created demo dataset in src/lib/seed-data.ts: multi-format raw feeds (SIEM JSON, cyber-sensor CSV, satellite text, intel report text) — 30+ alerts covering 4 genuine incident stories + 2-3 false-positive stories + background noise.

Stage Summary:
- Database schema: Alert (normalized alert), Incident (correlated, scored, analyzed), ChatMessage (copilot history).
- API contract fixed in src/lib/types.ts; all agents must conform to it.
- Demo data tells stories: A) admin brute-force→login→4.2GB download (Critical), B) encoded PowerShell→C2 beacon (High), C) two devices contact known botnet IP (High), D) DMZ port scan (Low/Medium); FP) employee 3 wrong passwords, approved vuln scanner, routine satellite telemetry.

---
Task ID: 2-b
Agent: full-stack-developer (frontend)
Task: Dark cyber SOC theme + 4 screens (Command Center, Threat Feed, Incident Analysis, AI Copilot)

Work Log:
- Overrode the `.dark` token block in globals.css with a deep slate/graphite scheme (oklch(0.13 0.012 240) bg, card 0.168, borders white/8%, emerald oklch(0.72 0.149 163) as primary/ring, chart ramp = severity ramp). Added CSS-only ambient background (radial emerald glow + fine grid with radial mask), header scanline shimmer keyframes, thin styled scrollbars (`.soc-scroll`), and copilot typing-dot animation. `<html className="dark">` set in layout.tsx (always-dark, no next-themes switching).
- Rewrote layout.tsx: SentinelAI metadata, Geist Sans/Mono variables kept, ambient bg layer, Providers wrapper.
- Created src/components/providers.tsx ("use client"): QueryClientProvider (staleTime 10s, retry 1, no refetchOnWindowFocus) + Sonner Toaster (theme dark, bottom-right).
- Created src/lib/ui-helpers.ts (frontend-owned): SEVERITY_STYLES / rawSeverityLabel / scoreHex / scoreTextClass (Critical=red-500, High=amber-500, Medium=yellow-400, Low=emerald-400, FP=slate-500), CLASSIFICATION_STYLES, STATUS_STYLES (Open=red, Investigating=amber, Contained=emerald, Resolved=slate), SOURCE_ICONS map (siem→Server, firewall→BrickWall, edr→Shield, ids→Radar, satellite→Satellite, intel-report→FileText, …), timeAgo/formatTime/formatDateTime (date-fns), unwrapList<T> defensive narrowing for list endpoints (bare array or {alerts}/{incidents} envelope).
- Created src/lib/api-client.ts: apiGet/apiSend with relative URLs only, ApiError carrying server `{error}` message.
- Created stores: src/store/soc-store.ts (activeTab, selectedIncidentId, openIncident → sets incident + switches to Analysis tab; askQuestion → copilot store + Copilot tab) and src/store/copilot-store.ts (pendingQuestion + nonce for auto-send).
- Shared components (src/components/soc/): badges.tsx (SeverityBadge, RawSeverityBadge, ClassificationBadge, StatusBadge, SourceChip via createElement to satisfy react-hooks/static-components, EventChip, CorrelationChip clickable → incident), threat-score.tsx (ThreatScoreBar with framer-motion animated width; ScoreGauge radial SVG with strokeDashoffset animation), seed-button.tsx (POST /api/alerts/seed, rotating status lines "Ingesting SIEM batch… / Parsing CSV sensor export… / Correlating alerts… / Scoring threats…", invalidates all queries, success toast, jumps to Command Center), empty-hero.tsx (big shield, pipeline copy, DEMO_FEED_LABELS chips), header.tsx (sticky, ShieldCheck wordmark + tagline, per-second mono clock with suppressHydrationWarning, pulsing SYSTEM ONLINE badge, compact seed action), footer.tsx (sticky via mt-auto, safe-area pb env(safe-area-inset-bottom), demo disclaimer + MITRE attribution), error-state.tsx (retry).
- Tab 1 Command Center (tabs/command-center.tsx): GET /api/dashboard/summary (refetchInterval 15s). 6 KPI cards (Total Alerts/Active Incidents/Critical/High/Medium/False Positives) with colored left borders + big mono numbers, 2→3→6-col responsive. Recharts severity donut with center total + legend; hourly AreaChart (emerald gradient); CSS-bar Alerts-by-Source list. Ranked incident table (max-h-520 soc-scroll, sticky header): P1–P4 priority badge, incident id mono, title, severity badge, animated ThreatScoreBar, confidence, alert count, status badge, Sparkles when analyzed; row click/Enter → openIncident. xl-only AI Copilot mini panel with 3 quick-question buttons that auto-send via copilot store. Empty summary → EmptyHero; error → retry; skeletons while loading.
- Tab 2 Threat Feed (tabs/threat-feed.tsx): toolbar with 300ms-debounced search, source Select (options from summary alertsBySource), severity Select, correlated-only Switch, refresh button, Load Demo button; GET /api/alerts?search&source&severity&correlated keyed by filters. Feed table (max-h-620): timeAgo + exact on hover, mono alert id, SourceChip, stacked user/device/ip mono, EventChip, truncated description w/ tooltip, RawSeverityBadge, Correlated chip showing INC-XXXX (db id mapped via /api/incidents) that jumps to Analysis, or Unassigned slate chip. Collapsible Import panel: format Select (auto/json/csv/text), mono textarea, POST /api/alerts/import → toast "Imported N alerts · M failed", hint listing the 5 demo feed types.
- Tab 3 Incident Analysis (tabs/incident-analysis.tsx): two-pane lg+ (w-80 ranked list: severity dot, INC id, title, score; horizontal scroll strip on mobile) + detail pane fed by GET /api/incidents/[id]. Detail header: severity/classification/status badges, mono id, title, meta line; actions = Run AI Analysis (POST /api/incidents/[id]/analyze, 2.5s-rotating status lines incl. "Consulting threat analyst model…", success toast + invalidation), status workflow Select → PATCH, Confirm Threat / Mark False Positive (PATCH classification) / Dismiss (no-op). Score panel: radial ScoreGauge + confidence bar + riskSignals chips (+points colored by weight). Attack timeline: vertical connector, severity-colored dots, mono time, SourceChip, EventChip, description, user/device/ip, alert id. MITRE panel: T-id·name chips with tactic subtext or "No techniques mapped yet — run AI analysis". BLUF briefing card: emerald header strip "BLUF — BOTTOM LINE UP FRONT", pre-wrap mono text, numbered Recommended Actions, Crosshair evidence bullets. Amber ribbon when !analyzed.
- Tab 4 AI Copilot (tabs/ai-copilot.tsx): GET/POST/DELETE /api/copilot/chat; history + local session messages; user bubbles emerald right, assistant card left with Bot avatar, whitespace-pre-wrap (no markdown renderer); quick-question chips above input (first derives top incident id from summary); auto-send on copilot-store nonce change; three-dot typing indicator; Enter to send / Shift+Enter newline; two-step Confirm Clear; 502-aware error toast.
- page.tsx: single route, min-h-screen flex col, SocHeader + controlled shadcn Tabs (segmented control w/ icons, emerald active state incl. dark:-prefixed overrides) + SocFooter.
- Verified: `bun run lint` clean; `bunx tsc --noEmit` clean for all src files EXCEPT backend-owned src/lib/normalizer.ts (see note); dev.log shows GET / 200; curl of /api/dashboard/summary still 404/HTML because backend (Task 2-a) is mid-flight — frontend handles with skeletons/error-retry states.
- Note for backend (2-a): `bunx tsc --noEmit` currently fails in src/lib/normalizer.ts line 277 — named capturing groups in regex require TS target ≥ ES2018; tsconfig target is ES2017 (examples/ + skills/ scaffold dirs also have pre-existing tsc errors, outside both agents' scope). Did not touch the file per ownership rules.

Stage Summary:
- Files created: src/components/providers.tsx, src/lib/ui-helpers.ts, src/lib/api-client.ts, src/store/soc-store.ts, src/store/copilot-store.ts, src/components/soc/{badges,threat-score,seed-button,empty-hero,header,footer,error-state}.tsx, src/components/soc/tabs/{command-center,threat-feed,incident-analysis,ai-copilot}.tsx.
- Files modified: src/app/layout.tsx (dark class, Providers, metadata), src/app/globals.css (SOC theme), src/app/page.tsx (full SOC shell).
- Design decisions: emerald-only accent (no indigo/violet), severity color system centralized in ui-helpers and used in every badge/chart/timeline dot, framer-motion used sparingly (fade/slide on mount/tab switch, animated score bars/gauges/bars), mono font for all IDs/IPs/timestamps/scores, all fetches relative with defensive contract narrowing, every async region has skeleton + error-retry + empty state, touch targets ≥44px, tables scroll horizontally/vertically with styled scrollbars, footer respects safe-area.
- Cross-tab navigation: zustand soc-store owns activeTab + selectedIncidentId — incident row (Command Center) → openIncident(dbId) → Analysis tab with detail loaded; feed "Correlated → INC-XXXX" chip → same; Command Center mini-copilot / soc-store.askQuestion pushes pendingQuestion into copilot-store and switches to Copilot tab where the nonce watcher auto-sends.

---
Task ID: 2-a
Agent: full-stack-developer (backend)
Task: Normalizer, correlator, scorer, LLM service, all API routes

Work Log:
- Read Task-1 contracts (types.ts, seed-data.ts, mitre-data.ts, threat-intel.ts, schema.prisma) and the D2 spec PDF (§5-§9) before coding.
- Created src/lib/normalizer.ts: parseAndNormalize(raw, format) handling canonical SIEM JSON, vendor EDR JSON (id/sensor/@timestamp/hostname/account/src_ip/event_type/message/severity mapping), CSV (severity = last column, description = cols 7..n-1 joined, quote-aware splitter), satellite text lines (regex per spec, alertId SAT-<tag>-<NNN>), and INTELLIGENCE REPORT text (SUMMARY paragraph -> description, Published: -> timestamp, INTL-000). Every alert gets metadata.iocs {ips, domains, hashes} (IPv4/domain/hex>=32 regex; file-extension tokens like winword.exe excluded; alert's own ip field included) + metadata.iocMatch/iocMatches vs MALICIOUS_* lists. Event keys normalized (lowercase, spaces/hyphens -> _). Invalid timestamps throw per-item errors. SOURCE_LABELS map + title-case fallback exported.
- Created src/lib/scorer.ts: pure scoreIncident() implementing spec §7 signals exactly (+20 privileged, +15 failed logins >=5 events or desc >=5, +15 external IP, +15 success-after-fail, +20 GB>=1/"large data"/"exfiltration"/"mass file", +25 iocMatch, +10 >=3 sources; cap 100), severity bands 85/70/45/20, FP heuristics (score<45 + benign keywords OR all-internal+no-IOC+<=3 failed OR scanner+benign -> severity & classification "False Positive"), MITRE via EVENT_MITRE_RULES on event+description (max 4, parent-id fallback), 2-4 evidence bullets citing alert IDs, confidence 60+10+10+5+5 cap 96, spec §8 BLUF template, pattern-based titles <=70 chars.
- Created src/lib/correlator.ts: runCorrelation() detaches alerts -> deleteMany incidents -> O(n^2) pair scoring in 30-min window (same user +3, same IP +3, same device +2, failed->success +4, success->large-transfer +4, same malicious IOC value +5, same event +1, threshold 5) -> Union-Find transitive closure -> groups >=2 become INC-1001.. with scorer fields, saved with alert.attach in a transaction. Returns { incidentsBefore, incidentsAfter, alertsGrouped, alertsUngrouped }.
- Created src/lib/llm.ts: analyzeIncidentWithLLM() (ZAI.create -> chat.completions.create, thinking disabled; STRICT-JSON system prompt per spec §9; fence-stripping + first{-last} extraction; 1 retry; validate/clamp severity/classification enums, scores 0-100, mitre filtered via mitreById; NEVER throws -> null on double failure) and copilotChat() (§9 copilot rules, compact snapshot: counts + top 8 incidents with keyEvents/bluf excerpt + last 6 history messages; returns null on failure).
- Created src/lib/summary.ts: shared toAlertDTO/toIncidentDTO/toIncidentDetailDTO serializers (ISO dates, JSON columns parsed, correlated flag), rankIncidents (Critical>High>Medium>Low>FP, then score desc, then updatedAt desc), getDashboardSummary() (counts, alertsBySeverity = incident severity when correlated else capitalized rawSeverity incl. "Info" bucket, alertsBySource, alertsByHour = last 12 distinct UTC hours "HH:00", topIncidents top 5, lastUpdated).
- Created 9 route files: /api/alerts (GET filters source/severity/correlated/search/limit, search is lowercased JS filter for SQLite), /api/alerts/import (POST; per-row create, alertId collisions counted as failed), /api/alerts/seed (POST; wipes chats+incidents+alerts when >=5 alerts exist, feeds all 5 demo chunks through auto normalizer, then runCorrelation), /api/incidents (GET ranked, response { incidents }), /api/incidents/correlate (POST stats + summary), /api/incidents/[id] (GET by cuid or INC-XXXX with asc timeline; PATCH status/classification/analystNote with enum validation, note appended as "\n\n[Analyst] <note>"), /api/incidents/[id]/analyze (POST LLM merge, +5 confidence cap 96, preserves analyst-note suffix, analyzed=true), /api/copilot/chat (GET history asc last 50, POST persist user msg -> grounded reply -> persist assistant, 502 on LLM failure, DELETE clears), /api/dashboard/summary. All force-dynamic.
- Verification: bunx tsc --noEmit clean for my files (pre-existing errors only in examples/ and skills/); bun run lint clean; smoke-tested every endpoint with curl against the running dev server.

Smoke-test results (actual):
- POST /api/alerts/seed -> {"seeded":29,"correlated":21,"incidents":6} (29 alerts from 5 feeds, 0 failed).
- GET /api/dashboard/summary -> totalAlerts 29, correlated 21, incidents 6, counts: critical 1 / high 1 / low 2 / falsePositive 2 / genuineThreats 4; charts populated; lastUpdated ISO.
- GET /api/incidents ranking: INC-1001 Critical 100 | INC-1002 High 70 | INC-1004 Low 40 | INC-1003 Low 40 | INC-1006 FP 30 | INC-1005 FP 15.
- INC-1001 = admin compromise: score 100 (all 7 signals hit: +20+15+15+15+20+25+10 capped), conf 90, 6-alert timeline A1001->A1002->A1003->A1004->A1006->A1005, MITRE T1110/T1078/T1021/T1041, BLUF in exact spec template.
- POST /api/incidents/<cuid>/analyze -> llmUsed=true, merged to Critical 95 conf 95 analyzed=true, real LLM title/explanation/actions.
- POST /api/copilot/chat -> reply cites "INC-1001 ... Critical severity and 95% confidence"; GET history persists both messages; DELETE clears.
- FP incidents verified: INC-1005 (rpatel) severity "False Positive" score 15; INC-1006 (scanner) severity "False Positive" score 30.
- Import tested: CSV w/ dup id -> imported 1 failed 1; satellite text ok; bad timestamp -> 400 "Invalid timestamp ...".
- PATCH INC-1005 {status, classification, analystNote} -> Resolved + "[Analyst] ..." appended; invalid enum -> 400.
- POST /api/incidents/correlate rerun -> before 6 / after 6 / grouped 21 / ungrouped 8 + summary (resets analyzed flags as documented).
- Final state: DB freshly re-seeded (29 alerts, 6 incidents, nothing analyzed) so the frontend can demo "Run AI Analysis" live.

Stage Summary:
- Endpoints: GET /api/alerts | POST /api/alerts/import | POST /api/alerts/seed | GET /api/incidents | POST /api/incidents/correlate | GET+PATCH /api/incidents/[id] | POST /api/incidents/[id]/analyze | GET+POST+DELETE /api/copilot/chat | GET /api/dashboard/summary. /api/route.ts untouched; no Task-1 shared file modified.
- Deviation 1 (deliberate, verified): correlation weights are same-user +3 and same-IP +3 regardless of RFC1918 (task draft said user +2, "non-internal ip" +3). With the draft values the demo's expected outcomes are mathematically unreachable: A1005 (admin/server-01 but different external IP) can never reach threshold 5, Story B pairs max at 4, and scanner-F6003 can never join its story. PDF spec §6 itself says only "Same IP ... add correlation points". Verified no unintended groupings (satellites 3<5, achen-vs-12.4GB-satellite 4<5, all cross-story pairs 0).
- Deviation 2: EVENT_MITRE_RULES references T1588.001 which is absent from MITRE_TECHNIQUES (Task-1 data gap); scorer resolves to parent T1588 via id-prefix fallback instead of editing the shared file. Also detectFormat must JSON.parse-probe "["-prefixed input because satellite text starts with "[".
- Deviation 3: incidents list endpoint wraps as { incidents: [...] }; analyze bumps confidence +5 (route contract) rather than the heuristic note's +10; copilot DELETE returns { ok: true }.
- Frontend notes: all dates ISO strings; incident detail = IncidentDetailDTO with alerts[] asc; un-analyzed incidents have explanation=null but always have deterministic bluf/evidence/recommendedActions/status; alertsBySeverity may contain an "Info" bucket; correlated boolean + incidentId present on every alert; re-seed/re-correlate resets analysis+notes (use for demo reset); import does NOT auto-correlate (call /api/incidents/correlate after).
---
Task ID: 3
Agent: Z.ai Code (main)
Task: Integration verification + agent-browser QA + bug fixes

Work Log:
- Verified full API pipeline via curl: seed → 29 alerts / 6 incidents (INC-1001 Critical 100/90, INC-1002 High 70/85, INC-1003/1004 Low 40, INC-1005/1006 False Positive), ranked Critical-first, all DTO shapes conform to src/lib/types.ts.
- Ran agent-browser end-to-end QA at 1440x900 and 375x812; exercised every tab and core interaction.
- FIX 1 (command-center.tsx): CopilotMiniPanel useQuery had queryKey ["dashboard-summary"] with `select` but NO queryFn → React Query error toast on mount. Added queryFn + refetchInterval.
- FIX 2 (incident-analysis.tsx): detail query typed as bare IncidentDetailDTO but API returns { incident } envelope → runtime crash "Cannot read properties of undefined (reading 'join')" on incident.sources. Now unwraps `.incident` in queryFn (also added enabled guard).
- FIX 3 (incident-analysis.tsx): Attack Timeline <ol> had max-h-96 but overflow visible → 6-alert timeline spilled 340px past the card, over the footer, breaking sticky-footer layout. Added overflow-y-auto. Verified bodyH == footer bottom after fix.
- FIX 4 (incident-analysis.tsx): BLUF card was hidden until LLM analysis ran; spec F8 requires BLUF as a MUST feature and deterministic baseline always exists. BLUF now always renders with provenance chip: "Deterministic Baseline" (amber) vs "AI Analyst Report" (emerald, post-LLM).
- Verified LLM round-trip: Run AI Analysis on INC-1001 → analyzed=true, AI BLUF in exact §8 template, 4 recommended actions, evidence with alert IDs, AI explanation card.
- Verified Copilot grounding: "What is the highest-risk threat?" → answer cites INC-1001, Critical, 95% confidence, evidence summary.
- Verified analyst feedback: Confirm Threat (classification persisted), status workflow dropdown (Open → Investigating persisted), PATCH endpoint.
- Verified Threat Feed: source filter (Firewall → 4 rows), correlated chips link, import panel — pasted raw JSON alert X9001 via UI → normalized → queryable.
- Verified mobile 375px: icon-only tabs, 2-col KPI grid, stacked charts, horizontally scrollable table, footer respects bottom.
- Final checks: bun run lint clean; bunx tsc --noEmit clean for src/; dev.log shows no runtime errors; zero browser console errors.

Stage Summary:
- App is demo-ready: full D2 pipeline works (input → normalize → correlate → score → MITRE → BLUF → prioritized view → Copilot), all 13 acceptance criteria pass.
- Current data state: seeded demo set + 1 imported alert X9001 (uncorrelated); INC-1001 analyzed by LLM, status Investigating, classification Genuine Threat.
- Known minor deviations documented by backend in Task 2-a section (correlation weight tweak +2→3 same-user, T1588 fallback).
---
Task ID: 5
Agent: Z.ai Code (main)
Task: Create recurring webDevReview scheduled task + close out MVP build

Work Log:
- Created cron job (ID 384658): every 15 min, kind=webDevReview, tz Asia/Calcutta, mandatory D2 review prompt (assess → QA via agent-browser → fix bugs or add features → update this worklog).

Stage Summary:
- SentinelAI D2 MVP is complete, browser-verified, and demo-ready. Next scheduled reviews will iterate on polish and new features (nice-to-haves from spec §15: PDF BLUF export, live alert simulation, entity graph, CSV upload, dark-theme animations).
