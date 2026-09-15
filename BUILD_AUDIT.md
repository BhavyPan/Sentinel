# D2 specification audit

Source: `SentinelAI_D2_AI_Build_Specification.pdf` (9 pages), reviewed against the existing codebase on 2026-09-15.

## Required features

| Requirement | Implementation and work completed |
| --- | --- |
| F1 Multi-source input | Five demo feeds, paste/file import, row error reporting and 2 MB server limit. |
| F2 Normalisation | Common alert DTO, validated fields/IPs/severity, UTC timestamps, preserved metadata and extracted IOCs. |
| F3 Correlation | Deterministic 30-minute linking; atomic updates, stable case IDs, preserved notes/status/activity; shared engine for simulation. |
| F4 Genuine threats | Evidence-based scores; suspicious internal execution no longer dismissed solely because its IP is internal. |
| F5 False positives | Routine/approved activity and small password mistakes; word-boundary matching avoids treating “unauthorized” as “authorized”; explanatory report. |
| F6 Prioritisation | Required 0–100 scoring weights and severity bands; small routine downloads no longer get large-transfer points. |
| F7 MITRE mapping | Curated valid IDs/names, timeline mapping and strict validation of model-suggested techniques. |
| F8 BLUF reports | Seven-section deterministic report; provider-neutral structured output, no artificial confidence boost; clearly labeled fallback. |
| F9 Investigation view | Ranked cases, severity/score/confidence/status, all seven KPI categories, paginated feed and analyst workflow. |

All four required screens were already substantially implemented. Work focused on functional gaps and reliability. The existing Next.js API routes are retained in place of the specification's suggested FastAPI backend; they expose the required endpoints under `/api` and use Supabase PostgreSQL through Prisma.

## Significant corrections

- Removed destructive re-correlation and demo resets. Stable cases retain their IDs, full AI output when evidence is unchanged, analyst state and audit history.
- New alert evidence refreshes the baseline and invalidates stale analysis; merges retain audit history on the surviving case.
- Login sequence links require a shared entity. Corrected failure-event and large-transfer detection and overbroad false-positive rules.
- Import no longer silently converts missing fields to the string “undefined” or drops metadata. Intelligence/satellite records receive content-derived IDs.
- Copilot includes explicitly requested cases beyond the top five, rejects references to absent IDs, and saves complete user/assistant exchanges.
- The OpenAI-compatible integration uses server-side credentials, structured schema, response validation, timeout, and local fallback. Provider requests are tested with mocked responses.
- Fixed Linux-only database configuration and shell-specific build/start scripts. Production builds enforce TypeScript checks.
- Added Low-severity KPI, chronological date/hour buckets, pagination, full ranked incident table (previously limited to five), and React subscription fixes.

## Verification coverage

- Regression tests: demo formats, metadata, invalid rows, UTC handling, text IDs, CSV quotes, correlation relationships/window, transfer size, internal suspicious activity, benign-password classification, score bands, MITRE/BLUF, AI schema and provider transport failures.
- Production build, TypeScript, lint, and server response checks cover the application and API route compilation.

## Practical limits

- Automated tests deliberately make no live provider calls; provider credentials and quota remain deployment-specific.
- Correlation/scoring are transparent demo heuristics; confidence is not a calibrated probability.
- Copilot's provider snapshot includes up to 20 relevant cases, with up to 30 alert records per case; the local summary can select from all stored cases.
- When correlation merges cases, links to a retired case ID do not redirect; the surviving case records the merge in its activity trail.
- Shared local storage and unauthenticated endpoints match the hackathon scope; real operational deployment needs separate access and tenancy design.
