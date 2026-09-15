# SentinelAI

D2 threat intelligence correlation and alert prioritisation MVP. Import security feeds, connect related alerts, review ranked incidents, inspect MITRE ATT&CK mappings and BLUF reports, and ask an optional external model about stored evidence. Application data is stored in Supabase PostgreSQL through Prisma.

## Run locally

Requires Node.js 20.9+ and npm. The application uses Next.js API routes and Supabase PostgreSQL through Prisma, so a separate FastAPI server is not needed.

```sh
npm ci
npm run db:generate
npm run db:push
npm run dev
```

Open http://localhost:3000. On a fresh checkout, copy `.env.example` to the ignored `.env.local` file and add the Supabase connection strings from **Supabase Dashboard → Connect**. Use the transaction pooler for `DATABASE_URL` and the session pooler or direct connection for `DIRECT_URL`. `db:push` does not automatically accept data loss.

### Optional external AI — Groq recommended

The app supports any OpenAI-compatible chat API. Groq is recommended for this demo because it offers a rate-limited free plan and structured JSON output. Add a Groq API key to the untracked `.env.local` file:

```dotenv
AI_BASE_URL=https://api.groq.com/openai/v1
AI_MODEL=openai/gpt-oss-20b
AI_FALLBACK_MODELS=qwen/qwen3.8-27b,openai/gpt-oss-120b
AI_API_KEY=your_key_here
AI_MODE=auto
```

Restart the application after changing settings. Create a key in the [Groq Console](https://console.groq.com/keys). The selected default model supports Groq structured outputs.

The key stays on the server. Running AI Analysis sends the selected incident and its alerts to the configured provider. Copilot sends relevant stored incident context and recent conversation. Keep `AI_MODE=local` to disable all external AI calls.

Without a key, or when the configured provider fails, the app shows a clearly labeled local response. Rule-based scores, classification, evidence, MITRE mappings and BLUF reports remain available. Local Copilot supports greetings, priority, incident briefs and false-positive summaries; it does not provide unrestricted AI conversation. Only successful, validated external analyses receive the AI-analyzed flag.

### Production build

```sh
npm run build
npm start
```

The build checks TypeScript and copies public/static assets into Next.js standalone output using a cross-platform Node script. For deployment, provide the pooled Supabase `DATABASE_URL`, the migration-only `DIRECT_URL`, and optional `AI_*` settings as server environment variables. The local start script loads the root environment settings before launching the standalone server.

## Demo walkthrough

1. Click **Load Demo Dataset** to import 29 alerts from SIEM JSON, EDR JSON, cyber-sensor CSV, satellite text and an intelligence report.
2. Open **Command Center** to see severity counts and priority-ranked cases.
3. Open the Critical administrator-compromise case in **Incident Analysis**. Inspect the failed logins, successful login and large download timeline, evidence, MITRE mapping and BLUF.
4. Click **Run AI Analysis** for an external-model assessment when configured.
5. Ask **AI Copilot**: “What should we investigate first and why?”
6. Try file import, correlation, analyst status/notes, false-positive feedback, watchlist, graph, simulation and PDF report export.

Demo loading is idempotent when the bundled demo is already present and preserves imported alerts, chat history and analyst casework. Re-correlation retains stable case IDs for unchanged or growing groups. When groups merge, the case with the largest overlap survives and receives the other cases' audit events; retired case IDs no longer resolve. Changed evidence invalidates stale AI analysis while preserving analyst status and notes.

## Feed formats

- JSON: canonical `alert_id`, `source`, `timestamp`, `user`, `device`, `ip`, `event`, `description`, `raw_severity`, optional `metadata`; vendor EDR fields are also supported.
- CSV: `alert_id,source,timestamp,user,device,ip,event,description,severity`; quote descriptions containing commas.
- Satellite text: `[TAG] 2026-09-15T10:00:00Z SEV:low STATION :: description`.
- Intelligence text: start with `INTELLIGENCE REPORT`, then `Published:` and `SUMMARY:` lines.

Timestamps without a timezone use UTC. Imports accept up to 2 MB, validate required fields/IPs/severity, preserve metadata, and return row errors without discarding valid siblings. Duplicate alert IDs are skipped. After import, run correlation using the header action. The threat feed displays 50 alerts per page.

## Verification

```sh
npm test
npm run typecheck
npm run lint
npm run build
```

- Unit/regression suite checks the scoring and normalization rules, AI validation, and mocked provider transport. No live API key is required.
- Run the development server and production build sequentially because Next.js shares build output.

## Scope

The nine required D2 features and four required screens are implemented, along with the original graph, simulation, watchlist, analyst workflow and PDF exports. See `BUILD_AUDIT.md` for the specification comparison.

This is a hackathon MVP with synthetic threat intelligence, heuristic scores, shared Supabase case/chat storage and no authentication. A live external-model response requires a provider key and available quota; automated checks mock provider responses and do not verify external accounts or credentials.
