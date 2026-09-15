# Solution Overview

## What We Built

We built **Sentinel2**, an AI-powered Security Operations Center (SOC) dashboard. Sentinel2 acts as a force multiplier for security analysts by automatically digesting raw security alerts, grouping related events into cohesive incidents, and using rapid AI inference to read the logs and provide a plain-language summary of what actually happened, why it matters, and what to do next.

## How It Works

1. **Alert Ingestion:** Sentinel2 ingests security events from various hypothetical sources (firewalls, EDRs, DLP). 
2. **Correlation Engine:** A correlation engine evaluates the incoming alerts and groups them together if they share common entities (like the same user or IP address) within a specific timeframe.
3. **AI Triage:** The combined data of an incident is instantly passed to an LLM via the Groq API. The AI acts as a senior analyst, generating a BLUF (Bottom Line Up Front) summary, mapping the activity to MITRE ATT&CK frameworks, and scoring the confidence of the threat.
4. **Actionable Dashboard:** The SOC analyst views a clean, prioritized list of incidents. Instead of reading JSON logs, they read the AI's summary, allowing them to make a remediation decision in seconds rather than minutes.
5. **Interactive Copilot:** Analysts can chat directly with an integrated AI Copilot to ask questions like "Summarize the latest critical incidents" or "How do I mitigate T1110?".

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

```
[Raw Alerts] --> [Next.js API Correlation] --> [Supabase DB]
                                  |
                           [Groq AI Inference]
                                  |
                       [SOC Analyst Dashboard]
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Used Groq for AI Inference** | Security triaging must be real-time. Groq's LPU inference engine provides the ultra-low latency required to analyze incidents faster than traditional LLM providers, avoiding dashboard lag. |
| **Next.js App Router** | Unified frontend and backend allowed for rapid prototyping and seamless integration of Server Actions for secure database mutations. |
| **Supabase (PostgreSQL)** | Provided a robust, scalable relational database out-of-the-box that plays perfectly with Prisma ORM. |

## Technologies Used

- **Groq AI API:** Used the `llama-3.1-8b-instant` (or similar) model via the Groq API to analyze incident payloads. The AI is specifically prompted to act as a Tier 3 SOC analyst, outputting structured JSON (MITRE mappings, severity, confidence, BLUF) and powering the conversational copilot.
- **Next.js & Tailwind CSS:** Used to build a responsive, highly-interactive, dark-mode dashboard tailored for long hours of monitoring.
- **Supabase:** Hosted PostgreSQL database for storing alerts, incidents, and relational metadata.
