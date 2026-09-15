# 🚀 Sentinel2: AI-Powered SOC Dashboard

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | Sentinel |
| **Track** | AI / Security |
| **Team Lead** | BhavyPan |
| **Members** | BhavyPan |

---

## 🎯 Problem Statement

> In 2–3 sentences: What problem does your project solve? Who experiences this problem?

Security Operations Center (SOC) analysts are overwhelmed by the sheer volume of security alerts, many of which are false positives or low-priority events. Sentinel2 addresses this by providing an AI-driven dashboard that correlates alerts into incidents, triages them using Groq-powered AI, and provides actionable summaries, reducing alert fatigue and enabling analysts to focus on genuine threats.

---

## 💡 Solution

> In 2–3 sentences: What did you build? How does it solve the problem above?

We built a modern, responsive web application using Next.js and Tailwind CSS that ingests security alerts and groups them into incidents. It integrates an AI copilot using the Groq API to analyze incidents, summarize the "Bottom Line Up Front" (BLUF), and suggest immediate remediation steps, drastically reducing investigation times.

---

## ✨ Key Features

- **Real-time Incident Dashboard:** View and manage alerts, correlated incidents, and metrics in an intuitive UI.
- **AI-Powered Analysis:** Leverages Groq AI to provide BLUF summaries, extract MITRE ATT&CK tactics, and suggest mitigation steps for each incident.
- **Incident Correlation:** Automatically groups related alerts into single manageable incidents to reduce noise.
- **Interactive Copilot:** A chat-based assistant to help analysts query security events and ask questions directly within the dashboard.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | TypeScript |
| **Frameworks** | Next.js, React, Tailwind CSS |
| **Databases** | Supabase (PostgreSQL), Prisma ORM |
| **Other** | Groq API, Vercel |

---

## 📁 Repository Structure

```
├── src/                  # All source code (Next.js App Router)
├── prisma/               # Database schema and migrations
├── demo/                 # Demo artifacts
│   ├── screenshots/      # App screenshots
│   └── live-demo-url.txt # Link to deployed demo
├── presentation/         # Slide deck
└── README.md             # This file
```

---

## ⚡ How to Run

```bash
# 1. Clone the repo
git clone https://github.com/BhavyPan/Sentinel2.git
cd Sentinel2

# 2. Install dependencies
npm install

# 3. Configure environment
cp .env.example .env.local
# Edit .env.local with your Supabase DATABASE_URL and Groq AI_API_KEY

# 4. Generate Prisma Client
npm run db:generate

# 5. Run the project
npm run dev
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 🌐 Live Demo | [https://sentinel2-dun.vercel.app](https://sentinel2-dun.vercel.app) |

---

## 🏅 What We're Most Proud Of

Integrating lightning-fast AI capabilities via Groq directly into the incident response workflow, enabling analysts to go from raw alert data to an actionable summary in seconds.
