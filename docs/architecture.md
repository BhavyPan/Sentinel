# Architecture

## System Architecture

Sentinel2 leverages a modern, decoupled architecture designed for high performance and real-time responsiveness. The frontend handles real-time data visualization and user interaction, while the backend API integrates with PostgreSQL for persistence and the Groq API for rapid AI inference.

```mermaid
graph TD
    A[User / SOC Analyst] -->|HTTPS| B[Next.js Frontend (React/Tailwind)]
    B <-->|REST API / Server Actions| C[Next.js API Routes]
    C -->|Prisma ORM| D[Supabase PostgreSQL DB]
    C -->|LLM Inference API| E[Groq AI (Llama 3)]
    F[Security Sensors / SIEM] -->|Ingestion API| C
```

## Components

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | Next.js 15, React 19, Tailwind CSS | Rendering the interactive SOC dashboard, charts, and copilot UI. |
| Backend API | Next.js API Routes / Server Actions | Handling business logic, incident correlation, and authentication. |
| AI / Copilot | Groq API | Rapid analysis of incidents, BLUF generation, and conversational copilot support. |
| Database | Supabase (PostgreSQL), Prisma | Storing alerts, incidents, and threat intelligence data. |

## Data Flow

1. **Ingestion:** Raw security alerts (from EDR, Firewall, DLP) are ingested into the system (simulated/seeded via API).
2. **Correlation:** The backend evaluates incoming alerts and groups related events (by IP, user, or timeframe) into consolidated incidents.
3. **AI Analysis:** The incident payload is sent to the Groq API. The LLM extracts MITRE ATT&CK tactics, assigns a confidence score, and generates a Bottom Line Up Front (BLUF) summary.
4. **Persistence:** The incident, along with its AI analysis and metadata, is saved to the Supabase PostgreSQL database.
5. **Visualization:** The SOC analyst views the dashboard where data is fetched and displayed using interactive tables and charts.

## Security Considerations

- **Environment Variables:** Sensitive keys (e.g., `DATABASE_URL`, `AI_API_KEY`) are stored in `.env.local` and never committed to version control.
- **Data Privacy:** Incident analysis relies on metadata without exposing raw PII directly to the AI model where possible.
- **Secure Deployment:** Deployed securely on Vercel with encrypted environment variables.

## Scalability Notes

- **Stateless Backend:** The Next.js API is completely stateless, meaning it scales horizontally automatically on Vercel's edge network.
- **High-Performance Inference:** Utilizing Groq's LPU architecture ensures that even with a surge in incidents, the AI analysis remains virtually instantaneous without becoming a bottleneck.
- **Connection Pooling:** Supabase and Prisma handle connection pooling, allowing the database to efficiently manage high volumes of simultaneous connections from serverless functions.
