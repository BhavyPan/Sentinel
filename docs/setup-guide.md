# Setup Guide

## Prerequisites

Before you begin, ensure you have the following installed:

- Node.js 18+
- npm (or yarn/pnpm/bun)
- A Supabase account (for PostgreSQL database)
- A Groq account (for AI API access)
- Git

## Environment Variables

Copy `.env.example` to `.env.local` and fill in the values:

```bash
cp .env.example .env.local
```

| Variable | Description | Required |
|---|---|---|
| `DATABASE_URL` | Your Supabase PostgreSQL connection string (Transaction connection) | Yes |
| `DIRECT_URL` | Your Supabase PostgreSQL connection string (Session connection) | Yes |
| `AI_API_KEY` | Your Groq API key | Yes |
| `AI_MODEL` | Set to `llama-3.1-8b-instant` (or desired Groq model) | Yes |

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/BhavyPan/Sentinel2.git
cd Sentinel2

# 2. Install dependencies
npm install

# 3. Generate Prisma Client and Push Schema
npm run db:generate
npm run db:push
```

## Running the Application

```bash
# Start the development server
npm run dev
```

The application will be available at: `http://localhost:3000`

## Seeding Demo Data

To see the dashboard in action with realistic alerts and incidents, you can use the built-in API seed routes via the dashboard UI or manually triggering them:

1. Navigate to `http://localhost:3000`
2. You can trigger alert generation or test the incident correlation logic by simulating events using the UI elements if provided, or by hitting the API routes directly (e.g., POST `/api/alerts/seed`).

## Troubleshooting

| Issue | Solution |
|---|---|
| `PrismaClientInitializationError` | Ensure your `DATABASE_URL` and `DIRECT_URL` are correct and your Supabase database is active. |
| AI features are failing or returning empty | Check that your `AI_API_KEY` is valid and the `AI_MODEL` is correctly set in `.env.local`. |
| Port 3000 is already in use | Run `npm run dev -- -p 3001` to start on a different port. |
