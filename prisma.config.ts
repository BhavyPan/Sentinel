import { loadEnvConfig } from "@next/env";
import { defineConfig, env } from "prisma/config";

loadEnvConfig(process.cwd());

export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: {
    // Prisma CLI operations need a session/direct connection. Runtime queries
    // continue to use the pooled DATABASE_URL from schema.prisma.
    url: env("DIRECT_URL"),
  },
});
