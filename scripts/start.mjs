import { loadEnvConfig } from "@next/env";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

process.env.NODE_ENV = "production";
loadEnvConfig(process.cwd());
await import(pathToFileURL(resolve(".next/standalone/server.js")).href);
