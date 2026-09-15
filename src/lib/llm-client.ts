/** Server-only transport for OpenAI-compatible chat APIs. */
export async function completeChat(
  messages: { role: "system" | "user" | "assistant"; content: string }[],
  json = false,
  schema?: Record<string, unknown>,
): Promise<string> {
  if (process.env.AI_MODE === "local") throw new Error("Local mode");

  const apiKey = process.env.AI_API_KEY;
  const baseUrl = process.env.AI_BASE_URL?.replace(/\/$/, "");
  const primaryModel = process.env.AI_MODEL;
  if (!apiKey || !baseUrl || !primaryModel) {
    throw new Error("External AI provider is not configured");
  }

  const fallbackModels = (process.env.AI_FALLBACK_MODELS || "")
    .split(",")
    .map((model) => model.trim())
    .filter(Boolean);
  const models = [...new Set([primaryModel, ...fallbackModels])];
  let lastError: Error | null = null;

  for (let index = 0; index < models.length; index++) {
    const model = models[index];
    const isLastModel = index === models.length - 1;
    try {
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        signal: AbortSignal.timeout(30_000),
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: 0.2,
          max_completion_tokens: json ? 2500 : 800,
          ...(json
            ? {
                response_format: schema
                  ? {
                      type: "json_schema",
                      json_schema: {
                        name: "sentinel_incident_analysis",
                        strict: true,
                        schema,
                      },
                    }
                  : { type: "json_object" },
              }
            : {}),
        }),
      });

      if (!response.ok) {
        const errorBody = (await response.text()).slice(0, 1000);
        lastError = new Error(`AI provider (${model}) returned HTTP ${response.status}: ${errorBody}`);
        if (!isLastModel && (response.status === 404 || response.status === 429 || response.status >= 500)) {
          continue;
        }
        throw lastError;
      }

      const data = await response.json();
      const choice = data?.choices?.[0];
      if (choice?.finish_reason && choice.finish_reason !== "stop") {
        throw new Error(`AI provider (${model}) response was incomplete or blocked`);
      }
      const content = choice?.message?.content;
      if (typeof content !== "string" || !content.trim()) {
        throw new Error(`AI provider (${model}) returned no text`);
      }
      return content.trim();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      const retryable =
        lastError.name === "AbortError" ||
        lastError.name === "TimeoutError" ||
        /timeout|timed out|aborted|429|502|503|504|unavailable|rate.?limit/i.test(lastError.message);
      if (!isLastModel && retryable) continue;
      throw lastError;
    }
  }

  throw lastError ?? new Error("All configured AI models failed");
}
