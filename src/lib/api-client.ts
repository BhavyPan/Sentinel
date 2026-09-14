/**
 * SentinelAI — frontend fetch helpers. All URLs are RELATIVE ("/api/...").
 */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function parseError(res: Response): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object" && "error" in body) {
      const msg = (body as { error: unknown }).error;
      if (typeof msg === "string") return msg;
    }
    if (body && typeof body === "object" && "message" in body) {
      const msg = (body as { message: unknown }).message;
      if (typeof msg === "string") return msg;
    }
  } catch {
    /* body was not JSON */
  }
  return `Request failed (${res.status})`;
}

/** GET + parse JSON, throwing ApiError with the server's message on failure. */
export async function apiGet<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new ApiError(await parseError(res), res.status);
  return (await res.json()) as T;
}

/** POST/PUT/PATCH/DELETE with a JSON body. */
export async function apiSend<T>(
  url: string,
  method: "POST" | "PATCH" | "DELETE",
  body?: unknown
): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(await parseError(res), res.status);
  return (await res.json()) as T;
}
