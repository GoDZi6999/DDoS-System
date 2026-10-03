"use client";
// Browser-side access to the API through the same-origin proxy
// (app/api/backend/[...path]). The session cookie travels automatically.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function toLogin() {
  const next = window.location.pathname + window.location.search;
  // A full page load, so no cached data from the ended session survives.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.href = `/login?next=${encodeURIComponent(next)}`;
}

async function parse<T>(response: Response): Promise<T> {
  if (response.status === 401) {
    toLogin();
    throw new ApiError(401, "Your session has ended. Please sign in again.");
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail) && body.detail[0]?.msg) {
        message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
      }
    } catch {}
    throw new ApiError(response.status, message);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

/** SWR fetcher: `path` is relative to /api/v1, e.g. "alerts?limit=10". */
export async function fetcher<T>(path: string): Promise<T> {
  return parse<T>(await fetch(`/api/backend/${path}`, { cache: "no-store" }));
}

/** State-changing call; the custom header is the proxy's CSRF check. */
export async function send<T>(
  method: "POST" | "PUT" | "PATCH",
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api/backend/${path}`, {
    method,
    headers: { "Content-Type": "application/json", "x-sentinel-csrf": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return parse<T>(response);
}
