// Same-origin proxy from the browser to the ArgusAI API.
//
// The browser sends its session cookie; this handler swaps it for the API's
// bearer token (see lib/session.ts). Only the endpoints the dashboard uses are
// reachable, and state-changing requests must carry a custom header and a
// same-origin Origin, which a cross-site form or image cannot produce.
import type { NextRequest } from "next/server";
import { backendFetch, clearSession } from "@/lib/session";

const ALLOWED = [
  /^auth\/me$/,
  /^auth\/password$/,
  /^alerts(\/\d+(\/(ack|status|notes|assignee|events))?)?$/,
  /^events(\/\d+)?$/,
  /^stats\/(summary|timeseries|distribution)$/,
  /^sensors$/,
  /^config\/detection$/,
  /^audit$/,
  /^users(\/\d+)?$/,
  /^notifications\/(channels(\/\d+(\/test)?)?|deliveries)$/,
];

const MAX_BODY = 64 * 1024;
const CSRF_HEADER = "x-sentinel-csrf";

function problem(status: number, detail: string) {
  return Response.json({ detail }, { status, headers: { "Cache-Control": "no-store" } });
}

function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

async function forward(request: NextRequest, ctx: RouteContext<"/api/backend/[...path]">) {
  const { path } = await ctx.params;
  const target = path.join("/");
  if (!ALLOWED.some((pattern) => pattern.test(target))) return problem(404, "Not found");

  const init: RequestInit = { method: request.method, headers: {} };
  if (request.method !== "GET") {
    if (request.headers.get(CSRF_HEADER) !== "1" || !sameOrigin(request)) {
      return problem(403, "Cross-site request refused");
    }
    const body = await request.text();
    if (body.length > MAX_BODY) return problem(413, "Request body too large");
    init.body = body;
    init.headers = { "Content-Type": "application/json" };
  }

  let response: Response;
  try {
    response = await backendFetch(`/api/v1/${target}${request.nextUrl.search}`, init);
  } catch {
    return problem(502, "The ArgusAI API is unreachable.");
  }

  // A password change ends every session of the user, this one included.
  if (target === "auth/password" && response.status === 204) await clearSession();

  const headers = new Headers({ "Cache-Control": "no-store" });
  const type = response.headers.get("content-type");
  if (type) headers.set("Content-Type", type);
  const body = response.status === 204 ? null : await response.arrayBuffer();
  return new Response(body, { status: response.status, headers });
}

export { forward as GET, forward as POST, forward as PUT, forward as PATCH };
