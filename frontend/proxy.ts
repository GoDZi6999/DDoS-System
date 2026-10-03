// Send visitors without a session to the login page before any page renders.
// This only checks that a session cookie exists; the API validates the token
// on every request, so an invalid cookie still gets nothing but a 401.
import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  const hasSession =
    request.cookies.has("sentinel_access") || request.cookies.has("sentinel_refresh");
  if (hasSession) return NextResponse.next();
  const login = new URL("/login", request.url);
  const next = request.nextUrl.pathname + request.nextUrl.search;
  if (next !== "/") login.searchParams.set("next", next);
  return NextResponse.redirect(login);
}

export const config = {
  // Everything except the login and status pages, API routes and static assets.
  matcher: ["/((?!login|status|api|_next/static|_next/image|icon\\.svg|favicon\\.ico).*)"],
};
