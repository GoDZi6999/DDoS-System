// Server-side session handling (backend-for-frontend).
//
// The API's access and refresh tokens live only in httpOnly cookies set by
// this Next.js server; browser JavaScript never sees them. Route handlers and
// server actions call the API through backendFetch, which attaches the access
// token and transparently rotates it with the refresh token when it expires.
import { cookies, headers } from "next/headers";

export const ACCESS_COOKIE = "argus_access";
export const REFRESH_COOKIE = "argus_refresh";

const API = process.env.API_INTERNAL_URL ?? "http://localhost:8000";

type TokenPair = {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
};

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    // Set COOKIE_SECURE=true when the dashboard is served over HTTPS.
    secure: process.env.COOKIE_SECURE === "true",
    path: "/",
    maxAge,
  };
}

/**
 * Client IP and user agent, forwarded so the API can throttle and audit per
 * user. Next.js fills X-Forwarded-For from the socket only when the request
 * has none, so the right-most entry is used: it is the peer address, or the
 * address added by a reverse proxy in front. A client talking to Next.js
 * directly can still pick its own value; deployments beyond localhost put a
 * TLS proxy in front that overwrites the header (docs/SECURITY.md).
 */
async function clientHeaders(): Promise<Record<string, string>> {
  const incoming = await headers();
  const forwarded: Record<string, string> = {};
  const ip = incoming.get("x-forwarded-for")?.split(",").at(-1)?.trim();
  if (ip) forwarded["X-Forwarded-For"] = ip;
  const agent = incoming.get("user-agent");
  if (agent) forwarded["User-Agent"] = agent.slice(0, 256);
  return forwarded;
}

async function storeTokens(tokens: TokenPair) {
  const jar = await cookies();
  jar.set(ACCESS_COOKIE, tokens.access_token, cookieOptions(tokens.expires_in));
  jar.set(REFRESH_COOKIE, tokens.refresh_token, cookieOptions(tokens.refresh_expires_in));
}

export async function clearSession() {
  const jar = await cookies();
  jar.delete(ACCESS_COOKIE);
  jar.delete(REFRESH_COOKIE);
}

export type LoginResult = { ok: true } | { ok: false; error: string };

export async function login(username: string, password: string): Promise<LoginResult> {
  let response: Response;
  try {
    response = await fetch(`${API}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...(await clientHeaders()) },
      body: new URLSearchParams({ username, password }),
      cache: "no-store",
    });
  } catch {
    return { ok: false, error: "The Argus API is unreachable." };
  }
  if (response.status === 429) {
    const wait = Math.ceil(Number(response.headers.get("retry-after") ?? "60") / 60);
    return { ok: false, error: `Too many failed attempts. Try again in about ${wait} min.` };
  }
  if (!response.ok) return { ok: false, error: "Incorrect username or password." };
  await storeTokens((await response.json()) as TokenPair);
  return { ok: true };
}

export async function logout() {
  const refresh = (await cookies()).get(REFRESH_COOKIE)?.value;
  if (refresh) {
    await fetch(`${API}/api/v1/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(await clientHeaders()) },
      body: JSON.stringify({ refresh_token: refresh }),
      cache: "no-store",
    }).catch(() => undefined);
  }
  await clearSession();
}

/** Seconds until the JWT expires (no signature check: only used to decide when to refresh). */
function secondsLeft(token: string): number {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
    return payload.exp - Date.now() / 1000;
  } catch {
    return 0;
  }
}

// The API treats a reused refresh token as theft and ends the session, but a
// dashboard fires several requests at once when the access token expires.
// Concurrent (and slightly late) refreshes of the same token therefore share
// one API call and its result. This assumes one Next.js server process, which
// is how the Compose stack runs it.
const inflight = new Map<string, Promise<TokenPair | null>>();
const REUSE_MS = 30_000;

function rotate(token: string, forwarded: Record<string, string>): Promise<TokenPair | null> {
  let pending = inflight.get(token);
  if (!pending) {
    pending = fetch(`${API}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...forwarded },
      body: JSON.stringify({ refresh_token: token }),
      cache: "no-store",
    })
      .then(async (response) => (response.ok ? ((await response.json()) as TokenPair) : null))
      .catch(() => null);
    inflight.set(token, pending);
    setTimeout(() => inflight.delete(token), REUSE_MS).unref?.();
  }
  return pending;
}

async function refresh(): Promise<string | null> {
  const token = (await cookies()).get(REFRESH_COOKIE)?.value;
  if (!token) return null;
  const tokens = await rotate(token, await clientHeaders());
  if (!tokens) {
    await clearSession();
    return null;
  }
  await storeTokens(tokens);
  return tokens.access_token;
}

/** A usable access token, refreshed if it expires within 30 seconds. */
export async function accessToken(): Promise<string | null> {
  const token = (await cookies()).get(ACCESS_COOKIE)?.value;
  if (token && secondsLeft(token) > 30) return token;
  return refresh();
}

/** Call the API as the signed-in user; retries once after refreshing on 401. */
export async function backendFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const send = async (token: string | null) =>
    fetch(`${API}${path}`, {
      ...init,
      headers: {
        ...(init.headers as Record<string, string>),
        ...(await clientHeaders()),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      cache: "no-store",
    });
  let response = await send(await accessToken());
  if (response.status === 401) {
    const renewed = await refresh();
    if (renewed) response = await send(renewed);
  }
  return response;
}

export const apiBaseUrl = API;
