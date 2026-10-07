// Live updates for the browser as Server-Sent Events.
//
// The API's WebSocket needs the access token, which never reaches the browser,
// so this handler opens the WebSocket server-side and relays each message as an
// SSE "message" event. When the API closes the socket (its token expired after
// 15 minutes, or the API restarted) the stream ends and EventSource reconnects,
// which refreshes the token through accessToken().
import type { NextRequest } from "next/server";
import { accessToken, apiBaseUrl } from "@/lib/session";

const KEEPALIVE_MS = 15_000;

export async function GET(request: NextRequest) {
  const token = await accessToken();
  if (!token) return Response.json({ detail: "Not authenticated" }, { status: 401 });

  const encoder = new TextEncoder();
  let stop = () => {};
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const socket = new WebSocket(`${apiBaseUrl.replace(/^http/, "ws")}/api/v1/ws`);
      let done = false;
      const write = (chunk: string) => {
        if (!done) controller.enqueue(encoder.encode(chunk));
      };
      const keepalive = setInterval(() => write(": keepalive\n\n"), KEEPALIVE_MS);
      stop = () => {
        if (done) return;
        done = true;
        clearInterval(keepalive);
        request.signal.removeEventListener("abort", stop);
        try {
          socket.close();
        } catch {}
        try {
          controller.close();
        } catch {}
      };

      write("retry: 3000\n\n");
      socket.onopen = () => socket.send(JSON.stringify({ type: "auth", token }));
      socket.onmessage = (message) => {
        if (typeof message.data !== "string") return;
        // One JSON object per line keeps the SSE framing trivially safe.
        write(`data: ${message.data.replace(/\n/g, " ")}\n\n`);
      };
      socket.onclose = stop;
      socket.onerror = stop;
      request.signal.addEventListener("abort", stop);
    },
    cancel() {
      stop();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
