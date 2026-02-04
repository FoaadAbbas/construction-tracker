import type { WebSocketServer, WebSocket } from "ws";

type Client = { ws: WebSocket; projectId?: string };

const clients: Client[] = [];

export function registerWs(wss: WebSocketServer) {
  wss.on("connection", (ws, req) => {
    const url = new URL(req.url || "", "http://localhost");
    const projectId = url.searchParams.get("projectId") || undefined;
    const client: Client = { ws, projectId };
    clients.push(client);

    ws.on("close", () => {
      const idx = clients.indexOf(client);
      if (idx >= 0) clients.splice(idx, 1);
    });
  });
}

export function publish(projectId: string, event: unknown) {
  const msg = JSON.stringify(event);
  for (const c of clients) {
    if (c.projectId && c.projectId !== projectId) continue;
    if (c.ws.readyState === c.ws.OPEN) {
      c.ws.send(msg);
    }
  }
}
