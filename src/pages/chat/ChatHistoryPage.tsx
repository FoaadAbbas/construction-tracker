import { useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { useAppData } from "../../app/data/useAppData";

type ChatMsg = {
  id: string;
  role: "user" | "assistant";
  text: string;
  createdAtISO: string;
};

function uid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export function ChatHistoryPage() {
  const { sendChat } = useAppData();
  const [prompt, setPrompt] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [msgs, setMsgs] = useState<ChatMsg[]>(() => [
    {
      id: uid(),
      role: "assistant",
      text:
        "Hi. Ask me about your project progress, scans, zones, or reports. (Gemini API wiring can be added next.)",
      createdAtISO: new Date().toISOString(),
    },
  ]);

  const canSend = useMemo(() => prompt.trim().length >= 1 && !isSending, [prompt, isSending]);

  async function onSend() {
    const p = prompt.trim();
    if (!p) return;
    setPrompt("");
    setIsSending(true);

    const userMsg: ChatMsg = { id: uid(), role: "user", text: p, createdAtISO: new Date().toISOString() };
    setMsgs((m) => [...m, userMsg]);

    try {
      const reply = await sendChat(p);
      const botMsg: ChatMsg = { id: uid(), role: "assistant", text: reply, createdAtISO: new Date().toISOString() };
      setMsgs((m) => [...m, botMsg]);
    } catch (e: any) {
      const botMsg: ChatMsg = {
        id: uid(),
        role: "assistant",
        text: `Error: ${String(e?.message || e)}`,
        createdAtISO: new Date().toISOString(),
      };
      setMsgs((m) => [...m, botMsg]);
    } finally {
      setIsSending(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="text-2xl font-semibold">Chatbot</div>
        <div className="text-sm muted">Backend endpoint is ready. Next step is plugging Gemini API.</div>
      </div>

      <Card title="Conversation" subtitle={`${msgs.length} messages`}>
        <div className="space-y-3">
          <div className="h-[52vh] overflow-y-auto rounded-xl border border-app surface-2 p-3">
            <div className="space-y-3">
              {msgs.map((m) => (
                <div key={m.id} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                  <div
                    className={[
                      "max-w-[85%] rounded-2xl px-3 py-2 text-sm border",
                      m.role === "user"
                        ? "bg-app text-app border-app"
                        : "surface-2 text-app border-app",
                    ].join(" ")}
                  >
                    <div className="whitespace-pre-wrap">{m.text}</div>
                    <div className="mt-1 text-[10px] muted">
                      {new Date(m.createdAtISO).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-end">
            <Input
              label="Message"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Ask something…"
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void onSend();
                }
              }}
            />

            <Button className="w-auto" disabled={!canSend} onClick={() => void onSend()}>
              {isSending ? "Sending…" : "Send"}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
