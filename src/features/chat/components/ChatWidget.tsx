import type { FormEvent } from "react";
import { useState } from "react";
import { useAppData } from "../../../app/data/useAppData";

type Msg = { from: "user" | "ai"; text: string };

export function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([
    { from: "ai", text: "Hi, I'm powered by Gemini. Ask me about progress or schedule." },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const { sendChat } = useAppData();

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    const prompt = input.trim();
    setMessages((m) => [...m, { from: "user", text: prompt }]);
    setInput("");
    setSending(true);
    try {
      const reply = await sendChat(prompt);
      setMessages((m) => [...m, { from: "ai", text: reply }]);
    } catch (err: any) {
      setMessages((m) => [...m, { from: "ai", text: `Error: ${err?.message || err}` }]);
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <button
        onClick={() => setOpen((v) => !v)}
        className="fixed bottom-4 right-4 w-12 h-12 rounded-full accent font-semibold shadow"
      >
        AI
      </button>

      {open && (
        <div className="fixed bottom-20 right-4 w-[92vw] max-w-sm rounded-2xl border border-app bg-app shadow-xl overflow-hidden">
          <div className="p-3 border-b border-app flex items-center justify-between">
            <div className="text-sm font-medium">Assistant</div>
            <button onClick={() => setOpen(false)} className="muted text-sm">
              Close
            </button>
          </div>
          <div className="p-3 h-72 overflow-auto text-sm text-app space-y-2">
            {messages.map((m, i) => (
              <div
                key={i}
                className={`rounded-xl px-3 py-2 border ${
                  m.from === "user" ? "border-app" : "border-app surface-2"
                }`}
              >
                <div className="text-xs muted">{m.from === "user" ? "You" : "Gemini"}</div>
                <div className="whitespace-pre-wrap">{m.text}</div>
              </div>
            ))}
          </div>
          <form className="p-3 border-t border-app flex gap-2" onSubmit={onSubmit}>
            <input
              className="flex-1 rounded-xl border border-app bg-app px-3 py-2 text-sm outline-none"
              placeholder="Ask about progress, risks, schedule..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={sending}
            />
            <button
              type="submit"
              disabled={sending}
              className="rounded-xl px-3 py-2 text-sm border border-app bg-app"
            >
              {sending ? "…" : "Send"}
            </button>
          </form>
        </div>
      )}
    </>
  );
}
