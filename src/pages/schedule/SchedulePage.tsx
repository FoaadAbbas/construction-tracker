import { useEffect, useState } from "react";
import { Card } from "../../components/ui/Card";
import { Input } from "../../components/ui/Input";
import { Select } from "../../components/ui/Select";
import { Button } from "../../components/ui/Button";
import { useAppData } from "../../app/data/useAppData";
import type { ScheduleTask, WorkDiaryEntry } from "../../app/data/types";
import { formatDate } from "../../app/format";

export function SchedulePage() {
  const { syncSchedule, fetchWorkDiary, data } = useAppData();
  const [provider, setProvider] = useState<"msproject" | "primavera">("msproject");
  const [token, setToken] = useState("");
  const [tasks, setTasks] = useState<ScheduleTask[]>([]);
  const [diary, setDiary] = useState<WorkDiaryEntry[]>([]);
  const [status, setStatus] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(false);

  const handleSync = async () => {
    setLoading(true);
    setStatus("Syncing schedule…");
    try {
      const res = await syncSchedule(provider, token || "demo-token");
      setTasks(res.tasks || []);
      setStatus(`Pulled ${res.tasks?.length ?? 0} tasks from ${provider === "msproject" ? "MS Project" : "Primavera"}`);
    } catch (e: any) {
      setStatus(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  const loadDiary = async () => {
    try {
      const res = await fetchWorkDiary();
      setDiary(res.entries || []);
    } catch {
      // ignore for now
    }
  };

  useEffect(() => {
    loadDiary();
  }, [data.projectId]);

  return (
    <div className="space-y-6">
      <div>
        <div className="text-2xl font-semibold">Schedule & Work Diary</div>
        <div className="text-sm muted">
          Connect MS Project or Primavera to pull schedule tasks and align them with daily work diaries.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Integration" subtitle="Bring schedule + diary into the dashboard">
          <div className="space-y-3">
            <Select label="Provider" value={provider} onChange={(e) => setProvider(e.target.value as any)}>
              <option value="msproject">MS Project API</option>
              <option value="primavera">Primavera</option>
            </Select>
            <Input
              label="API token"
              placeholder="Paste token (kept client-side for demo)"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
            <Button onClick={handleSync} disabled={loading}>
              {loading ? "Syncing…" : "Sync schedule"}
            </Button>
            {status && <div className="text-xs muted">{status}</div>}
          </div>
        </Card>

        <Card title="Latest Tasks" subtitle="Top 5 critical items" className="lg:col-span-2">
          {tasks.length === 0 ? (
            <div className="text-sm muted">No tasks synced yet.</div>
          ) : (
            <div className="space-y-2">
              {tasks.slice(0, 5).map((t) => (
                <div
                  key={t.id}
                  className="rounded-xl border border-app p-3 flex items-center justify-between"
                >
                  <div>
                    <div className="font-medium">{t.name}</div>
                    <div className="text-xs muted">
                      {formatDate(t.start)} → {formatDate(t.finish)} · Owner: {t.owner}
                    </div>
                  </div>
                  <div className="text-sm">
                    <span className="muted mr-1">Prog</span>
                    <span className="font-semibold">{t.progressPct}%</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card title="Work diary (latest)" subtitle="Automatic feed for field updates">
        {diary.length === 0 ? (
          <div className="text-sm muted">No diary entries yet.</div>
        ) : (
          <div className="space-y-3">
            {diary.map((d) => (
              <div key={d.id} className="rounded-xl border border-app p-3">
                <div className="flex items-center justify-between">
                  <div className="font-medium">{d.crew}</div>
                  <div className="text-xs muted">{formatDate(d.dateISO)}</div>
                </div>
                <div className="text-sm mt-1 text-app">{d.summary}</div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
