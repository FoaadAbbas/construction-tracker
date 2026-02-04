import { useEffect, useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { useNavigate } from "react-router-dom";
import { useAppData } from "../../app/data/useAppData";
import { formatDate } from "../../app/format";

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-2xl border border-app surface-2 p-4">
      <div className="text-sm muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs muted">{hint}</div>}
    </div>
  );
}

export function DashboardPage() {
  const nav = useNavigate();
  const { data, dashboard, fetchRecommendations } = useAppData();
  const latest = data.runs[0];

  const overall = `${Math.round(dashboard.overallProgressPct)}%`;
  const volumeChange = `${dashboard.volumeChangeM3.toFixed(3)} m³`;
  const forecast = dashboard.forecastCompletionISO ? formatDate(dashboard.forecastCompletionISO) : "—";
  const productivity = dashboard.productivityIndex ? dashboard.productivityIndex.toFixed(2) : "1.00";

  const [recs, setRecs] = useState<string[]>([]);
  const [recStatus, setRecStatus] = useState<string>("Loading recommendations…");

  useEffect(() => {
    (async () => {
      try {
        setRecStatus("Loading recommendations…");
        const r = await fetchRecommendations();
        setRecs(r);
        setRecStatus("");
      } catch (e: any) {
        setRecStatus(String(e?.message || e));
      }
    })();
  }, [data.projectId, fetchRecommendations]);

  const trendPath = useMemo(() => {
    const series = dashboard.series || [];
    if (!series.length) return "";
    const values = series.map((p) => p.progressPct);
    const max = Math.max(100, ...values);
    const min = Math.min(0, ...values);
    const range = Math.max(1, max - min);
    const width = 320;
    const height = 140;
    return series
      .map((p, i) => {
        const x = (i / Math.max(1, series.length - 1)) * width;
        const y = height - ((p.progressPct - min) / range) * height;
        return `${i === 0 ? "M" : "L"}${x},${y}`;
      })
      .join(" ");
  }, [dashboard.series]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-2xl font-semibold">Overview</div>
          <div className="text-sm muted">
            Decision support summary based on the latest comparison run.
          </div>
        </div>

        <div className="flex gap-2">
          <Button className="w-auto" variant="secondary" onClick={() => nav("/scans")}>
            Upload scans
          </Button>
          <Button className="w-auto" onClick={() => nav("/compare")}>Run compare</Button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Kpi label="Overall progress" value={overall} hint="Completion percentage" />
        <Kpi label="Volume change" value={volumeChange} hint="Between baseline and latest scan" />
        <Kpi label="Forecast completion date" value={forecast} hint="Estimated project finish" />
        <Kpi label="Productivity index" value={productivity} hint="Higher is better" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card
          title="Latest run"
          subtitle={latest ? `Created: ${formatDate(latest.createdAtISO)}` : "No runs yet"}
          className="lg:col-span-2"
          right={
            <Button className="w-auto" variant="secondary" onClick={() => nav("/reports")}>
              View reports
            </Button>
          }
        >
          {!latest ? (
            <div className="text-sm muted">
              To see KPIs, select two scans (t₁, t₂) and run a comparison.
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="muted">t₁ scan</div>
                  <div className="font-medium">{data.scans.find((s) => s.id === latest.t1ScanId)?.name ?? "—"}</div>
                </div>
                <div>
                  <div className="muted">t₂ scan</div>
                  <div className="font-medium">{data.scans.find((s) => s.id === latest.t2ScanId)?.name ?? "—"}</div>
                </div>
              </div>

              <div className="rounded-xl border border-app surface-2 p-3">
                <div className="text-sm muted mb-2">Progress by zone (heat list)</div>
                <div className="space-y-2">
                  {latest.metricsByArea.slice(0, 6).map((m) => {
                    const areaName = data.areas.find((a) => a.id === m.areaId)?.name ?? `Zone ${m.areaId}`;
                    return (
                      <div key={m.areaId} className="flex items-center gap-3">
                        <div className="w-40 truncate text-sm">{areaName}</div>
                        <div className="flex-1 h-2 rounded surface-2 overflow-hidden">
                          <div className="h-2 accent" style={{ width: `${m.progressPct}%` }} />
                        </div>
                        <div className="w-12 text-right text-sm muted">{m.progressPct}%</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </Card>

        <Card title="Setup checklist" subtitle="Finish these for a complete demo">
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-app">Upload scans</span>
              <span className={data.scans.length ? "text-emerald-400" : "muted"}>
                {data.scans.length ? "Done" : "Missing"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-app">Select t₁ + t₂</span>
              <span className={data.selectedT1 && data.selectedT2 ? "text-emerald-400" : "muted"}>
                {data.selectedT1 && data.selectedT2 ? "Done" : "Missing"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-app">Define zones</span>
              <span className={data.areas.some((a) => a.type === "zone") ? "text-emerald-400" : "muted"}>
                {data.areas.some((a) => a.type === "zone") ? "Done" : "Optional"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-app">Run comparison</span>
              <span className={latest ? "text-emerald-400" : "muted"}>{latest ? "Done" : "Missing"}</span>
            </div>

            <div className="pt-2">
              <Button className="w-full" onClick={() => nav("/compare")}>
                Go to Compare
              </Button>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Progress trend" subtitle="Latest comparison runs" className="lg:col-span-2">
          {trendPath ? (
            <div className="space-y-2">
              <svg viewBox="0 0 320 150" className="w-full">
                <path d={trendPath} fill="none" stroke="var(--accent)" strokeWidth="3" />
              </svg>
              <div className="text-xs muted">Shows overall progress % over time.</div>
            </div>
          ) : (
            <div className="text-sm muted">Run a comparison to see the progress chart.</div>
          )}
        </Card>

        <Card title="AI recommendations" subtitle="Gemini-powered" className="lg:col-span-1">
          {recStatus && <div className="text-xs muted">{recStatus}</div>}
          <div className="space-y-2 mt-1">
            {recs.map((r, idx) => (
              <div key={idx} className="rounded-lg border border-app p-3 text-sm">
                {r}
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
