import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { useAppData } from "../../app/data/useAppData";
import { formatDate } from "../../app/format";

function ConfidenceBadge({ v }: { v: string }) {
  const cls = v === "high"
    ? "bg-emerald-400 text-zinc-900"
    : v === "medium"
    ? "bg-amber-400 text-zinc-900"
    : "bg-red-400 text-zinc-900";
  return <span className={["text-xs px-2 py-1 rounded-full", cls].join(" ")}>{v}</span>;
}

export function ComparePage() {
  const nav = useNavigate();
  const { data, runComparison } = useAppData();
  const t1 = data.scans.find((s) => s.id === data.selectedT1);
  const t2 = data.scans.find((s) => s.id === data.selectedT2);
  const latest = data.runs[0];

  const canRun = !!t1 && !!t2 && t1.id !== t2.id;

  const leafAreaCount = useMemo(() => data.areas.filter((a) => a.type === "zone").length, [data.areas]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-2xl font-semibold">Compare</div>
          <div className="text-sm muted">Run a comparison between t₁ and t₂ and generate KPIs + forecasts.</div>
        </div>
        <Button className="w-auto" variant="secondary" onClick={() => nav("/reports")}>Reports</Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Inputs" subtitle="Select scans + areas">
          <div className="space-y-3 text-sm">
            <div>
              <div className="muted">t₁</div>
              <div className="font-medium">{t1 ? t1.name : "Not selected"}</div>
            </div>
            <div>
              <div className="muted">t₂</div>
              <div className="font-medium">{t2 ? t2.name : "Not selected"}</div>
            </div>
            <div>
              <div className="muted">Defined leaf areas</div>
              <div className="font-medium">{leafAreaCount}</div>
            </div>

            <div className="pt-2 flex gap-2">
              <Button className="w-auto" variant="secondary" onClick={() => nav("/scans")}>Manage scans</Button>
              <Button className="w-auto" variant="secondary" onClick={() => nav("/areas")}>Manage zones</Button>
            </div>
          </div>
        </Card>

        <Card title="Run" subtitle="Compute volume delta + progress">
          <div className="text-sm muted">
            Runs an async backend job (Python) to compute volume(T1), volume(T2), ΔV, and progress metrics.
          </div>

          <div className="mt-4">
              <Button
                disabled={!canRun}
                onClick={() => {
                  void runComparison().catch(() => void 0);
                }}
              >
              Run comparison
            </Button>
            {!canRun && (
              <div className="mt-2 text-xs text-red-400">
                Select two different scans (t₁ and t₂) first.
              </div>
            )}
          </div>
        </Card>

        <Card title="Latest output" subtitle={latest ? formatDate(latest.createdAtISO) : "No runs yet"}>
          {!latest ? (
            <div className="text-sm muted">Run a comparison to generate outputs.</div>
          ) : (
            <div className="space-y-3 text-sm">
              {latest.status && latest.status !== "done" && (
                <div className="rounded-xl border border-app surface-2 p-3 text-app">
                  Status: <span className="font-semibold">{latest.status}</span>
                  {latest.status === "failed" && latest.error ? (
                    <div className="mt-2 text-xs text-red-400">{latest.error}</div>
                  ) : null}
                </div>
              )}
              <div className="flex items-center justify-between">
                <span className="muted">Overall progress</span>
                <span className="font-semibold">{latest.overallProgressPct}%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="muted">Volume change</span>
                <span className="font-semibold">{(latest.volumeChangeM3 ?? 0).toFixed(3)} m³</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="muted">Forecast completion</span>
                <span className="font-semibold">{formatDate(latest.forecastCompletionISO)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="muted">Alignment confidence</span>
                <ConfidenceBadge v={latest.alignmentConfidence} />
              </div>
              <div className="pt-2">
                <Button className="w-full" variant="secondary" onClick={() => nav("/reports")}>Open report</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
