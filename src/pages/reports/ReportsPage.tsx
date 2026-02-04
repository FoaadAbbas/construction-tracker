import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { useAppData } from "../../app/data/useAppData";
import { formatDate } from "../../app/format";

export function ReportsPage() {
  const { data, reports, generateReportForRun } = useAppData();
  const latest = data.runs[0];

  return (
    <div className="space-y-6">
      <div>
        <div className="text-2xl font-semibold">Reports</div>
        <div className="text-sm muted">Generate real PDF and Excel reports from comparison runs.</div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Quick generate" subtitle={latest ? `Latest run: ${formatDate(latest.createdAtISO)}` : "No runs yet"}>
          {!latest ? (
            <div className="text-sm muted">Run a comparison first to generate a report.</div>
          ) : (
            <div className="space-y-3">
              <div className="text-sm muted">
                This will generate and store a PDF + XLSX on the backend, and you can download them from report history.
              </div>
              <Button onClick={() => void generateReportForRun(latest.id)}>Generate PDF + Excel</Button>
            </div>
          )}
        </Card>

        <Card title="Report history" subtitle={`${reports.length} reports`} className="lg:col-span-2">
          {reports.length === 0 ? (
            <div className="text-sm muted">No reports yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="muted">
                  <tr className="border-b border-app">
                    <th className="text-left py-2 pr-3">Created</th>
                    <th className="text-left py-2 pr-3">Run</th>
                    <th className="text-right py-2">Downloads</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.id} className="border-b border-app/60">
                      <td className="py-2 pr-3 text-app">{formatDate(r.createdAtISO)}</td>
                      <td className="py-2 pr-3 text-app">{r.runId}</td>
                      <td className="py-2 text-right">
                        <div className="flex gap-2 justify-end">
                          <a
                            className="rounded-xl border border-app px-3 py-2 text-sm"
                            href={r.pdfUrl}
                            target="_blank"
                            rel="noreferrer"
                          >
                            PDF
                          </a>
                          <a
                            className="rounded-xl border border-app px-3 py-2 text-sm"
                            href={r.xlsxUrl}
                            target="_blank"
                            rel="noreferrer"
                          >
                            Excel
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
