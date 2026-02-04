import { useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Select } from "../../components/ui/Select";
import { useAppData } from "../../app/data/useAppData";
import { formatBytes, formatDate } from "../../app/format";
import { useNavigate } from "react-router-dom";

export function UploadComparePage() {
  const { data, addScan, removeScan, setSelectedT1, setSelectedT2 } = useAppData();
  const navigate = useNavigate();
  const [capturedAtISO, setCapturedAtISO] = useState(() => new Date().toISOString().slice(0, 16));
  const [notes, setNotes] = useState("");
  const [zoneId, setZoneId] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);

  const canSelectT1 = useMemo(() => data.scans.some((s) => s.id === data.selectedT1), [data.scans, data.selectedT1]);
  const canSelectT2 = useMemo(() => data.scans.some((s) => s.id === data.selectedT2), [data.scans, data.selectedT2]);

  if (data.selectedT1 && !canSelectT1) setSelectedT1(undefined);
  if (data.selectedT2 && !canSelectT2) setSelectedT2(undefined);

  return (
    <div className="space-y-6">
      <div>
        <div className="text-2xl font-semibold">Scans</div>
        <div className="text-sm muted">Upload point clouds (t₁ and t₂) and select which scans to compare.</div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Upload scan" subtitle="Metadata only (prototype)" className="lg:col-span-1">
          <div className="space-y-3">
            <Input
              label="Captured date/time"
              type="datetime-local"
              value={capturedAtISO}
              onChange={(e) => setCapturedAtISO(e.target.value)}
            />
            <Input
              label="Notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Optional"
            />
            <Select
              label="Link to zone (optional)"
              value={zoneId}
              onChange={(e) => setZoneId(e.target.value)}
            >
              <option value="">No zone</option>
              {(data.areas || []).map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name} ({z.type})
                </option>
              ))}
            </Select>

            <label className="block">
              <div className="mb-1 text-sm muted">Point cloud file</div>
              <div className="mb-2 text-xs text-gray-500">
                Supported: LAS/LAZ (LiDAR point clouds), PLY, E57, PCD, XYZ, CSV
              </div>
              <input
                className="block w-full text-sm text-app file:mr-3 file:rounded-xl file:border file:border-app file:bg-app file:px-3 file:py-2 file:text-sm file:text-app"
                type="file"
                accept=".las,.laz,.ply,.e57,.pcd,.xyz,.txt,.csv"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  setFileError(null);
                  try {
                    const iso = new Date(capturedAtISO).toISOString();
                    addScan(f, iso, notes.trim() || undefined, zoneId || undefined).catch((err) => {
                      console.error("Upload error:", err);
                      setFileError(err.message || "Upload failed");
                    });
                    setNotes("");
                    setZoneId("");
                  } catch {
                    setFileError("Invalid captured date/time");
                  } finally {
                    e.target.value = "";
                  }
                }}
              />
              {fileError && <div className="mt-1 text-xs text-red-400">{fileError}</div>}
            </label>
          </div>
        </Card>

        <Card title="Active selection" subtitle="Choose scans for comparison" className="lg:col-span-2">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Select
              label="t₁ scan"
              value={data.selectedT1 ?? ""}
              onChange={(e) => setSelectedT1(e.target.value || undefined)}
            >
              <option value="">Select…</option>
              {data.scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({new Date(s.capturedAtISO).toLocaleDateString()})
                </option>
              ))}
            </Select>

            <Select
              label="t₂ scan"
              value={data.selectedT2 ?? ""}
              onChange={(e) => setSelectedT2(e.target.value || undefined)}
            >
              <option value="">Select…</option>
              {data.scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({new Date(s.capturedAtISO).toLocaleDateString()})
                </option>
              ))}
            </Select>
          </div>

          <div className="mt-4 text-sm muted">Tip: t₁ should be the earlier scan and t₂ the later scan.</div>
        </Card>
      </div>

      <Card title="Scan library" subtitle={`${data.scans.length} scans`}>
        {data.scans.length === 0 ? (
          <div className="text-sm muted">No scans yet. Upload your first scan above.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="muted">
                <tr className="border-b border-app">
                  <th className="text-left py-2 pr-3">Name</th>
                  <th className="text-left py-2 pr-3">Captured</th>
                  <th className="text-left py-2 pr-3">Size</th>
                  <th className="text-left py-2 pr-3">Notes</th>
                  <th className="text-left py-2 pr-3">Tags</th>
                  <th className="text-right py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.scans.map((s) => {
                  const isT1 = data.selectedT1 === s.id;
                  const isT2 = data.selectedT2 === s.id;
                  return (
                    <tr key={s.id} className="border-b border-app/60">
                      <td className="py-2 pr-3 font-medium text-app">{s.name}</td>
                      <td className="py-2 pr-3 text-app">{formatDate(s.capturedAtISO)}</td>
                      <td className="py-2 pr-3 text-app">{formatBytes(s.sizeBytes)}</td>
                      <td className="py-2 pr-3 text-app">{s.notes ?? "—"}</td>
                      <td className="py-2 pr-3">
                        <div className="flex gap-2">
                          {isT1 && <span className="text-xs px-2 py-1 rounded-full bg-zinc-100 text-zinc-900">t₁</span>}
                          {isT2 && <span className="text-xs px-2 py-1 rounded-full bg-zinc-100 text-zinc-900">t₂</span>}
                        </div>
                      </td>
                      <td className="py-2 text-right">
                        <div className="flex gap-2 justify-end">
                          <Button className="w-auto" variant="secondary" onClick={() => setSelectedT1(s.id)}>
                            Set t₁
                          </Button>
                          <Button className="w-auto" variant="secondary" onClick={() => setSelectedT2(s.id)}>
                            Set t₂
                          </Button>
                          <Button 
                            className="w-auto" 
                            variant="secondary" 
                            onClick={() => {
                              setSelectedT2(s.id);
                              navigate('/model');
                            }}
                          >
                            View 3D
                          </Button>
                          <Button className="w-auto" variant="secondary" onClick={() => void removeScan(s.id)}>
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
