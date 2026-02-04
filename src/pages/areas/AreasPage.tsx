import { useMemo, useState } from "react";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Select } from "../../components/ui/Select";
import { useAppData } from "../../app/data/useAppData";
import type { AreaId, AreaNode } from "../../app/data/types";

function buildTree(nodes: AreaNode[]) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const children = new Map<AreaId, AreaNode[]>();
  for (const n of nodes) {
    if (!n.parentId) continue;
    const arr = children.get(n.parentId) ?? [];
    arr.push(n);
    children.set(n.parentId, arr);
  }
  // stable order
  for (const [k, arr] of children) {
    arr.sort((a, b) => a.name.localeCompare(b.name));
    children.set(k, arr);
  }
  return { byId, children };
}

export function AreasPage() {
  const { data, addArea, renameArea, removeArea, setAreaCompletion, linkScanToArea, createProject } = useAppData();
  const tree = useMemo(() => buildTree(data.areas), [data.areas]);

  const siteRoot = data.areas.find((a) => a.type === "site");
  const [createParentId, setCreateParentId] = useState<string>(siteRoot?.id ?? "");
  const [createType, setCreateType] = useState<string>("floor");
  const [createName, setCreateName] = useState("");
  const [isAdding, setIsAdding] = useState(false);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");

  const allParents = data.areas.filter((a) => a.type !== "zone");

  const canCreate = createName.trim().length >= 2 && !!createParentId;

  const [linkChoice, setLinkChoice] = useState<Record<string, string>>({});

  const renderNode = (node: AreaNode, depth: number) => {
    const kids = tree.children.get(node.id) ?? [];
    const isEditing = editingId === node.id;
    const linkedScans = node.linkedScanIds || [];

    return (
      <div key={node.id}>
        <div
          className={[
            "flex items-center justify-between gap-3 rounded-xl border border-app bg-app px-3 py-2",
            depth === 0 ? "" : "mt-2",
          ].join(" ")}
          style={{ marginLeft: depth * 14 }}
        >
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs px-2 py-0.5 rounded-full border border-app">
                {node.type}
              </span>
              {isEditing ? (
                <input
                  autoFocus
                  className="bg-transparent border-b border-app outline-none text-sm w-64"
                  value={editingName}
                  onChange={(e) => setEditingName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      renameArea(node.id, editingName.trim() || node.name);
                      setEditingId(null);
                    }
                    if (e.key === "Escape") setEditingId(null);
                  }}
                />
              ) : (
                <span className="font-medium truncate">{node.name}</span>
              )}
              {node.type === "zone" && (
                <span className="text-xs px-2 py-0.5 rounded-full border border-app">
                  {Math.round((node.completionPct ?? 0) * 10) / 10}%
                </span>
              )}
            </div>
            <div className="text-xs muted">
              {kids.length ? `${kids.length} child nodes` : "Leaf"}
            </div>
          </div>

          <div className="flex gap-2 shrink-0">
            {isEditing ? (
              <>
                <Button
                  className="w-auto"
                  variant="secondary"
                  onClick={() => {
                    renameArea(node.id, editingName.trim() || node.name);
                    setEditingId(null);
                  }}
                >
                  Save
                </Button>
                <Button className="w-auto" variant="secondary" onClick={() => setEditingId(null)}>
                  Cancel
                </Button>
              </>
            ) : (
              <>
                <Button
                  className="w-auto"
                  variant="secondary"
                  onClick={() => {
                    setEditingId(node.id);
                    setEditingName(node.name);
                  }}
                >
                  Rename
                </Button>
                {node.type === "zone" && (
                  <Button
                    className="w-auto"
                    variant="secondary"
                    onClick={() => {
                      const cur = node.completionPct ?? 0;
                      const raw = window.prompt("Set completion percentage (0-100)", String(cur));
                      if (raw == null) return;
                      const v = Number(raw);
                      if (!Number.isFinite(v)) return;
                      setAreaCompletion(node.id, Math.max(0, Math.min(100, v)));
                    }}
                  >
                    Set %
                  </Button>
                )}
                {node.type !== "site" && (
                  <Button
                    className="w-auto"
                    variant="secondary"
                    onClick={() => {
                      const ok = window.confirm(`Delete "${node.name}" and all its child nodes?`);
                      if (!ok) return;
                      removeArea(node.id);
                    }}
                  >
                    Delete
                  </Button>
                )}
              </>
            )}
          </div>
        </div>

        {(linkedScans.length > 0 || data.scans.length > 0) && (
          <div className="mt-2 space-y-2" style={{ marginLeft: depth * 14 + 8 }}>
            <div className="text-xs muted">Linked scans</div>
            <div className="flex flex-wrap gap-2">
              {linkedScans.length === 0 && <span className="text-xs muted">No scans linked.</span>}
              {linkedScans.map((sid) => {
                const scan = data.scans.find((s) => s.id === sid);
                return (
                  <span key={sid} className="text-xs rounded-full border border-app px-2 py-1 flex items-center gap-2">
                    {scan?.name || sid}
                    <button
                      className="text-[10px] muted"
                      onClick={() =>
                        linkScanToArea(
                          node.id,
                          linkedScans.filter((x) => x !== sid)
                        )
                      }
                    >
                      ×
                    </button>
                  </span>
                );
              })}
            </div>
            {data.scans.length > 0 && (
              <div className="flex items-center gap-2">
                <select
                  className="rounded-lg border border-app bg-app px-3 py-2 text-sm"
                  value={linkChoice[node.id] || ""}
                  onChange={(e) => setLinkChoice((prev) => ({ ...prev, [node.id]: e.target.value }))}
                >
                  <option value="">Choose scan</option>
                  {data.scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
                <Button
                  className="w-auto"
                  disabled={!linkChoice[node.id]}
                  onClick={() => {
                    const chosen = linkChoice[node.id];
                    if (!chosen) return;
                    const next = Array.from(new Set([...linkedScans, chosen]));
                    linkScanToArea(node.id, next);
                  }}
                >
                  Link scan
                </Button>
              </div>
            )}
          </div>
        )}

        {kids.map((k) => renderNode(k, depth + 1))}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-2xl font-semibold">Zones & Site Map</div>
          <div className="text-sm muted">
          Define your site hierarchy (floors, wings, zones). This enables progress KPIs even without a BIM model.
          </div>
        </div>

        <Button
          className="w-auto"
          variant="secondary"
          onClick={async () => {
            const name = window.prompt("New project name");
            if (!name) return;
            await createProject(name);
          }}
        >
          Create new project
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Create node" subtitle="Fast setup for demo">
          <div className="space-y-3">
            <Select label="Parent" value={createParentId} onChange={(e) => setCreateParentId(e.target.value)}>
              {allParents.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.type})
                </option>
              ))}
            </Select>

            <Input
              label="Type"
              value={createType}
              onChange={(e) => setCreateType(e.target.value)}
              placeholder="e.g., floor, wing, zone, room, section"
            />

            <Input label="Name" value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="e.g., Floor 2" />

            <Button
              disabled={!canCreate || isAdding}
              onClick={async () => {
                setIsAdding(true);
                try {
                  await addArea(createName.trim(), createType as any, createParentId || undefined);
                  setCreateName("");
                } finally {
                  setIsAdding(false);
                }
              }}
            >
              {isAdding ? "Adding..." : "Add"}
            </Button>

            <div className="text-xs muted">
              Recommended: Site → Floor → Wing → Zone. Only leaf nodes (type: zone) get progress metrics.
            </div>
          </div>
        </Card>

        <Card title="Zone tree" subtitle={`${data.areas.length} nodes`} className="lg:col-span-2">
          {siteRoot ? (
            <div>{renderNode(siteRoot, 0)}</div>
          ) : (
            <div className="text-sm muted">No site root found.</div>
          )}
        </Card>
      </div>
    </div>
  );
}
