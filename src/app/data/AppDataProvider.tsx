import { createContext, useEffect, useMemo, useRef, useState } from "react";
import type { AppData, AreaId, AreaNode, ComparisonRun, ScanId } from "./types";
import {
  chat,
  createProject as apiCreateProject,
  createReport,
  createRun,
  createZone,
  deleteScan,
  deleteZone,
  fetchDashboard,
  fetchRecommendations,
  fetchProjects,
  fetchReports,
  fetchRuns,
  fetchScans,
  fetchZones,
  fetchWorkDiary,
  patchZoneLinks,
  patchZone,
  syncSchedule,
  uploadScan,
} from "./api";

type AppDataContextValue = {
  data: AppData;
  isLoading: boolean;
  error?: string;
  projects: { id: string; name: string; createdAtISO: string }[];

  // Scans
  addScan: (file: File, capturedAtISO: string, notes?: string, zoneId?: string) => Promise<void>;
  removeScan: (scanId: ScanId) => Promise<void>;
  setSelectedT1: (scanId?: ScanId) => void;
  setSelectedT2: (scanId?: ScanId) => void;

      // Zones
      addArea: (name: string, type: AreaNode["type"], parentId?: AreaId) => Promise<string>;
  renameArea: (id: AreaId, name: string) => Promise<void>;
  removeArea: (id: AreaId) => Promise<void>;
  setAreaCompletion: (id: AreaId, completionPct: number) => Promise<void>;
  linkScanToArea: (id: AreaId, scanIds: string[]) => Promise<void>;

  // Comparison
  runComparison: () => Promise<void>;

  // Reports
  refreshReports: () => Promise<void>;
  generateReportForRun: (runId: string) => Promise<void>;

  // Chat
  sendChat: (prompt: string) => Promise<string>;

  // Dashboard
  refreshDashboard: () => Promise<void>;
  fetchRecommendations: () => Promise<string[]>;
  syncSchedule: (provider: "msproject" | "primavera", token: string) => Promise<any>;
  fetchWorkDiary: () => Promise<any>;
  setProjectId: (projectId: string) => void;
  createProject: (name: string) => Promise<string>;
  dashboard: {
    overallProgressPct: number;
    volumeChangeM3: number;
    forecastCompletionISO: string;
    productivityIndex: number;
    series: { t: string; progressPct: number }[];
  };
  reports: { id: string; createdAtISO: string; pdfUrl: string; xlsxUrl: string; runId: string }[];
};

export const AppDataContext = createContext<AppDataContextValue | null>(null);

export function AppDataProvider({ children }: { children: React.ReactNode }) {
  const [data, setData] = useState<AppData>({ scans: [], areas: [], runs: [] });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | undefined>(undefined);
  const [projects, setProjects] = useState<{ id: string; name: string; createdAtISO: string }[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string | undefined>(undefined);

  const [dashboard, setDashboard] = useState<AppDataContextValue["dashboard"]>({
    overallProgressPct: 0,
    volumeChangeM3: 0,
    forecastCompletionISO: "",
    productivityIndex: 1.0,
    series: [],
  });
  const [reports, setReports] = useState<AppDataContextValue["reports"]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const LS_PROJECT = "constrack_project";

  async function loadAll(projectId: string) {
    const [zones, scans, runs, dash, reps] = await Promise.all([
      fetchZones(projectId),
      fetchScans(projectId),
      fetchRuns(projectId),
      fetchDashboard(projectId),
      fetchReports(projectId),
    ]);

    setData((prev) => ({
      ...prev,
      projectId,
      areas: zones.map((z) => ({
        id: z.id,
        name: z.name,
        type: z.type as AreaNode["type"],
        parentId: z.parentId,
        completionPct: z.completionPct,
        linkedScanIds: z.linkedScanIds || [],
      })),
      scans: scans.map((s) => ({
        id: s.id,
        name: s.name,
        sizeBytes: s.sizeBytes,
        capturedAtISO: s.capturedAtISO,
        uploadedAtISO: s.uploadedAtISO,
        notes: s.notes,
      })),
      runs: (runs || []).map((r) => ({
        id: r.id,
        createdAtISO: r.createdAtISO,
        t1ScanId: r.t1ScanId,
        t2ScanId: r.t2ScanId,
        status: r.status,
        error: r.error,
        alignmentConfidence: r.alignmentConfidence || "medium",
        forecastCompletionISO: r.forecastCompletionISO || "",
        overallProgressPct: r.overallProgressPct || 0,
        volumeT1M3: r.volumeT1M3,
        volumeT2M3: r.volumeT2M3,
        volumeChangeM3: r.volumeChangeM3,
        metricsByArea: (r.metricsByZone || []).map((m: any) => ({
          areaId: m.zoneId,
          progressPct: m.progressPct,
          volumeChangeM3: m.volumeChangeM3,
          areaChangeM2: 0,
          workRatePerDay: 0,
          deviationDays: 0,
        })),
      })) as ComparisonRun[],
    }));

    setDashboard(dash);
    setReports(
      (reps || []).map((x) => ({
        id: x.id,
        createdAtISO: x.createdAtISO,
        pdfUrl: x.pdfUrl,
        xlsxUrl: x.xlsxUrl,
        runId: x.runId,
      }))
    );
  }

  useEffect(() => {
    (async () => {
      try {
        setError(undefined);
        const projectList = await fetchProjects();
        setProjects(projectList);
        const stored = localStorage.getItem(LS_PROJECT);
        const fallback = stored && projectList.find((p) => p.id === stored) ? stored : projectList[0]?.id;
        setActiveProjectId(fallback);
      } catch (e: any) {
        setError(String(e?.message || e));
      }
    })();
  }, []);

  useEffect(() => {
    if (!activeProjectId) return;
    localStorage.setItem(LS_PROJECT, activeProjectId);

    let cancelled = false;
    const setupWs = () => {
      try {
        wsRef.current?.close();
      } catch {
        // ignore
      }
      const ws = new WebSocket(`ws://localhost:4000/ws?projectId=${encodeURIComponent(activeProjectId)}`);
      ws.onmessage = async (ev) => {
        try {
          const msg = JSON.parse(String(ev.data));
          if (msg?.type === "run.done" || msg?.type === "run.created") {
            await loadAll(activeProjectId);
          }
        } catch {
          // ignore
        }
      };
      wsRef.current = ws;
    };

    (async () => {
      try {
        setIsLoading(true);
        await loadAll(activeProjectId);
        setupWs();
      } catch (e: any) {
        if (!cancelled) setError(String(e?.message || e));
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      try {
        wsRef.current?.close();
      } catch {
        // ignore
      }
    };
  }, [activeProjectId]);

  const api = useMemo<AppDataContextValue>(() => {
    const getProjectId = () => {
      const pid = activeProjectId || data.projectId;
      if (!pid) throw new Error("projectId not loaded");
      return pid;
    };

    return {
      data,
      isLoading,
      error,
      projects,
      dashboard,
      reports,
      setProjectId: (projectId) => setActiveProjectId(projectId),
      createProject: async (name) => {
        const trimmed = String(name || "").trim();
        if (trimmed.length < 2) throw new Error("Project name is required");
        const created = await apiCreateProject(trimmed);
        const projectList = await fetchProjects();
        setProjects(projectList);
        setActiveProjectId(created.id);
        return created.id;
      },

      addScan: async (file, capturedAtISO, notes, zoneId) => {
        const projectId = getProjectId();
        await uploadScan(projectId, file, capturedAtISO, notes, zoneId);
        await loadAll(projectId);
      },

      removeScan: async (scanId) => {
        const projectId = getProjectId();
        await deleteScan(scanId);
        setData((prev) => ({
          ...prev,
          selectedT1: prev.selectedT1 === scanId ? undefined : prev.selectedT1,
          selectedT2: prev.selectedT2 === scanId ? undefined : prev.selectedT2,
          areas: prev.areas.map(area => ({
            ...area,
            linkedScanIds: area.linkedScanIds?.filter(id => id !== scanId) || []
          }))
        }));
        await loadAll(projectId);
      },

      setSelectedT1: (scanId) => setData((p) => ({ ...p, selectedT1: scanId })),
      setSelectedT2: (scanId) => setData((p) => ({ ...p, selectedT2: scanId })),

      addArea: async (name, type, parentId) => {
        const projectId = getProjectId();
        const result = await createZone(projectId, { name, type, parentId });
        await loadAll(projectId);
        return result.id;
      },

      renameArea: async (id, name) => {
        const projectId = getProjectId();
        await patchZone(id, { name });
        await loadAll(projectId);
      },

      removeArea: async (id) => {
        const projectId = getProjectId();
        await deleteZone(id);
        await loadAll(projectId);
      },

      setAreaCompletion: async (id, completionPct) => {
        const projectId = getProjectId();
        await patchZone(id, { completionPct });
        await loadAll(projectId);
      },

      linkScanToArea: async (id, scanIds) => {
        const projectId = getProjectId();
        await patchZoneLinks(id, scanIds);
        await loadAll(projectId);
      },

      runComparison: async () => {
        const projectId = getProjectId();
        const t1 = data.selectedT1;
        const t2 = data.selectedT2;
        if (!t1 || !t2 || t1 === t2) throw new Error("Select two different scans");
        await createRun(projectId, t1, t2, 0.05);
        // results will arrive via websocket; refresh now anyway
        await loadAll(projectId);
      },

      refreshReports: async () => {
        const projectId = getProjectId();
        const reps = await fetchReports(projectId);
        setReports(
          (reps || []).map((x) => ({
            id: x.id,
            createdAtISO: x.createdAtISO,
            pdfUrl: x.pdfUrl,
            xlsxUrl: x.xlsxUrl,
            runId: x.runId,
          }))
        );
      },

      generateReportForRun: async (runId) => {
        const projectId = getProjectId();
        await createReport(projectId, runId);
        await loadAll(projectId);
      },

      sendChat: async (prompt) => {
        const r = await chat(prompt);
        return r.reply;
      },

      refreshDashboard: async () => {
        const projectId = getProjectId();
        setDashboard(await fetchDashboard(projectId));
      },

      fetchRecommendations: async () => {
        const projectId = getProjectId();
        const r = await fetchRecommendations(projectId);
        return r.recommendations;
      },

      syncSchedule: async (provider, token) => {
        const projectId = getProjectId();
        return syncSchedule(projectId, provider, token);
      },

      fetchWorkDiary: async () => {
        const projectId = getProjectId();
        return fetchWorkDiary(projectId);
      },
    };
  }, [data, isLoading, error, dashboard, reports, activeProjectId, projects]);

  return <AppDataContext.Provider value={api}>{children}</AppDataContext.Provider>;
}
