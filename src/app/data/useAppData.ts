import { useContext } from "react";
import { AppDataContext } from "./AppDataProvider";

export function useAppData() {
  const ctx = useContext(AppDataContext);
  if (!ctx) {
    // During hot reload or initialization, return a safe default
    return {
      data: { scans: [], areas: [], runs: [], selectedT1: undefined, selectedT2: undefined, projectId: undefined },
      isLoading: true,
      error: undefined,
      projects: [],
      addScan: () => Promise.resolve(),
      removeScan: () => Promise.resolve(),
      setSelectedT1: () => {},
      setSelectedT2: () => {},
      addArea: () => Promise.resolve(""),
      renameArea: () => Promise.resolve(),
      removeArea: () => Promise.resolve(),
      setAreaCompletion: () => Promise.resolve(),
      linkScanToArea: () => Promise.resolve(),
      runComparison: () => Promise.resolve(),
      refreshReports: () => Promise.resolve(),
      generateReportForRun: () => Promise.resolve(),
      sendChat: () => Promise.resolve(""),
      refreshDashboard: () => Promise.resolve(),
      fetchRecommendations: () => Promise.resolve([]),
      syncSchedule: () => Promise.resolve(null),
      fetchWorkDiary: () => Promise.resolve(null),
      setProjectId: () => {},
      createProject: () => Promise.resolve(""),
      dashboard: {
        overallProgressPct: 0,
        volumeChangeM3: 0,
        forecastCompletionISO: "",
        productivityIndex: 0,
        series: [],
      },
      reports: [],
    };
  }
  return ctx;
}
