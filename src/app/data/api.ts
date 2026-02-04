export type ApiConfig = {
  projectId?: string;
};

const API_BASE = import.meta.env.VITE_API_BASE || '';

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem("constrack_token");
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const fullPath = API_BASE + path;
  const res = await fetch(fullPath, {
    ...init,
    headers,
  });
  const txt = await res.text();
  const json = txt ? JSON.parse(txt) : null;

  // Handle authentication errors
  if (res.status === 401 || res.status === 403) {
    // Don't redirect if we're already on auth pages
    const currentPath = window.location.pathname;
    if (currentPath.startsWith('/login') || currentPath.startsWith('/register') || currentPath.startsWith('/forgot-password')) {
      throw new Error(json?.error || "Authentication required");
    }

    // Token is invalid or expired, clear auth data
    localStorage.removeItem("constrack_token");
    localStorage.removeItem("constrack_user");
    window.location.href = "/login";
    throw new Error("Authentication required");
  }

  if (!res.ok) {
    const msg = json?.error || res.statusText || "Request failed";
    throw new Error(msg);
  }
  return json as T;
}

export async function fetchProjects() {
  return api<{ id: string; name: string; createdAtISO: string }[]>("/api/projects");
}

export async function createProject(name: string) {
  return api<{ id: string; name: string; createdAtISO: string }>("/api/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
}

export async function fetchZones(projectId: string) {
  return api<
    {
      id: string;
      projectId: string;
      name: string;
      type: string;
      parentId?: string;
      completionPct: number;
      linkedScanIds?: string[];
    }[]
  >(`/api/zones?projectId=${encodeURIComponent(projectId)}`);
}

export async function createZone(projectId: string, body: { name: string; type: string; parentId?: string }) {
  return api<{ id: string; projectId: string; name: string; type: string; parentId?: string; completionPct: number }>(`/api/zones`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ projectId, ...body }),
  });
}

export async function patchZone(id: string, body: { name?: string; completionPct?: number }) {
  return api(`/api/zones/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function patchZoneLinks(id: string, linkedScanIds: string[]) {
  return api(`/api/zones/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ linkedScanIds }),
  });
}

export async function deleteZone(id: string) {
  return api(`/api/zones/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function fetchScans(projectId: string) {
  return api<{ id: string; name: string; sizeBytes: number; capturedAtISO: string; uploadedAtISO: string; notes?: string }[]>(
    `/api/scans?projectId=${encodeURIComponent(projectId)}`
  );
}

export async function uploadScan(projectId: string, file: File, capturedAtISO: string, notes?: string, zoneId?: string) {
  const fd = new FormData();
  fd.append("projectId", projectId);
  fd.append("capturedAtISO", capturedAtISO);
  if (notes) fd.append("notes", notes);
  if (zoneId) fd.append("zoneId", zoneId);
  fd.append("file", file);

  const token = localStorage.getItem("constrack_token");
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/api/scans/upload`, {
    method: "POST",
    body: fd,
    headers
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json?.error || res.statusText);
  return json as { id: string; name: string; sizeBytes: number; capturedAtISO: string; uploadedAtISO: string; notes?: string };
}

export async function deleteScan(id: string) {
  return api(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function fetchRuns(projectId: string) {
  return api<any[]>(`/api/runs?projectId=${encodeURIComponent(projectId)}`);
}

export async function createRun(projectId: string, t1ScanId: string, t2ScanId: string, voxelSize?: number) {
  return api<{ id: string; status: string }>(`/api/runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ projectId, t1ScanId, t2ScanId, voxelSize }),
  });
}

export async function fetchDashboard(projectId: string) {
  return api<{ overallProgressPct: number; volumeChangeM3: number; forecastCompletionISO: string; productivityIndex: number; series: { t: string; progressPct: number }[] }>(
    `/api/dashboard?projectId=${encodeURIComponent(projectId)}`
  );
}

export async function fetchReports(projectId: string) {
  return api<any[]>(`/api/reports?projectId=${encodeURIComponent(projectId)}`);
}

export async function createReport(projectId: string, runId: string) {
  return api<any>(`/api/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ projectId, runId }),
  });
}

export async function chat(prompt: string) {
  return api<{ reply: string }>(`/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt }),
  });
}

export async function fetchRecommendations(projectId: string) {
  return api<{ recommendations: string[] }>(`/api/recommendations?projectId=${encodeURIComponent(projectId)}`);
}

export async function syncSchedule(
  projectId: string,
  provider: "msproject" | "primavera",
  token: string
) {
  return api<{
    provider: string;
    status: string;
    fetchedAtISO: string;
    tasks: {
      id: string;
      providerId: string;
      name: string;
      start: string;
      finish: string;
      progressPct: number;
      owner: string;
      critical: boolean;
    }[];
  }>(`/api/schedule/sync`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ projectId, provider, token }),
  });
}

export async function fetchWorkDiary(projectId: string) {
  return api<{ entries: { id: string; projectId: string; dateISO: string; crew: string; summary: string }[] }>(
    `/api/work-diary?projectId=${encodeURIComponent(projectId)}`
  );
}
