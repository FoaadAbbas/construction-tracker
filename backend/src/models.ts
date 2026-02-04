import mongoose, { Schema } from "mongoose";

export type ProjectDoc = {
  name: string;
  createdAtISO: string;
  userId: string;
};

const ProjectSchema = new Schema<ProjectDoc>(
  {
    name: { type: String, required: true },
    createdAtISO: { type: String, required: true },
    userId: { type: String, required: true, index: true },
  },
  { versionKey: false }
);

export const ProjectModel = mongoose.model<ProjectDoc>("Project", ProjectSchema);

export type ZoneType = "site" | "floor" | "wing" | "zone";

export type ZoneDoc = {
  _id: string;
  projectId: string;
  name: string;
  type: ZoneType;
  parentId?: string;
  completionPct: number;
  createdAtISO: string;
  linkedScanIds: string[];
};

const ZoneSchema = new Schema<ZoneDoc>(
  {
    projectId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    type: { type: String, required: true },
    parentId: { type: String, required: false, index: true },
    completionPct: { type: Number, required: true, default: 0 },
    linkedScanIds: { type: [String], required: true, default: [] },
    createdAtISO: { type: String, required: true },
  },
  { versionKey: false }
);

export const ZoneModel = mongoose.model<ZoneDoc>("Zone", ZoneSchema);

export type ScanDoc = {
  projectId: string;
  name: string;
  sizeBytes: number;
  capturedAtISO: string;
  uploadedAtISO: string;
  notes?: string;
  filePath: string;
};

const ScanSchema = new Schema<ScanDoc>(
  {
    projectId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    sizeBytes: { type: Number, required: true },
    capturedAtISO: { type: String, required: true },
    uploadedAtISO: { type: String, required: true },
    notes: { type: String, required: false },
    filePath: { type: String, required: true },
  },
  { versionKey: false }
);

export const ScanModel = mongoose.model<ScanDoc>("Scan", ScanSchema);

export type AreaMetric = {
  zoneId: string;
  progressPct: number;
  volumeChangeM3: number;
};

export type RunDoc = {
  projectId: string;
  createdAtISO: string;
  t1ScanId: string;
  t2ScanId: string;
  status: "queued" | "processing" | "done" | "failed";
  error?: string;
  alignmentConfidence: "low" | "medium" | "high";
  volumeT1M3: number;
  volumeT2M3: number;
  volumeChangeM3: number;
  overallProgressPct: number;
  metricsByZone: AreaMetric[];
  forecastCompletionISO?: string;
};

const MetricSchema = new Schema<AreaMetric>(
  {
    zoneId: { type: String, required: true },
    progressPct: { type: Number, required: true },
    volumeChangeM3: { type: Number, required: true },
  },
  { _id: false }
);

const RunSchema = new Schema<RunDoc>(
  {
    projectId: { type: String, required: true, index: true },
    createdAtISO: { type: String, required: true },
    t1ScanId: { type: String, required: true },
    t2ScanId: { type: String, required: true },
    status: { type: String, required: true, index: true },
    error: { type: String, required: false },
    alignmentConfidence: { type: String, required: true },
    volumeT1M3: { type: Number, required: true, default: 0 },
    volumeT2M3: { type: Number, required: true, default: 0 },
    volumeChangeM3: { type: Number, required: true, default: 0 },
    overallProgressPct: { type: Number, required: true, default: 0 },
    metricsByZone: { type: [MetricSchema], required: true, default: [] },
    forecastCompletionISO: { type: String, required: false },
  },
  { versionKey: false }
);

export const RunModel = mongoose.model<RunDoc>("Run", RunSchema);

export type ReportDoc = {
  projectId: string;
  runId: string;
  createdAtISO: string;
  pdfPath: string;
  xlsxPath: string;
};

const ReportSchema = new Schema<ReportDoc>(
  {
    projectId: { type: String, required: true, index: true },
    runId: { type: String, required: true, index: true },
    createdAtISO: { type: String, required: true },
    pdfPath: { type: String, required: true },
    xlsxPath: { type: String, required: true },
  },
  { versionKey: false }
);

export const ReportModel = mongoose.model<ReportDoc>("Report", ReportSchema);

export type UserDoc = {
  name: string;
  email: string;
  username: string;
  passwordHash: string;
  createdAtISO: string;
  resetToken?: string;
  resetTokenExpiry?: string;
};

const UserSchema = new Schema<UserDoc>(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAtISO: { type: String, required: true },
    resetToken: { type: String, required: false },
    resetTokenExpiry: { type: String, required: false },
  },
  { versionKey: false }
);

export const UserModel = mongoose.model<UserDoc>("User", UserSchema);
