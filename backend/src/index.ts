import "dotenv/config";
import path from "path";
import fs from "fs";
import { spawn } from "child_process";
import express from "express";
import cors from "cors";
import multer from "multer";
import { WebSocketServer } from "ws";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as brevo from "@getbrevo/brevo";

// Initialize Brevo client
const brevoApiInstance = new brevo.TransactionalEmailsApi();
brevoApiInstance.setApiKey(brevo.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY || "");
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@example.com";
const FROM_NAME = process.env.FROM_NAME || "Construction Tracker";

console.log("Brevo client initialized, FROM_EMAIL:", FROM_EMAIL);


import { connectDb } from "./db.js";
import { ProjectModel, ZoneModel, ScanModel, RunModel, ReportModel, UserModel, type ZoneDoc } from "./models.js";
import { registerWs, publish } from "./realtime.js";
import { generatePdf, generateXlsx } from "./reports.js";

const PORT = Number(process.env.PORT || 4000);
const ROOT = path.resolve(process.cwd());
const UPLOAD_DIR = path.join(ROOT, "uploads");
const REPORTS_DIR = path.join(ROOT, "reports");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(REPORTS_DIR, { recursive: true });

import crypto from "crypto";

// Point cloud cache for faster repeated loads
// Key: scanId, Value: { points, colors, timestamp }
interface CacheEntry {
  points: number[][];
  colors?: number[][];
  timestamp: number;
}
const pointCloudCache = new Map<string, CacheEntry>();
const CACHE_MAX_SIZE = 10;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

function cleanExpiredCache() {
  const now = Date.now();
  for (const [key, entry] of pointCloudCache) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      pointCloudCache.delete(key);
    }
  }
}

function addToCache(scanId: string, points: number[][], colors?: number[][]) {
  cleanExpiredCache();
  // If cache is full, remove oldest entry
  if (pointCloudCache.size >= CACHE_MAX_SIZE) {
    let oldestKey = "";
    let oldestTime = Infinity;
    for (const [key, entry] of pointCloudCache) {
      if (entry.timestamp < oldestTime) {
        oldestTime = entry.timestamp;
        oldestKey = key;
      }
    }
    if (oldestKey) pointCloudCache.delete(oldestKey);
  }
  pointCloudCache.set(scanId, { points, colors, timestamp: Date.now() });
}

function getFromCache(scanId: string): CacheEntry | undefined {
  const entry = pointCloudCache.get(scanId);
  if (entry && Date.now() - entry.timestamp <= CACHE_TTL_MS) {
    return entry;
  }
  if (entry) pointCloudCache.delete(scanId); // Expired
  return undefined;
}

// JWT validation middleware
function authenticateToken(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || "secret", (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    (req as any).user = user; // Attach user info to request
    next();
  });
}

// keep only safe chars, prevent path traversal, keep extension
function sanitizeFilename(name: string) {
  const base = path.basename(name); // removes any folders
  return base.replace(/[^a-zA-Z0-9._-]+/g, "_");
}

function validateLasFile(filePath: string): boolean {
  try {
    const buffer = fs.readFileSync(filePath);
    if (buffer.length < 4) return false;
    // LAS files start with "LASF"
    const signature = buffer.subarray(0, 4).toString('ascii');
    return signature === 'LASF';
  } catch {
    return false;
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const safe = sanitizeFilename(file.originalname); // includes extension
    const uniq = crypto.randomBytes(6).toString("hex"); // short unique suffix
    cb(null, `${Date.now()}-${uniq}-${safe}`);
  },
});

const upload = multer({ storage });

function pickConfidence(volumeChange: number) {
  const mag = Math.abs(volumeChange);
  if (mag < 1) return "high" as const;
  if (mag < 10) return "medium" as const;
  return "low" as const;
}

function forecastDateISO(overallProgressPct: number) {
  const daysLeft = Math.round((100 - overallProgressPct) * 0.6);
  const d = new Date();
  d.setDate(d.getDate() + Math.max(0, daysLeft));
  return d.toISOString();
}

async function ensureDemoProject() {
  // In production with user auth, we no longer create a demo project
  // Each user creates their own projects
  return "";
}

async function runPythonVolumeDiff(t1Path: string, t2Path: string, voxelSize: number) {
  const py = process.env.PYTHON_BIN || "python3";
  const script = path.join(ROOT, "python", "volume_diff.py");

  return await new Promise<{ volumeT1M3: number; volumeT2M3: number; volumeChangeM3: number }>((resolve, reject) => {
    const p = spawn(py, [script, "--t1", t1Path, "--t2", t2Path, "--voxel", String(voxelSize)], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += String(d)));
    p.stderr.on("data", (d) => (err += String(d)));
    p.on("close", (code) => {
      if (code !== 0 && code !== 2) {
        return reject(new Error(`Python process failed: code=${code} err=${err}`));
      }
      try {
        const parsed = JSON.parse(out.trim() || "{}");
        if (parsed.error) return reject(new Error(parsed.error));
        resolve({
          volumeT1M3: Number(parsed.volumeT1M3 || 0),
          volumeT2M3: Number(parsed.volumeT2M3 || 0),
          volumeChangeM3: Number(parsed.volumeChangeM3 || 0),
        });
      } catch (e) {
        reject(new Error(`Failed to parse python output. out=${out} err=${err}`));
      }
    });
  });
}

async function runPythonExtractPoints(filePath: string, maxPoints: number = 350000) {
  const py = process.env.PYTHON_BIN || "python3";
  const script = path.join(ROOT, "python", "volume_diff.py");

  return await new Promise<{ points: number[][]; colors?: number[][] }>((resolve, reject) => {
    const p = spawn(py, [script, "--extract", filePath, "--max_extract_points", String(maxPoints)], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += String(d)));
    p.stderr.on("data", (d) => (err += String(d)));
    p.on("close", (code) => {
      if (code !== 0 && code !== 2) {
        return reject(new Error(`Python process failed: code=${code}, stderr=${err}, stdout=${out}`));
      }
      try {
        const parsed = JSON.parse(out.trim() || "{}");
        if (parsed.error) return reject(new Error(parsed.error));
        resolve({
          points: parsed.points || [],
          colors: parsed.colors,
        });
      } catch (e) {
        reject(new Error(`Failed to parse python output. out=${out} err=${err}`));
      }
    });
    p.on("error", (error) => {
      reject(new Error(`Failed to start Python process: ${error.message}. Make sure Python 3 is installed and the required packages (laspy, open3d, numpy) are available.`));
    });
  });
}

function calcOverallProgress(volumeT1: number, volumeT2: number) {
  if (volumeT1 <= 0 || volumeT2 <= 0) return 0;
  const delta = volumeT2 - volumeT1;
  const pct = (delta / Math.abs(volumeT1)) * 100;
  return Math.max(0, Math.min(100, pct));
}

async function getLeafZones(projectId: string): Promise<(ZoneDoc & { _id: unknown })[]> {
  const zones = await ZoneModel.find({ projectId }).lean();
  const zoneIds = new Set(zones.map((z) => String(z._id)));
  const hasChild = new Set<string>();
  for (const z of zones) {
    if (z.parentId && zoneIds.has(z.parentId)) hasChild.add(z.parentId);
  }
  return zones.filter((z) => !hasChild.has(String(z._id)));
}

async function main() {
  await connectDb();
  const demoProjectId = await ensureDemoProject();

  const app = express();
  app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  }));
  app.use(express.json({ limit: "2mb" }));

  // static downloads
  app.use("/downloads/reports", express.static(REPORTS_DIR));

  app.get("/api/health", (_req, res) => res.json({ ok: true }));

  // Auth routes
  app.post("/api/auth/register", async (req, res) => {
    try {
      const { name, email, username, password } = req.body;
      if (!name || !email || !username || !password) {
        return res.status(400).json({ error: "name, email, username, and password are required" });
      }
      if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
      }

      const existingEmail = await UserModel.findOne({ email }).lean();
      if (existingEmail) {
        return res.status(400).json({ error: "Email already registered" });
      }

      const existingUsername = await UserModel.findOne({ username }).lean();
      if (existingUsername) {
        return res.status(400).json({ error: "Username already taken" });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const user = await UserModel.create({
        name,
        email,
        username,
        passwordHash,
        createdAtISO: new Date().toISOString(),
      });

      const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });

      res.json({ token, user: { id: String(user._id), name: user.name, email: user.email, username: user.username } });
    } catch (e: any) {
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: "email/username and password are required" });
      }

      const user = await UserModel.findOne({ $or: [{ email }, { username: email }] }).lean();
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "secret", { expiresIn: "7d" });

      res.json({ token, user: { id: String(user._id), name: user.name, email: user.email, username: user.username } });
    } catch (e: any) {
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  app.post("/api/test-email", async (req, res) => {
    try {
      const { to } = req.body;
      const sendSmtpEmail = new brevo.SendSmtpEmail();
      sendSmtpEmail.subject = "Test Email";
      sendSmtpEmail.htmlContent = "<p>This is a test email from Construction Tracker.</p>";
      sendSmtpEmail.sender = { name: FROM_NAME, email: FROM_EMAIL };
      sendSmtpEmail.to = [{ email: to || "test@example.com" }];

      const result = await brevoApiInstance.sendTransacEmail(sendSmtpEmail);
      res.json({ message: "Test email sent", id: result.body.messageId });
    } catch (e: any) {
      console.error("Test email error:", e);
      res.status(500).json({ error: String(e?.message || e?.body?.message || e) });
    }
  });

  app.get("/api/debug-email", async (req, res) => {
    try {
      const apiKeySet = !!process.env.BREVO_API_KEY;
      res.json({
        ok: true,
        config: {
          provider: "Brevo",
          apiKeySet,
          fromEmail: FROM_EMAIL,
          fromName: FROM_NAME
        },
        message: "Brevo configuration loaded"
      });
    } catch (e: any) {
      res.status(500).json({
        ok: false,
        error: e.message
      });
    }
  });

  app.post("/api/auth/forgot-password", async (req, res) => {
    try {
      const { email } = req.body;
      console.log("Forgot password request for email:", email);
      if (!email) {
        return res.status(400).json({ error: "email is required" });
      }

      const user = await UserModel.findOne({ email }).lean();
      if (!user) {
        console.log("User not found for email:", email);
        // Don't reveal if email exists or not for security
        return res.json({ message: "If an account with that email exists, a reset link has been sent." });
      }

      console.log("User found, generating reset token");
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

      await UserModel.findByIdAndUpdate(user._id, {
        resetToken,
        resetTokenExpiry: resetTokenExpiry.toISOString(),
      });

      const resetUrl = `${process.env.CORS_ORIGIN}/reset-password?token=${resetToken}`;
      console.log("Reset URL:", resetUrl);

      console.log("Sending email via Brevo...");
      const sendSmtpEmail = new brevo.SendSmtpEmail();
      sendSmtpEmail.subject = "Password Reset";
      sendSmtpEmail.htmlContent = `<p>You requested a password reset.</p><p>Click <a href="${resetUrl}">here</a> to reset your password.</p><p>This link expires in 1 hour.</p>`;
      sendSmtpEmail.sender = { name: FROM_NAME, email: FROM_EMAIL };
      sendSmtpEmail.to = [{ email: email }];

      const result = await brevoApiInstance.sendTransacEmail(sendSmtpEmail);
      console.log("Email sent successfully, id:", result.body.messageId);

      res.json({ message: "If an account with that email exists, a reset link has been sent." });
    } catch (e: any) {
      console.error("Error in forgot-password:", e);
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  app.post("/api/auth/reset-password", async (req, res) => {
    try {
      const { token, newPassword } = req.body;
      if (!token || !newPassword) {
        return res.status(400).json({ error: "token and newPassword are required" });
      }
      if (newPassword.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
      }

      const user = await UserModel.findOne({ resetToken: token }).lean();
      if (!user || !user.resetTokenExpiry || new Date(user.resetTokenExpiry) < new Date()) {
        return res.status(400).json({ error: "Invalid or expired token" });
      }

      const passwordHash = await bcrypt.hash(newPassword, 10);
      await UserModel.findByIdAndUpdate(user._id, {
        passwordHash,
        resetToken: undefined,
        resetTokenExpiry: undefined,
      });

      res.json({ message: "Password reset successfully" });
    } catch (e: any) {
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  // Projects
  app.get("/api/projects", authenticateToken, async (req, res) => {
    const userId = (req as any).user.userId;
    const projects = await ProjectModel.find({ userId }).lean();
    res.json(
      projects.map((p) => ({
        id: String(p._id),
        name: p.name,
        createdAtISO: p.createdAtISO,
      }))
    );
  });

  app.post("/api/projects", authenticateToken, async (req, res) => {
    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ error: "name is required" });
    const userId = (req as any).user.userId;
    const p = await ProjectModel.create({ name, createdAtISO: new Date().toISOString(), userId });
    const projectId = String(p._id);
    await ZoneModel.create({
      projectId,
      name,
      type: "site",
      completionPct: 0,
      createdAtISO: new Date().toISOString(),
    });
    res.json({ id: projectId, name, createdAtISO: p.createdAtISO });
  });

  // Zones
  app.get("/api/zones", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const zones = await ZoneModel.find({ projectId }).lean();
    res.json(
      zones.map((z) => ({
        id: String(z._id),
        projectId: z.projectId,
        name: z.name,
        type: z.type,
        parentId: z.parentId,
        completionPct: z.completionPct ?? 0,
        linkedScanIds: z.linkedScanIds || [],
      }))
    );
  });

  app.post("/api/zones", authenticateToken, async (req, res) => {
    const projectId = String(req.body?.projectId || demoProjectId);
    const name = String(req.body?.name || "").trim();
    const type = String(req.body?.type || "").trim();
    const parentId = req.body?.parentId ? String(req.body.parentId) : undefined;
    if (!name) return res.status(400).json({ error: "name is required" });
    if (!type) return res.status(400).json({ error: "type is required" });

    const created = await ZoneModel.create({
      projectId,
      name,
      type,
      parentId,
      completionPct: 0,
      linkedScanIds: [],
      createdAtISO: new Date().toISOString(),
    });
    res.json({
      id: String(created._id),
      projectId,
      name,
      type,
      parentId,
      completionPct: 0,
      linkedScanIds: [],
    });
  });

  app.patch("/api/zones/:id", authenticateToken, async (req, res) => {
    const id = String(req.params.id);
    const patch: Record<string, unknown> = {};
    if (typeof req.body?.name === "string") patch.name = req.body.name;
    if (typeof req.body?.completionPct === "number") patch.completionPct = req.body.completionPct;
    if (Array.isArray(req.body?.linkedScanIds)) {
      patch.linkedScanIds = (req.body.linkedScanIds as unknown[])
        .map((x) => String(x))
        .filter((v) => !!v);
    }
    const z = await ZoneModel.findByIdAndUpdate(id, patch, { new: true }).lean();
    if (!z) return res.status(404).json({ error: "not found" });
    res.json({
      id: String(z._id),
      projectId: z.projectId,
      name: z.name,
      type: z.type,
      parentId: z.parentId,
      completionPct: z.completionPct ?? 0,
      linkedScanIds: z.linkedScanIds || [],
    });
  });

  app.delete("/api/zones/:id", authenticateToken, async (req, res) => {
    const id = String(req.params.id);
    // remove node + descendants (scoped to the same project)
    const root = await ZoneModel.findById(id).lean();
    if (!root) return res.status(404).json({ error: "not found" });
    const projectId = String(root.projectId);

    const zones = await ZoneModel.find({ projectId }).lean();
    const childrenByParent = new Map<string, string[]>();
    for (const z of zones) {
      const pid = z.parentId ? String(z.parentId) : "";
      if (!pid) continue;
      const arr = childrenByParent.get(pid) || [];
      arr.push(String(z._id));
      childrenByParent.set(pid, arr);
    }
    const toRemove = new Set<string>();
    const collect = (cur: string) => {
      toRemove.add(cur);
      for (const c of childrenByParent.get(cur) || []) collect(c);
    };
    collect(id);
    await ZoneModel.deleteMany({ _id: { $in: Array.from(toRemove) }, projectId });
    res.json({ ok: true, removed: Array.from(toRemove) });
  });

  // Scans
  app.get("/api/scans", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const scans = await ScanModel.find({ projectId }).sort({ uploadedAtISO: -1 }).lean();
    res.json(
      scans.map((s) => ({
        id: String(s._id),
        projectId: s.projectId,
        name: s.name,
        sizeBytes: s.sizeBytes,
        capturedAtISO: s.capturedAtISO,
        uploadedAtISO: s.uploadedAtISO,
        notes: s.notes,
      }))
    );
  });

  app.post("/api/scans/upload", authenticateToken, upload.single("file"), async (req, res) => {
    const projectId = String(req.body?.projectId || demoProjectId);
    const capturedAtISO = String(req.body?.capturedAtISO || new Date().toISOString());
    const notes = req.body?.notes ? String(req.body.notes) : undefined;
    const zoneId = req.body?.zoneId ? String(req.body.zoneId) : undefined;
    if (!req.file) return res.status(400).json({ error: "file is required" });

    // Note: File validation is handled by the Python processing scripts
    // when extracting points or computing volumes

    const doc = await ScanModel.create({
      projectId,
      name: req.file.originalname,
      sizeBytes: req.file.size,
      capturedAtISO,
      uploadedAtISO: new Date().toISOString(),
      notes,
      filePath: req.file.path,
    });

    // Link to zone if provided
    if (zoneId) {
      await ZoneModel.findByIdAndUpdate(zoneId, { $addToSet: { linkedScanIds: String(doc._id) } });
    }

    res.json({
      id: String(doc._id),
      projectId,
      name: doc.name,
      sizeBytes: doc.sizeBytes,
      capturedAtISO: doc.capturedAtISO,
      uploadedAtISO: doc.uploadedAtISO,
      notes: doc.notes,
    });
  });

  app.delete("/api/scans/:id", authenticateToken, async (req, res) => {
    const id = String(req.params.id);
    const scan = await ScanModel.findByIdAndDelete(id).lean();
    if (scan?.filePath) {
      try {
        fs.unlinkSync(scan.filePath);
      } catch {
        // ignore
      }
    }
    res.json({ ok: true });
  });

  app.get("/api/scans/:id/file", authenticateToken, async (req, res) => {
    const id = String(req.params.id);
    const scan = await ScanModel.findById(id).lean();
    if (!scan?.filePath) return res.status(404).json({ error: "Scan not found" });
    res.sendFile(scan.filePath);
  });

  app.get("/api/scans/:id/points", authenticateToken, async (req, res) => {
    const id = String(req.params.id);
    const format = String(req.query.format || "json"); // "json" or "binary"
    const scan = await ScanModel.findById(id).lean();
    if (!scan?.filePath) return res.status(404).json({ error: "Scan not found" });

    try {
      // Check cache first
      let cached = getFromCache(id);
      let points: number[][];
      let colors: number[][] | undefined;

      if (cached) {
        console.log(`Cache hit for scan ${id}`);
        points = cached.points;
        colors = cached.colors;
      } else {
        console.log(`Cache miss for scan ${id}, extracting...`);
        const result = await runPythonExtractPoints(scan.filePath);
        points = result.points;
        colors = result.colors;
        // Add to cache
        addToCache(id, points, colors);
      }

      if (format === "binary") {
        // Binary format: Float32Array buffer
        // Format: [numPoints (4 bytes), hasColors (1 byte), ...positions (12 bytes each), ...colors (12 bytes each if present)]
        const numPoints = points.length;
        const hasColors = colors && colors.length === numPoints ? 1 : 0;
        const headerSize = 5; // 4 bytes for numPoints + 1 byte for hasColors
        const pointsSize = numPoints * 3 * 4; // 3 floats * 4 bytes each
        const colorsSize = hasColors ? numPoints * 3 * 4 : 0;
        const totalSize = headerSize + pointsSize + colorsSize;

        const buffer = Buffer.alloc(totalSize);
        let offset = 0;

        // Write header
        buffer.writeUInt32LE(numPoints, offset); offset += 4;
        buffer.writeUInt8(hasColors, offset); offset += 1;

        // Write positions
        for (let i = 0; i < numPoints; i++) {
          buffer.writeFloatLE(points[i][0], offset); offset += 4;
          buffer.writeFloatLE(points[i][1], offset); offset += 4;
          buffer.writeFloatLE(points[i][2], offset); offset += 4;
        }

        // Write colors if present
        if (hasColors && colors) {
          for (let i = 0; i < numPoints; i++) {
            buffer.writeFloatLE(colors[i][0], offset); offset += 4;
            buffer.writeFloatLE(colors[i][1], offset); offset += 4;
            buffer.writeFloatLE(colors[i][2], offset); offset += 4;
          }
        }

        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Length", totalSize);
        res.send(buffer);
      } else {
        // JSON format (legacy)
        res.json({ points, colors });
      }
    } catch (error) {
      console.error("Error extracting points:", error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: `Failed to extract points from scan: ${errorMessage}` });
    }
  });

  // Runs (volume diff)
  app.get("/api/runs", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const runs = await RunModel.find({ projectId }).sort({ createdAtISO: -1 }).lean();
    res.json(
      runs.map((r) => ({
        id: String(r._id),
        projectId: r.projectId,
        createdAtISO: r.createdAtISO,
        t1ScanId: r.t1ScanId,
        t2ScanId: r.t2ScanId,
        status: r.status,
        error: r.error,
        alignmentConfidence: r.alignmentConfidence,
        volumeT1M3: r.volumeT1M3,
        volumeT2M3: r.volumeT2M3,
        volumeChangeM3: r.volumeChangeM3,
        overallProgressPct: r.overallProgressPct,
        forecastCompletionISO: r.forecastCompletionISO,
        metricsByZone: r.metricsByZone,
      }))
    );
  });

  app.post("/api/runs", authenticateToken, async (req, res) => {
    const projectId = String(req.body?.projectId || demoProjectId);
    const t1ScanId = String(req.body?.t1ScanId || "");
    const t2ScanId = String(req.body?.t2ScanId || "");
    const voxelSize = Number(req.body?.voxelSize || 0.05);

    if (!t1ScanId || !t2ScanId) return res.status(400).json({ error: "t1ScanId and t2ScanId are required" });
    if (t1ScanId === t2ScanId) return res.status(400).json({ error: "t1 and t2 must be different scans" });

    const created = await RunModel.create({
      projectId,
      createdAtISO: new Date().toISOString(),
      t1ScanId,
      t2ScanId,
      status: "queued",
      alignmentConfidence: "medium",
      volumeT1M3: 0,
      volumeT2M3: 0,
      volumeChangeM3: 0,
      overallProgressPct: 0,
      metricsByZone: [],
      forecastCompletionISO: undefined,
    });

    const runId = String(created._id);
    publish(projectId, { type: "run.created", runId, status: "queued" });

    // async processing (simple in-process)
    (async () => {
      try {
        await RunModel.findByIdAndUpdate(runId, { status: "processing" });
        publish(projectId, { type: "run.progress", runId, status: "processing", pct: 5 });

        const t1 = await ScanModel.findById(t1ScanId).lean();
        const t2 = await ScanModel.findById(t2ScanId).lean();
        if (!t1 || !t2) throw new Error("Missing scan files");

        publish(projectId, { type: "run.progress", runId, status: "processing", pct: 20 });
        const volumes = await runPythonVolumeDiff(t1.filePath, t2.filePath, voxelSize);

        publish(projectId, { type: "run.progress", runId, status: "processing", pct: 75 });

        const overallProgressPct = calcOverallProgress(volumes.volumeT1M3, volumes.volumeT2M3);
        const leafZones = await getLeafZones(projectId);

        const perZoneProgress = leafZones.map((z, i) => {
          // simple heuristic: distribute overall progress
          const w = leafZones.length <= 1 ? 1 : (i + 1) / leafZones.length;
          const p = Math.max(0, Math.min(100, overallProgressPct * (0.7 + 0.6 * w)));
          return {
            zoneId: String(z._id),
            progressPct: Math.round(p * 10) / 10,
            volumeChangeM3: volumes.volumeChangeM3 / Math.max(1, leafZones.length),
          };
        });

        // update root site completionPct
        const root = await ZoneModel.findOne({ projectId, type: "site" }).lean();
        if (root) await ZoneModel.findByIdAndUpdate(String(root._id), { completionPct: overallProgressPct });

        const conf = pickConfidence(volumes.volumeChangeM3);
        const forecastCompletionISO = forecastDateISO(overallProgressPct);

        await RunModel.findByIdAndUpdate(runId, {
          status: "done",
          alignmentConfidence: conf,
          volumeT1M3: volumes.volumeT1M3,
          volumeT2M3: volumes.volumeT2M3,
          volumeChangeM3: volumes.volumeChangeM3,
          overallProgressPct,
          forecastCompletionISO,
          metricsByZone: perZoneProgress,
        });

        publish(projectId, { type: "run.done", runId, status: "done" });
      } catch (e: any) {
        await RunModel.findByIdAndUpdate(runId, { status: "failed", error: String(e?.message || e) });
        publish(projectId, { type: "run.done", runId, status: "failed", error: String(e?.message || e) });
      }
    })();

    res.json({ id: runId, status: "queued" });
  });

  // Dashboard
  app.get("/api/dashboard", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const latest = await RunModel.findOne({ projectId, status: "done" }).sort({ createdAtISO: -1 }).lean();
    const overallProgressPct = latest?.overallProgressPct ?? 0;
    const volumeChangeM3 = latest?.volumeChangeM3 ?? 0;
    const forecastCompletionISO = latest?.forecastCompletionISO || "";

    // simple productivity index: progress per day since first run
    const firstRun = await RunModel.findOne({ projectId, status: "done" }).sort({ createdAtISO: 1 }).lean();
    let productivityIndex = 1.0;
    if (firstRun && latest) {
      const days = Math.max(1, (new Date(latest.createdAtISO).getTime() - new Date(firstRun.createdAtISO).getTime()) / (1000 * 60 * 60 * 24));
      const rate = overallProgressPct / days;
      productivityIndex = Math.round((rate / 5) * 100) / 100; // 5%/day baseline
      productivityIndex = Math.max(0, productivityIndex);
    }

    const runs = await RunModel.find({ projectId, status: "done" }).sort({ createdAtISO: 1 }).lean();
    const series = runs.map((r) => ({ t: r.createdAtISO, progressPct: r.overallProgressPct }));

    res.json({ overallProgressPct, volumeChangeM3, forecastCompletionISO, productivityIndex, series });
  });

  // Reports
  app.get("/api/reports", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const reports = await ReportModel.find({ projectId }).sort({ createdAtISO: -1 }).lean();
    res.json(
      reports.map((r) => ({
        id: String(r._id),
        projectId: r.projectId,
        runId: r.runId,
        createdAtISO: r.createdAtISO,
        pdfUrl: `/downloads/reports/${path.basename(r.pdfPath)}`,
        xlsxUrl: `/downloads/reports/${path.basename(r.xlsxPath)}`,
      }))
    );
  });

  app.post("/api/reports", authenticateToken, async (req, res) => {
    const projectId = String(req.body?.projectId || demoProjectId);
    const runId = String(req.body?.runId || "");
    if (!runId) return res.status(400).json({ error: "runId is required" });

    const run = await RunModel.findById(runId).lean();
    if (!run) return res.status(404).json({ error: "run not found" });
    if (run.status !== "done") return res.status(400).json({ error: "run is not done yet" });

    const zones = await ZoneModel.find({ projectId }).lean();
    const pdfPath = await generatePdf(REPORTS_DIR, run as any, zones as any);
    const xlsxPath = await generateXlsx(REPORTS_DIR, run as any, zones as any);

    const rep = await ReportModel.create({
      projectId,
      runId,
      createdAtISO: new Date().toISOString(),
      pdfPath,
      xlsxPath,
    });

    res.json({
      id: String(rep._id),
      pdfUrl: `/downloads/reports/${path.basename(pdfPath)}`,
      xlsxUrl: `/downloads/reports/${path.basename(xlsxPath)}`,
    });
  });

  // Gemini chatbot placeholder (you will plug Gemini API key later)
  app.post("/api/chat", authenticateToken, async (req, res) => {
    const prompt = String(req.body?.prompt || "");
    if (!prompt) return res.status(400).json({ error: "prompt is required" });

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: "Gemini API key not configured" });
    }

    try {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [
              {
                parts: [{
                  text: `You are an expert construction progress assistant for a building project tracking system called Construction Tracker. The system tracks construction progress using point cloud scans and provides insights through comparisons, reports, and AI recommendations.

Key Features and Pages:
- Dashboard: Displays overall progress percentage, volume change in cubic meters, forecast completion date, productivity index, and AI-generated recommendations for optimization.
- Scans (Upload/Compare Page): Upload point cloud files (PLY, LAS, LAZ, E57 formats), select two scans (t1 and t2) for comparison to calculate volume differences.
- Areas: Manage hierarchical project structure including site, floors, wings, and zones. Link scans to specific zones for targeted analysis.
- Compare: Run detailed comparisons between selected scans to generate KPIs, forecasts, and progress metrics.
- Reports: Generate and download professional PDF and Excel reports from comparison runs, including volume data and progress summaries.
- Schedule: Sync project schedules from MS Project or Primavera, and maintain a work diary for tracking activities.
- Chat: Access history of conversations with the AI assistant for ongoing support.
- Authentication: Secure login, registration, and password recovery pages.

UI Components:
- Buttons: Primary (accent-colored) and secondary (bordered) variants for various actions like uploading, comparing, and generating reports.

Algorithms and Functions:
- Volume Difference Calculation: Uses Open3D library to compute volume changes between point clouds, supporting multiple file formats.
- Progress Tracking: Calculates completion percentages based on volume metrics and zone-specific data.
- Forecasting: Predicts project completion dates using historical data and productivity trends.
- Productivity Index: Measures construction efficiency over time.
- API Endpoints: CRUD operations for projects, zones (areas), scans, comparison runs, and reports. Chat functionality powered by Gemini AI.

You help users understand construction progress, analyze scan data, provide insights on delays, suggest optimizations, answer questions about the project features, and guide them through using the application. Always be helpful, accurate, and professional. Respond based on the user's query: ${prompt}`
                }],
              },
            ],
          }),
        }
      );

      const json = await r.json();
      const candidate = json?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!candidate) throw new Error(json?.error?.message || "No response from Gemini");
      res.json({ reply: candidate });
    } catch (e: any) {
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  app.get("/api/recommendations", authenticateToken, async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const apiKey = process.env.GEMINI_API_KEY;
    const latest = await RunModel.findOne({ projectId, status: "done" }).sort({ createdAtISO: -1 }).lean();
    if (!latest) return res.json({ recommendations: ["Run a comparison to generate recommendations."] });
    if (!apiKey) {
      return res.json({
        recommendations: [
          "Enable Gemini by setting GEMINI_API_KEY to get AI recommendations.",
          `Latest progress is ${latest.overallProgressPct.toFixed(1)}% with volume delta ${latest.volumeChangeM3?.toFixed(2) ?? 0} m³.`,
        ],
      });
    }

    const prompt = [
      "You are a construction scheduler and progress analyst. Provide concise recommendations (max 3 bullets) for the project team.",
      `Latest run overall progress: ${latest.overallProgressPct.toFixed(1)}%.`,
      `Volume change: ${latest.volumeChangeM3?.toFixed(2) ?? 0} m3.`,
      `Forecast completion: ${latest.forecastCompletionISO || "n/a"}.`,
      `Alignment confidence: ${latest.alignmentConfidence}.`,
      "Keep each bullet under 120 characters.",
    ].join("\n");

    try {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
          }),
        }
      );
      const json = await r.json();
      const text = json?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      const lines = text
        .split(/\n|•|-|\*/g)
        .map((l: string) => l.trim())
        .filter(Boolean)
        .slice(0, 3);
      if (!lines.length) lines.push("No recommendations available.");
      res.json({ recommendations: lines });
    } catch (e: any) {
      res.status(500).json({ error: String(e?.message || e) });
    }
  });

  app.post("/api/schedule/sync", async (req, res) => {
    const provider = String(req.body?.provider || "").toLowerCase();
    const token = String(req.body?.token || "").trim();
    const projectId = String(req.body?.projectId || demoProjectId);
    if (!provider) return res.status(400).json({ error: "provider is required" });
    if (!token) return res.status(400).json({ error: "token is required" });

    const baseTasks = [
      { id: "T-100", name: "Site mobilization", start: "2024-10-01", finish: "2024-10-10", progressPct: 100 },
      { id: "T-200", name: "Excavation", start: "2024-10-11", finish: "2024-11-05", progressPct: 82 },
      { id: "T-300", name: "Substructure", start: "2024-11-06", finish: "2024-12-15", progressPct: 45 },
      { id: "T-400", name: "Superstructure", start: "2024-12-16", finish: "2025-02-20", progressPct: 10 },
    ];

    // Simulate provider specific meta
    res.json({
      provider,
      projectId,
      status: "synced",
      fetchedAtISO: new Date().toISOString(),
      tasks: baseTasks.map((t, i) => ({
        ...t,
        providerId: `${provider.toUpperCase()}-${t.id}`,
        owner: i % 2 === 0 ? "GC" : "Subcontractor",
        critical: i < 2,
      })),
    });
  });

  app.get("/api/work-diary", async (req, res) => {
    const projectId = String(req.query.projectId || demoProjectId);
    const entries = [
      {
        id: "WD-1",
        projectId,
        dateISO: new Date().toISOString(),
        crew: "Concrete",
        summary: "Poured podium slab, inspected formwork, minor rebar issue resolved.",
      },
      {
        id: "WD-2",
        projectId,
        dateISO: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        crew: "Earthworks",
        summary: "Completed north excavation, trucked spoil offsite, survey confirmation signed.",
      },
    ];
    res.json({ entries });
  });

  const server = app.listen(PORT, () => {
    console.log(`Backend listening on http://localhost:${PORT}`);
    console.log(`Demo projectId: ${demoProjectId}`);
  });

  server.timeout = 300000; // 5 minutes
  server.keepAliveTimeout = 300000;

  const wss = new WebSocketServer({ server, path: "/ws" });
  registerWs(wss);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
