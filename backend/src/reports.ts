import fs from "fs";
import path from "path";
import PDFDocument from "pdfkit";
import ExcelJS from "exceljs";
import type { RunDoc, ZoneDoc } from "./models.js";

export async function generatePdf(reportDir: string, run: RunDoc, zones: ZoneDoc[]) {
  fs.mkdirSync(reportDir, { recursive: true });
  const runId = String((run as any)._id);
  const outPath = path.join(reportDir, `report_${runId}.pdf`);
  const doc = new PDFDocument({ margin: 50 });
  const stream = fs.createWriteStream(outPath);
  doc.pipe(stream);

  doc.fontSize(20).text("Construction Progress Report", { align: "left" });
  doc.moveDown();
  doc.fontSize(12).text(`Run ID: ${runId}`);
  doc.text(`Created: ${run.createdAtISO}`);
  doc.text(`T1 Scan: ${run.t1ScanId}`);
  doc.text(`T2 Scan: ${run.t2ScanId}`);
  doc.moveDown();

  doc.fontSize(14).text("Key Metrics", { underline: true });
  doc.fontSize(12);
  doc.text(`Volume (T1): ${run.volumeT1M3.toFixed(3)} m³`);
  doc.text(`Volume (T2): ${run.volumeT2M3.toFixed(3)} m³`);
  doc.text(`Volume Change: ${run.volumeChangeM3.toFixed(3)} m³`);
  doc.text(`Overall Progress: ${run.overallProgressPct.toFixed(1)}%`);
  if (run.forecastCompletionISO) doc.text(`Forecast Completion: ${run.forecastCompletionISO}`);
  doc.text(`Alignment Confidence: ${run.alignmentConfidence}`);

  doc.moveDown();
  doc.fontSize(14).text("Zones", { underline: true });
  doc.fontSize(10);

  const zoneMap = new Map(zones.map((z) => [String((z as any)._id), z]));
  const rows = run.metricsByZone.map((m) => {
    const z = zoneMap.get(m.zoneId);
    return {
      name: z ? `${z.name} (${z.type})` : m.zoneId,
      progress: m.progressPct,
      volume: m.volumeChangeM3,
    };
  });

  for (const r of rows) {
    doc.text(`- ${r.name}: ${r.progress.toFixed(1)}% | ΔV ${r.volume.toFixed(3)} m³`);
  }

  doc.end();

  await new Promise<void>((resolve, reject) => {
    stream.on("finish", () => resolve());
    stream.on("error", (e) => reject(e));
  });

  return outPath;
}

export async function generateXlsx(reportDir: string, run: RunDoc, zones: ZoneDoc[]) {
  fs.mkdirSync(reportDir, { recursive: true });
  const runId = String((run as any)._id);
  const outPath = path.join(reportDir, `report_${runId}.xlsx`);

  const wb = new ExcelJS.Workbook();
  wb.creator = "construction-tracker";
  const wsSummary = wb.addWorksheet("Summary");

  wsSummary.addRow(["Run ID", runId]);
  wsSummary.addRow(["Created", run.createdAtISO]);
  wsSummary.addRow(["T1 Scan", run.t1ScanId]);
  wsSummary.addRow(["T2 Scan", run.t2ScanId]);
  wsSummary.addRow([]);
  wsSummary.addRow(["Volume (T1) m3", run.volumeT1M3]);
  wsSummary.addRow(["Volume (T2) m3", run.volumeT2M3]);
  wsSummary.addRow(["Volume Change m3", run.volumeChangeM3]);
  wsSummary.addRow(["Overall Progress %", run.overallProgressPct]);
  wsSummary.addRow(["Alignment Confidence", run.alignmentConfidence]);
  wsSummary.addRow(["Forecast Completion", run.forecastCompletionISO || ""]);

  const wsZones = wb.addWorksheet("Zones");
  wsZones.columns = [
    { header: "Zone ID", key: "zoneId", width: 28 },
    { header: "Zone Name", key: "name", width: 32 },
    { header: "Type", key: "type", width: 12 },
    { header: "Completion %", key: "completion", width: 14 },
    { header: "Progress % (Run)", key: "progress", width: 16 },
    { header: "Volume Change m3", key: "volume", width: 18 },
  ];

  const zoneMap = new Map(zones.map((z) => [String((z as any)._id), z]));
  for (const m of run.metricsByZone) {
    const z = zoneMap.get(m.zoneId);
    wsZones.addRow({
      zoneId: m.zoneId,
      name: z?.name || "",
      type: z?.type || "",
      completion: z?.completionPct ?? 0,
      progress: m.progressPct,
      volume: m.volumeChangeM3,
    });
  }

  await wb.xlsx.writeFile(outPath);
  return outPath;
}
