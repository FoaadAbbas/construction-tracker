import fs from "node:fs";
import path from "node:path";
import PDFDocument from "pdfkit";
import ExcelJS from "exceljs";
import type { RunDoc, ZoneDoc } from "./models.js";

export type ReportPaths = { pdfPath: string; xlsxPath: string };

export async function generateReportFiles(opts: {
  outDir: string;
  projectName: string;
  run: RunDoc;
  zones: ZoneDoc[];
}): Promise<ReportPaths> {
  fs.mkdirSync(opts.outDir, { recursive: true });
  const ts = Date.now();
  const pdfPath = path.join(opts.outDir, `report_${opts.run.projectId}_${ts}.pdf`);
  const xlsxPath = path.join(opts.outDir, `report_${opts.run.projectId}_${ts}.xlsx`);

  await generatePdf({ ...opts, pdfPath });
  await generateXlsx({ ...opts, xlsxPath });

  return { pdfPath, xlsxPath };
}

async function generatePdf(opts: {
  outDir: string;
  projectName: string;
  run: RunDoc;
  zones: ZoneDoc[];
  pdfPath: string;
}) {
  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48 });
    const stream = fs.createWriteStream(opts.pdfPath);
    stream.on("finish", () => resolve());
    stream.on("error", reject);
    doc.pipe(stream);

    doc.fontSize(18).text("Construction Progress Report", { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(12).text(`Project: ${opts.projectName}`);
    doc.text(`Generated: ${new Date().toISOString()}`);
    doc.text(`Run created: ${opts.run.createdAtISO}`);
    doc.moveDown();

    doc.fontSize(14).text("Scan Comparison Summary", { underline: true });
    doc.moveDown(0.25);
    doc.fontSize(12).text(`Volume (t1): ${opts.run.volumeT1M3.toFixed(3)} m³`);
    doc.text(`Volume (t2): ${opts.run.volumeT2M3.toFixed(3)} m³`);
    doc.text(`Volume change: ${opts.run.volumeChangeM3.toFixed(3)} m³`);
    doc.text(`Overall progress: ${opts.run.overallProgressPct.toFixed(1)}%`);
    doc.text(`Alignment confidence: ${opts.run.alignmentConfidence}`);
    if (opts.run.forecastCompletionISO) {
      doc.text(`Forecast completion: ${opts.run.forecastCompletionISO}`);
    }
    doc.moveDown();

    doc.fontSize(14).text("Zones", { underline: true });
    doc.moveDown(0.5);

    const zonesById = new Map(opts.zones.map((z) => [z._id.toString(), z]));
    const leaf = opts.zones.filter((z) => z.type === "zone");

    for (const z of leaf) {
      const metric = opts.run.metricsByZone.find((m) => m.zoneId === z._id.toString());
      const pct = metric?.progressPct ?? z.completionPct ?? 0;
      const dV = metric?.volumeChangeM3 ?? 0;
      doc.fontSize(12).text(`• ${z.name} — ${pct.toFixed(1)}%  (ΔV ${dV.toFixed(3)} m³)`);
    }

    doc.moveDown();
    doc.fontSize(10).fillColor("gray").text(
      "Note: Volume is estimated via voxel occupancy from point clouds. Adjust voxel size for accuracy/performance tradeoffs.",
      { width: 520 }
    );
    doc.end();
  });
}

async function generateXlsx(opts: {
  outDir: string;
  projectName: string;
  run: RunDoc;
  zones: ZoneDoc[];
  xlsxPath: string;
}) {
  const wb = new ExcelJS.Workbook();
  const summary = wb.addWorksheet("Summary");
  summary.addRow(["Project", opts.projectName]);
  summary.addRow(["Run created", opts.run.createdAtISO]);
  summary.addRow(["Volume t1 (m3)", opts.run.volumeT1M3]);
  summary.addRow(["Volume t2 (m3)", opts.run.volumeT2M3]);
  summary.addRow(["Volume change (m3)", opts.run.volumeChangeM3]);
  summary.addRow(["Overall progress (%)", opts.run.overallProgressPct]);
  summary.addRow(["Alignment confidence", opts.run.alignmentConfidence]);
  summary.addRow(["Forecast completion", opts.run.forecastCompletionISO ?? "-"]);

  const zones = wb.addWorksheet("Zones");
  zones.addRow(["Zone", "Completion %", "Volume Change (m3)"]);
  zones.getRow(1).font = { bold: true };

  const leaf = opts.zones.filter((z) => z.type === "zone");
  for (const z of leaf) {
    const metric = opts.run.metricsByZone.find((m) => m.zoneId === z._id.toString());
    zones.addRow([z.name, metric?.progressPct ?? z.completionPct ?? 0, metric?.volumeChangeM3 ?? 0]);
  }

  await wb.xlsx.writeFile(opts.xlsxPath);
}
