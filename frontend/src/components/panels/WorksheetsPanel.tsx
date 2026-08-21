// Extracted from frontend/src/components/PanelViews.tsx (issue #144, PR 4).
import React from 'react';
import { EvaluationReport, Worksheet } from '../../types';
import { PageHeader } from './PanelShared';
import { MetricCard } from '../Card';
import { ClipboardList, CheckCircle2, FileText } from 'lucide-react';

export const WorksheetsPanel: React.FC<{ reportsList: EvaluationReport[]; worksheetsList: Worksheet[] }> = ({ reportsList, worksheetsList }) => {
    // Real data: each row is a real Worksheet generation record (created
    // when a teacher runs the Bulk Diagnostic Generator — see
    // backend/src/routes/diagnosticBulk.ts), not the old WORKSHEETS_MOCK
    // fixture (which never made an API call at all). A worksheet is
    // "Pending" until a matching EvaluationReport.worksheetId shows up for
    // each of its studentIds — a paper takes hours (print, exam, scan)
    // between generation and results, so this reflects real turnaround
    // time instead of only ever showing "Evaluated" or nothing at all.
    const reportsByWorksheet = new Map<string, EvaluationReport[]>();
    reportsList.forEach(r => {
      if (!r.worksheetId) return;
      if (!reportsByWorksheet.has(r.worksheetId)) reportsByWorksheet.set(r.worksheetId, []);
      reportsByWorksheet.get(r.worksheetId)!.push(r);
    });
    const rows = worksheetsList.map(w => {
      const total = w.studentIds?.length ?? 0;
      const evaluated = reportsByWorksheet.get(w.id) ?? [];
      const evaluatedStudentIds = new Set(evaluated.map(r => r.studentId));
      const evaluatedCount = evaluatedStudentIds.size;
      const pendingCount = Math.max(0, total - evaluatedCount);
      const status: 'Evaluated' | 'Partial' | 'Pending' =
        pendingCount === 0 && total > 0 ? 'Evaluated' : evaluatedCount > 0 ? 'Partial' : 'Pending';
      const avgPct = evaluated.length > 0
        ? Math.round(evaluated.reduce((a, r) => a + (r.score / r.totalQuestions) * 100, 0) / evaluated.length)
        : null;
      return { worksheet: w, total, evaluatedCount, pendingCount, status, avgPct };
    }).sort((a, b) => new Date(b.worksheet.date).getTime() - new Date(a.worksheet.date).getTime());

    const totalWorksheets = rows.length;
    const evaluatedCount = rows.filter(r => r.status === 'Evaluated').length;
    const pendingCount = rows.filter(r => r.status !== 'Evaluated').length;

    const statusStyle: Record<string, string> = {
      Evaluated: 'text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800',
      Partial: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800',
      Pending: 'text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700',
    };

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <MetricCard title="Total Worksheets" value={totalWorksheets} subtext="Across all cycles" icon={ClipboardList} />
          <MetricCard title="Evaluated" value={evaluatedCount} subtext="All students graded" icon={CheckCircle2} />
          <MetricCard title="Pending" value={pendingCount} subtext="Awaiting scan/evaluation" icon={FileText} />
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm">
          <PageHeader title="Worksheet Cycles" desc="Baseline, Mid-year, and End-of-year assessments" />
          <div className="space-y-3 mt-4">
            {rows.length === 0 && (
              <div className="text-sm text-slate-400 dark:text-slate-500 py-4 text-center">No worksheets generated yet.</div>
            )}
            {rows.map(({ worksheet: w, total, evaluatedCount: ec, status, avgPct }) => (
              <div key={w.id} className="flex justify-between items-center p-4 border border-slate-200 dark:border-slate-700 rounded-lg">
                <div><div className="font-semibold text-sm">{w.cycle} — {w.className}{w.section ? ` ${w.section}` : ''}</div><div className="text-xs text-slate-400 dark:text-slate-500">{new Date(w.date).toLocaleDateString()} · {ec}/{total} evaluated</div></div>
                <div className="text-right"><span className={`text-xs font-mono font-bold px-2 py-1 rounded ${statusStyle[status]}`}>{status}</span><div className="text-xs text-slate-400 dark:text-slate-500 mt-1">Avg: {avgPct !== null ? `${avgPct}%` : '—'}</div></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
};
