// Extracted from frontend/src/components/PanelViews.tsx (issue #144, PR 7).
// Internally role-branches: State Admin gets a district drill-down
// sub-view, every other role gets the flat evaluation-list view.
import React, { useState } from 'react';
import { User, UserRole, School, Student, EvaluationReport } from '../../types';
import { PageHeader } from './PanelShared';
import { MetricCard } from '../Card';
import { handleDownloadPDF } from './pdfReportGenerator';
import { FileText, BarChart3, School as SchoolIcon, MapPin, ChevronDown, Award } from 'lucide-react';
import { DISTRICT_NAMES } from '../../constants';

export const ReportsPanel: React.FC<{
  currentUser: User;
  schools: School[];
  students: Student[];
  reportsList: EvaluationReport[];
}> = ({ currentUser, schools, students, reportsList }) => {
  const [expandedDistRpt, setExpandedDistRpt] = useState<string | null>(null);

    const isStateAdmin = currentUser.role === UserRole.ADMIN;
    if (isStateAdmin) {
      const userState = currentUser.stateCode || 'PB';
      const stateSchools = schools.filter(s => s.stateCode === userState);
      const stateDistricts = Array.from(new Set(stateSchools.map(s => s.districtCode))) as string[];
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <MetricCard title="Total Reports" value={reportsList.length} subtext="All evaluations" icon={FileText} />
            <MetricCard title="Avg Score" value={reportsList.length > 0 ? `${Math.round(reportsList.reduce((a, r) => a + (r.score / r.totalQuestions) * 100, 0) / reportsList.length)}%` : '—'} subtext="Across reports" icon={BarChart3} />
            <MetricCard title="Schools" value={stateSchools.length} subtext={`In ${userState}`} icon={SchoolIcon} />
            <MetricCard title="Districts" value={stateDistricts.length} subtext="Active jurisdictions" icon={MapPin} />
          </div>
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-5 shadow-sm">
            <PageHeader title={`District-Wise School Reports — ${userState}`} desc="Evaluation reports organized by district and school" />
            <div className="space-y-3 mt-4">{stateDistricts.map(dc => {
              const isExpanded = expandedDistRpt === dc;
              const distSchools = stateSchools.filter(s => s.districtCode === dc);
              return (
                <div key={dc}>
                  <button onClick={() => setExpandedDistRpt(isExpanded ? null : dc)} className={`w-full flex items-center gap-3 p-3 border rounded-lg text-left hover:bg-slate-50 dark:hover:bg-slate-800 transition-all ${isExpanded ? 'border-indigo-300 dark:border-indigo-700 bg-indigo-50 dark:bg-indigo-950' : 'border-slate-100 dark:border-slate-700'}`}>
                    <span className="font-bold text-sm w-16">{dc}</span>
                    <span className="text-sm flex-1">{DISTRICT_NAMES[dc] || dc}</span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{distSchools.length} schools</span>
                    <ChevronDown className={`w-4 h-4 text-slate-400 dark:text-slate-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                  </button>
                  {isExpanded && (
                    <div className="ml-6 mt-2 space-y-4 pl-4 border-l-2 border-indigo-200 dark:border-indigo-800">
                      {distSchools.map(sch => {
                        const schStudents = students.filter(st => st.schoolId === sch.id);
                        const schReports = reportsList.filter(r => schStudents.some(st => st.id === r.studentId));
                        const avgScore = schReports.length > 0 ? Math.round(schReports.reduce((a, r) => a + (r.score / r.totalQuestions) * 100, 0) / schReports.length) : 0;
                        return (
                          <div key={sch.id} className="border border-slate-200 dark:border-slate-700 rounded-xl p-4">
                            <div className="flex justify-between items-center mb-3"><h4 className="font-bold text-slate-900 dark:text-white text-sm">{sch.name}</h4><span className="text-xs text-slate-400 dark:text-slate-500">{sch.blockCode} · {sch.strength}</span></div>
                            <div className="grid grid-cols-3 gap-3 mb-3">
                              <div className="text-center bg-slate-50 dark:bg-slate-800 rounded-lg p-2"><div className="text-lg font-bold text-slate-900 dark:text-white">{schReports.length}</div><div className="text-[10px] text-slate-400 dark:text-slate-500">Reports</div></div>
                              <div className="text-center bg-slate-50 dark:bg-slate-800 rounded-lg p-2"><div className={`text-lg font-bold ${avgScore >= 70 ? 'text-emerald-600' : 'text-amber-600'}`}>{avgScore}%</div><div className="text-[10px] text-slate-400 dark:text-slate-500">Avg Score</div></div>
                              <div className="text-center bg-slate-50 dark:bg-slate-800 rounded-lg p-2"><div className="text-lg font-bold text-slate-900 dark:text-white">{schStudents.length}</div><div className="text-[10px] text-slate-400 dark:text-slate-500">Students</div></div>
                            </div>
                            {schReports.length > 0 ? (
                              <div className="space-y-2">{schReports.map(r => {
                                const student = schStudents.find(st => st.id === r.studentId);
                                const scorePct = Math.round((r.score / r.totalQuestions) * 100);
                                return (
                                  <div key={r.id} className="border border-slate-100 dark:border-slate-700 rounded-lg p-3 text-sm">
                                    <div className="flex justify-between items-center"><span className="font-semibold">{student?.name || 'N/A'}</span><span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${scorePct >= 80 ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300' : scorePct >= 60 ? 'bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300' : 'bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300'}`}>{r.score}/{r.totalQuestions} ({scorePct}%)</span></div>
                                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{r.narrative}</p>
                                    <div className="flex gap-1 mt-1.5">{Object.entries(r.conceptMastery).map(([t, m]) => (
                                      <span key={t} className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${m === 'Strong' ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800' : m === 'Satisfactory' ? 'bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800' : 'bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'}`}>{t}</span>
                                    ))}</div>
                                  </div>
                                );
                              })}</div>
                            ) : <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-3">No evaluation reports for this school yet.</p>}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}</div>
          </div>
        </div>
      );
    }
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <MetricCard title="Total Reports" value={reportsList.length} subtext="All evaluations" icon={FileText} />
          <MetricCard title="Avg Score" value={reportsList.length > 0 ? `${Math.round(reportsList.reduce((a, r) => a + (r.score / r.totalQuestions) * 100, 0) / reportsList.length)}%` : '—'} subtext="Across reports" icon={BarChart3} />
          <MetricCard title="Strong Concepts" value={reportsList.reduce((a, r) => a + Object.values(r.conceptMastery).filter(v => v === 'Strong').length, 0)} subtext="Mastered topics" icon={Award} />
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-4">
          <PageHeader title="Evaluation Reports" desc="Detailed assessment narratives and concept mastery breakdowns" />
          {reportsList.map(r => {
            const student = students.find(s => s.id === r.studentId);

            return (
              <div key={r.id} className="border border-slate-200 dark:border-slate-700 rounded-lg p-4 space-y-3 hover:border-slate-300 dark:hover:border-slate-600 transition-all">
                <div className="flex justify-between items-center"><span className="font-semibold text-sm">{student?.name || 'Unknown'}</span><span className="text-xs text-slate-400 dark:text-slate-500">{new Date(r.timestamp).toLocaleDateString()}</span></div>
                <div className="flex gap-4 text-sm"><span>Score: <strong>{r.score}/{r.totalQuestions}</strong></span><span>Level: <strong>L{r.recommendedLevel}.{r.recommendedSubLevel ?? 0}</strong></span></div>
                
                <div className="bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-700 rounded-lg p-3">
                  <span className="text-[9px] font-mono font-bold uppercase text-slate-400 dark:text-slate-500 tracking-wider">Evaluation Report Narrative</span>
                  <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed whitespace-pre-line">{r.narrative}</p>
                </div>

                <div className="flex flex-wrap gap-2">{Object.entries(r.conceptMastery).map(([t, m]) => (
                  <span key={t} className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${m === 'Strong' ? 'bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800' : m === 'Satisfactory' ? 'bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800' : 'bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'}`}>{t}: {m}</span>
                ))}</div>

                <div className="pt-2 border-t border-slate-100 dark:border-slate-700 flex justify-between items-center">
                  <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">Per-question answer detail not yet available</span>
                  {student && (
                    <button onClick={() => handleDownloadPDF(student, r)} className="text-xs font-semibold text-emerald-650 hover:text-emerald-800 flex items-center gap-1">
                      📥 Download PDF Report
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
};
