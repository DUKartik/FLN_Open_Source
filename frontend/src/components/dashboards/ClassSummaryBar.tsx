// Issue #172 + #167: a real "how is my class doing today?" summary bar for
// the Teacher Dashboard, folding in the stats + Top Performing Students list
// that used to live on the standalone Performance page (now removed).
import React from 'react';
import { Student } from '../../types';
import { MetricCard } from '../Card';
import { Users, BarChart3, TrendingUp, TrendingDown } from 'lucide-react';

export const ClassSummaryBar: React.FC<{ students: Student[] }> = ({ students }) => {
  const total = students.length;
  const assessed = students.filter(s => s.levelHistory.length > 0).length;
  const pending = total - assessed;

  // Issue #172 originally asked for "percentage at or above their target
  // level" — but targetLevel is defined as currentLevel + 1 essentially
  // everywhere it's set in this codebase, so that comparison is true for
  // almost no student by construction and would show a near-0% "on track"
  // figure for every class regardless of actual performance (the mirror
  // image of the same targetLevel quirk found while building #183's
  // gap-analysis engine). currentSubLevel === 0 (Mastery — the real,
  // already-computed signal for "doing well at their current level") is
  // used instead.
  const onTrack = students.filter(s => s.currentSubLevel === 0).length;
  const onTrackPercent = total > 0 ? Math.round((onTrack / total) * 100) : 0;

  const regressed = students.filter(s => {
    if (s.levelHistory.length < 2) return false;
    const last = s.levelHistory[s.levelHistory.length - 1];
    const prev = s.levelHistory[s.levelHistory.length - 2];
    return last.level < prev.level;
  }).length;

  const topStudents = [...students].sort((a, b) => (b.currentLevel ?? 0) - (a.currentLevel ?? 0)).slice(0, 5);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard title="Total Students" value={total} subtext="Active roster" icon={Users} />
        <MetricCard title="Assessed / Pending" value={`${assessed} / ${pending}`} subtext="This cycle" icon={BarChart3} />
        <MetricCard title="On Track" value={`${onTrackPercent}%`} subtext="Mastery at current level" icon={TrendingUp} />
        <MetricCard title="Regressed" value={regressed} subtext="Level dropped since last cycle" icon={TrendingDown} />
      </div>
      {topStudents.length > 0 && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm">
          <h4 className="text-xs font-mono font-bold text-slate-500 dark:text-slate-400 uppercase mb-3">Top Performing Students</h4>
          <div className="space-y-2">
            {topStudents.map(s => (
              <div key={s.id} className="flex justify-between items-center p-3 border border-slate-100 dark:border-slate-700 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-semibold">{s.name}</span>
                  <span className="text-xs text-slate-400 dark:text-slate-500">{s.classGroup}</span>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-32 h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                    <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${((s.currentLevel ?? 0) / 93) * 100}%` }} />
                  </div>
                  <span className="font-mono font-bold text-sm">L{s.currentLevel ?? 0}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
