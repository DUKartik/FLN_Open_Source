// Extracted from frontend/src/components/PanelViews.tsx (issue #144, PR 2).
import React from 'react';
import { PageHeader } from './PanelShared';
import { MetricCard } from '../Card';
import { SlidersHorizontal, Users, BarChart3, CheckCircle2 } from 'lucide-react';

export const AdaptiveTestPanel: React.FC = () => {
  return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-6">
        <PageHeader title="Adaptive Assessment" desc="Computer-adaptive testing that adjusts to student ability" icon={<SlidersHorizontal className="h-5 w-5" />} />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <MetricCard title="Active Sessions" value="3" subtext="Students currently testing" icon={Users} />
          <MetricCard title="Avg Adaptive Score" value="72%" subtext="Across all levels" icon={BarChart3} />
          <MetricCard title="Completion Rate" value="85%" subtext="Tests finished on time" icon={CheckCircle2} />
        </div>
        <div className="border border-slate-200 dark:border-slate-700 rounded-lg p-5 bg-slate-50 dark:bg-slate-800 space-y-3">
          <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">How Adaptive Testing Works</h4>
          <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">The system selects questions dynamically based on the student's previous answers. Correct answers lead to harder questions; incorrect answers adjust to easier ones. This pinpoints the exact FLN level.</p>
          <div className="flex gap-4 pt-2">
            <button className="bg-slate-900 text-white text-xs font-medium px-4 py-2 rounded-lg hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-200">Start New Adaptive Test</button>
            <button className="border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium px-4 py-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700">View Session Logs</button>
          </div>
        </div>
      </div>
  );
};
