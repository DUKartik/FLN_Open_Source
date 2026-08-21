// Issue #175: rebuild — CSV upload (feeds #178's real bulk-import endpoint),
// then the existing BulkDiagnosticWorkflow (reused as-is, not rewritten —
// it already calls the real POST /api/diagnostic/bulk route), plus a simple
// on-screen exam timer. Pending/Completed lists kept below as supplementary
// context, same data as before.
import React, { useState, useEffect, useRef } from 'react';
import { Student, User } from '../../types';
import { PageHeader } from './PanelShared';
import { ShieldAlert, CheckCircle2, Upload, Timer as TimerIcon } from 'lucide-react';
import { apiFetch } from '../../services/apiClient';
import { parseCSVText } from '../RoleDashboards';
import { BulkDiagnosticWorkflow } from '../BulkDiagnosticWorkflow';

interface DiagnosticTestPanelProps {
  students: Student[];
  currentUser: User;
  token: string;
  refreshStudents: () => void;
}

const TIMER_PRESETS_MIN = [15, 30, 45, 60];

export const DiagnosticTestPanel: React.FC<DiagnosticTestPanelProps> = ({ students, currentUser, token, refreshStudents }) => {
  const pending = students.filter(s => s.levelHistory.length === 0);
  const completed = students.filter(s => s.levelHistory.length > 0);

  // CSV upload
  const [showCsvImport, setShowCsvImport] = useState(false);
  const [csvImporting, setCsvImporting] = useState(false);
  const [csvResults, setCsvResults] = useState<any>(null);
  const [csvError, setCsvError] = useState('');

  const handleCsvUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCsvError('');
    setCsvResults(null);
    setCsvImporting(true);
    try {
      const text = await file.text();
      const rows = parseCSVText(text);
      const res = await apiFetch('/api/students/bulk-import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ rows }),
      });
      const data = await res.json();
      if (!res.ok) {
        setCsvError(data.error || 'Import failed.');
      } else {
        setCsvResults(data);
        refreshStudents();
      }
    } catch (err: any) {
      setCsvError(err.message || 'Failed to read or import the CSV file.');
    } finally {
      setCsvImporting(false);
      e.target.value = '';
    }
  };

  // Simple exam timer — purely client-side, no backend dependency. Counts
  // down from a chosen duration for the in-class exam window.
  const [timerMinutes, setTimerMinutes] = useState(30);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);
  const [timerRunning, setTimerRunning] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (timerRunning && secondsLeft !== null && secondsLeft > 0) {
      intervalRef.current = setInterval(() => {
        setSecondsLeft(s => (s !== null && s > 0 ? s - 1 : 0));
      }, 1000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [timerRunning, secondsLeft === null]);

  useEffect(() => {
    if (secondsLeft === 0) setTimerRunning(false);
  }, [secondsLeft]);

  const startTimer = () => { setSecondsLeft(timerMinutes * 60); setTimerRunning(true); };
  const pauseTimer = () => setTimerRunning(false);
  const resumeTimer = () => { if (secondsLeft && secondsLeft > 0) setTimerRunning(true); };
  const resetTimer = () => { setTimerRunning(false); setSecondsLeft(null); };
  const formatTime = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

  return (
    <div className="space-y-6">
      {/* CSV upload */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <PageHeader title="Upload Class Roster" desc="Bring in a whole class via CSV before generating diagnostic papers" icon={<Upload className="h-5 w-5" />} />
          <button
            onClick={() => { setShowCsvImport(!showCsvImport); setCsvResults(null); setCsvError(''); }}
            className="bg-emerald-700 hover:bg-emerald-600 text-white font-medium text-xs font-mono px-4 py-2.5 rounded-lg transition-colors cursor-pointer shrink-0"
          >
            {showCsvImport ? 'Close CSV Import' : '⬆ Bulk Import CSV'}
          </button>
        </div>
        {showCsvImport && (
          <div className="border-t border-slate-100 dark:border-slate-800 pt-4 space-y-3">
            <p className="text-[10px] text-slate-400 dark:text-slate-500">
              Required columns: <code className="bg-slate-100 dark:bg-slate-800 px-1 rounded">name, section, age, classGroup, aadharNumber, address</code>
            </p>
            {csvError && (
              <div className="p-3 text-xs bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 rounded-lg border border-red-100 dark:border-red-800 font-medium">⚠️ {csvError}</div>
            )}
            <input
              type="file"
              accept=".csv,text/csv"
              className="block w-full text-xs text-slate-600 dark:text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-mono file:font-semibold file:bg-emerald-50 dark:file:bg-emerald-950 file:text-emerald-700 dark:file:text-emerald-300 hover:file:bg-emerald-100 dark:hover:file:bg-emerald-900 cursor-pointer"
              onChange={handleCsvUpload}
            />
            {csvImporting && (
              <div className="text-xs font-mono text-emerald-600 dark:text-emerald-400 animate-pulse flex items-center gap-2">
                <span className="animate-spin">⏳</span> Importing students…
              </div>
            )}
            {csvResults && (
              <div className="text-xs font-mono bg-slate-50 dark:bg-slate-900/50 p-3 rounded-lg border border-slate-100 dark:border-slate-800">
                <span className="text-green-700 dark:text-green-400 font-bold">✅ {csvResults.total - csvResults.failed} valid</span>
                <span className="mx-2 text-slate-300">|</span>
                <span className="text-red-700 dark:text-red-400 font-bold">❌ {csvResults.failed} invalid</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Exam timer */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-4">
        <PageHeader title="Exam Timer" desc="A simple on-screen timer for the in-class exam window" icon={<TimerIcon className="h-5 w-5" />} />
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex gap-2">
            {TIMER_PRESETS_MIN.map(m => (
              <button
                key={m}
                onClick={() => setTimerMinutes(m)}
                disabled={secondsLeft !== null}
                className={`px-3 py-1.5 text-xs font-mono font-bold rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                  timerMinutes === m ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 border-transparent' : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300'
                }`}
              >
                {m}m
              </button>
            ))}
          </div>
          <div className="font-mono text-2xl font-bold text-slate-900 dark:text-white tabular-nums">
            {secondsLeft !== null ? formatTime(secondsLeft) : `${String(timerMinutes).padStart(2, '0')}:00`}
          </div>
          <div className="flex gap-2">
            {secondsLeft === null && (
              <button onClick={startTimer} className="bg-emerald-700 hover:bg-emerald-600 text-white font-mono text-xs font-bold px-4 py-2 rounded-lg transition-colors">Start</button>
            )}
            {secondsLeft !== null && secondsLeft > 0 && timerRunning && (
              <button onClick={pauseTimer} className="bg-amber-600 hover:bg-amber-700 text-white font-mono text-xs font-bold px-4 py-2 rounded-lg transition-colors">Pause</button>
            )}
            {secondsLeft !== null && secondsLeft > 0 && !timerRunning && (
              <button onClick={resumeTimer} className="bg-emerald-700 hover:bg-emerald-600 text-white font-mono text-xs font-bold px-4 py-2 rounded-lg transition-colors">Resume</button>
            )}
            {secondsLeft !== null && (
              <button onClick={resetTimer} className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 font-mono text-xs font-bold px-4 py-2 rounded-lg transition-colors">Reset</button>
            )}
          </div>
          {secondsLeft === 0 && <span className="text-xs font-mono font-bold text-red-600 dark:text-red-400">⏰ Time's up</span>}
        </div>
      </div>

      {/* Bulk diagnostic generation — reuses the existing, already-working
          BulkDiagnosticWorkflow (previously only reachable from a Dashboard
          card that #166 is removing) instead of writing new calling code. */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm">
        <BulkDiagnosticWorkflow user={currentUser} token={token} userRole={currentUser.role} />
      </div>

      {/* Supplementary status lists */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-4">
          <PageHeader title="Pending Diagnostics" desc={`${pending.length} students need initial assessment`} icon={<ShieldAlert className="h-5 w-5 text-amber-500" />} />
          {pending.length === 0 ? <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8">All students placed.</p> : (
            <div className="space-y-3">{pending.map(s => (
              <div key={s.id} className="flex justify-between items-center p-3 border border-slate-200 dark:border-slate-700 rounded-lg">
                <div><div className="font-medium text-sm">{s.name}</div><div className="text-xs text-slate-400 dark:text-slate-500">{s.classGroup} - {s.section}</div></div>
                <span className="text-[10px] font-mono font-bold text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950 px-2 py-1 rounded border border-amber-200 dark:border-amber-800">Run Diagnostic</span>
              </div>
            ))}</div>
          )}
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl p-6 shadow-sm space-y-4">
          <PageHeader title="Completed Diagnostics" desc={`${completed.length} students have been placed`} icon={<CheckCircle2 className="h-5 w-5 text-green-500" />} />
          <div className="space-y-3">{completed.map(s => (
            <div key={s.id} className="flex justify-between items-center p-3 border border-slate-200 dark:border-slate-700 rounded-lg">
              <div><div className="font-medium text-sm">{s.name}</div><div className="text-xs text-slate-400 dark:text-slate-500">Placed at L{s.currentLevel}.{s.currentSubLevel ?? 0}</div></div>
              <span className="text-[10px] font-mono font-bold text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-950 px-2 py-1 rounded border border-green-200 dark:border-green-800">Completed</span>
            </div>
          ))}</div>
        </div>
      </div>
    </div>
  );
};
