// Admin Aadhaar Reveal Panel — top-level entry to the Step-Up detokenization UX.
//
// Lists every student the current admin can access (the same scope as the
// role-aware `/api/students` filter) with a "Reveal" button per row. Clicking
// opens the AadhaarRevealDialog which drives the 3-stage vault step-up flow.
//
// Only SUPERADMIN / ADMIN / DISTRICT_ADMIN / BLOCK_ADMIN can see the panel —
// the backend mirrors this gate on every route under
// backend/src/routes/aadhaarDetokenize.ts. The frontend gate here is purely
// for UX (don't even render the menu item for teachers / volunteers).
import React, { useMemo, useState } from 'react';
import { ShieldCheck, Search } from 'lucide-react';
import { Student, User, UserRole } from '../../types';
import { PageHeader, EmptyStudents } from './PanelShared';
import { AadhaarRevealDialog } from './AadhaarRevealDialog';

interface Props {
  students: Student[];
  currentUser: User;
  token: string;
}

const ALLOWED_ROLES: ReadonlyArray<UserRole> = [
  UserRole.SUPERADMIN,
  UserRole.ADMIN,
  UserRole.DISTRICT_ADMIN,
  UserRole.BLOCK_ADMIN,
];

export const AadhaarRevealPanel: React.FC<Props> = ({ students, currentUser, token }) => {
  const [query, setQuery] = useState('');
  const [target, setTarget] = useState<Student | null>(null);

  const visibleStudents = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return students;
    return students.filter(s =>
      s.name.toLowerCase().includes(q) ||
      (s.displayId && s.displayId.toLowerCase().includes(q)) ||
      s.aadharMasked.toLowerCase().includes(q),
    );
  }, [students, query]);

  if (!ALLOWED_ROLES.includes(currentUser.role)) {
    // Defence-in-depth: the Layout menu shouldn't render this panel for
    // non-admin roles, but if it does (e.g. via a stale hash), fail closed.
    return (
      <div className="p-8 max-w-3xl mx-auto">
        <PageHeader title="Aadhaar Reveal" desc="Step-Up detokenization (admin only)" icon={ShieldCheck} />
        <p className="text-slate-600 dark:text-slate-400">
          This panel is restricted to admins. Your role ({currentUser.role}) cannot reveal plaintext Aadhaar.
        </p>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <PageHeader
        title="Aadhaar Reveal"
        desc="Step-Up detokenization for correction / audit / legal requests."
        icon={ShieldCheck}
      />

      <div className="mb-4 p-4 bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-800 rounded text-sm text-amber-900 dark:text-amber-200">
        <strong>Privacy notice.</strong> Plaintext Aadhaar is shown temporarily (60s auto-clear) for the
        purpose of correcting enrollment mistakes or responding to a verified audit/legal request. It is
        never persisted in this app and never logged. Every reveal is recorded with a vault audit id.
      </div>

      <div className="mb-4 flex items-center gap-2">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="search"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search by name / displayId / masked Aadhaar…"
            className="w-full pl-9 pr-3 py-2 border border-slate-300 dark:border-slate-700 rounded bg-white dark:bg-slate-900"
          />
        </div>
        <div className="text-sm text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {visibleStudents.length} of {students.length}
        </div>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-200">
            <tr>
              <th className="text-left px-4 py-2">Student</th>
              <th className="text-left px-4 py-2">Class</th>
              <th className="text-left px-4 py-2">School</th>
              <th className="text-left px-4 py-2">Masked Aadhaar</th>
              <th className="text-right px-4 py-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {visibleStudents.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-slate-500"><EmptyStudents students={visibleStudents} /></td></tr>
            )}
            {visibleStudents.map(s => (
              <tr key={s.id} className="border-t border-slate-100 dark:border-slate-800">
                <td className="px-4 py-2">
                  <div className="font-medium">{s.name}</div>
                  {s.displayId && <div className="text-xs text-slate-500 font-mono">{s.displayId}</div>}
                </td>
                <td className="px-4 py-2">{s.classGroup} / {s.section}</td>
                <td className="px-4 py-2 text-xs text-slate-600 dark:text-slate-400">{s.schoolId}</td>
                <td className="px-4 py-2 font-mono">{s.aadharMasked}</td>
                <td className="px-4 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => setTarget(s)}
                    className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-xs font-medium"
                  >
                    Reveal
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {target && (
        <AadhaarRevealDialog
          student={target}
          token={token}
          onClose={() => setTarget(null)}
        />
      )}
    </div>
  );
};