// Admin Aadhaar Reveal — Step-Up UX dialog.
//
// Drives the three-stage vault step-up workflow from a single admin-facing
// dialog: (1) enroll MFA, (2) request challenge + show QR, (3) approve with
// TOTP, (4) detokenize. The plaintext Aadhaar is the ONLY time the backend
// returns it; this dialog auto-clears it after 60s and on dialog close.
//
// SECURITY: this dialog talks ONLY to the FLN backend (/api/students/.../
// aadhaar/*). It never imports a Vault client, never holds the Vault
// service JWT, never persists plaintext Aadhaar in localStorage / IndexedDB.
import React, { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { apiFetch } from '../../services/apiClient';
import { Student } from '../../types';

type Phase =
  | 'idle'           // pre-enroll — show "Begin" button
  | 'enrolling'      // POST /mfa/enroll in flight
  | 'awaiting_totp'  // challenge minted; admin types TOTP
  | 'approving'      // POST /step-up/approve in flight
  | 'detokenizing'   // POST /detokenize in flight
  | 'revealed'       // plaintext visible (auto-clears)
  | 'error';

type Props = {
  student: Student;
  token: string;
  onClose: () => void;
};

const AUTO_CLEAR_MS = 60_000; // 60s — see AadhaarRevealPanel.tsx comment

export const AadhaarRevealDialog: React.FC<Props> = ({ student, token, onClose }) => {
  const [phase, setPhase] = useState<Phase>('idle');
  const [factorId, setFactorId] = useState<string>('');
  const [otpauthUri, setOtpauthUri] = useState<string>('');
  const [challengeId, setChallengeId] = useState<string>('');
  const [expiresAt, setExpiresAt] = useState<string>('');
  const [totpCode, setTotpCode] = useState<string>('');
  const [aadhaar, setAadhaar] = useState<string>('');
  const [last4, setLast4] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [countdown, setCountdown] = useState<number>(AUTO_CLEAR_MS / 1000);

  // Defensive: if the dialog unmounts or the user clicks outside, clear
  // the plaintext from React state immediately. The plaintext also clears
  // automatically after AUTO_CLEAR_MS via the timer below.
  useEffect(() => () => {
    setAadhaar('');
    setTotpCode('');
  }, []);

  // Auto-clear timer for the revealed plaintext.
  useEffect(() => {
    if (phase !== 'revealed') return;
    setCountdown(AUTO_CLEAR_MS / 1000);
    const tick = setInterval(() => setCountdown(s => Math.max(0, s - 1)), 1000);
    const stop = setTimeout(() => {
      setAadhaar('');
      setLast4('');
      setPhase('idle');
    }, AUTO_CLEAR_MS);
    return () => { clearInterval(tick); clearTimeout(stop); };
  }, [phase]);

  // Render the QR when otpauthUri changes.
  useEffect(() => {
    if (!otpauthUri) { setQrDataUrl(''); return; }
    let cancelled = false;
    QRCode.toDataURL(otpauthUri, { margin: 1, scale: 5, errorCorrectionLevel: 'M' })
      .then(url => { if (!cancelled) setQrDataUrl(url); })
      .catch(() => { if (!cancelled) setQrDataUrl(''); });
    return () => { cancelled = true; };
  }, [otpauthUri]);

  // Auth helper — keeps the Auth header consistent with apiClient.ts's
  // behavior. We pass an explicit Authorization so the dialog works even
  // if apiClient's localStorage token check races.
  const apiCall = async <T,>(method: string, path: string, body?: unknown): Promise<T> => {
    const res = await apiFetch(path, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json: any = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (json && typeof json.message === 'string') ? json.message : `HTTP ${res.status}`;
      throw new Error(`${json?.error || 'vault_error'}: ${msg}`);
    }
    return json as T;
  };

  const onEnroll = async () => {
    setErrorMsg('');
    setPhase('enrolling');
    try {
      const r = await apiCall<{ factorId: string; otpauthUri: string }>(
        'POST',
        `/api/students/${student.id}/aadhaar/mfa/enroll`,
        { label: `FLN admin reveal for ${student.name}` },
      );
      setFactorId(r.factorId);
      setOtpauthUri(r.otpauthUri);
      // Immediately request the step-up challenge so the admin doesn't
      // need a second click before they can type the TOTP code.
      await onRequestStepUp(r.factorId);
    } catch (err: any) {
      setErrorMsg(err?.message || 'MFA enrollment failed.');
      setPhase('error');
    }
  };

  const onRequestStepUp = async (factor: string) => {
    try {
      const r = await apiCall<{ challengeId: string; expiresAt: string }>(
        'POST',
        `/api/students/${student.id}/aadhaar/step-up/request`,
        { factorId: factor },
      );
      setChallengeId(r.challengeId);
      setExpiresAt(r.expiresAt);
      setPhase('awaiting_totp');
    } catch (err: any) {
      setErrorMsg(err?.message || 'Step-up request failed.');
      setPhase('error');
    }
  };

  const onApprove = async () => {
    if (!/^[0-9]{6,10}$/.test(totpCode)) {
      setErrorMsg('Enter a 6-digit TOTP code.');
      return;
    }
    setErrorMsg('');
    setPhase('approving');
    try {
      await apiCall<{ challengeId: string; status: string }>(
        'POST',
        `/api/students/${student.id}/aadhaar/step-up/approve`,
        { challengeId, code: totpCode },
      );
      await onDetokenize();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Step-up approval failed.');
      setPhase('awaiting_totp'); // let the admin try again with a fresh code
    }
  };

  const onDetokenize = async () => {
    setPhase('detokenizing');
    try {
      const r = await apiCall<{ aadhaar: string; last4: string; aadharMasked: string }>(
        'POST',
        `/api/students/${student.id}/aadhaar/detokenize`,
        { challengeId },
      );
      setAadhaar(r.aadhaar);
      setLast4(r.last4);
      setPhase('revealed');
    } catch (err: any) {
      setErrorMsg(err?.message || 'Detokenization failed.');
      setPhase('error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 dark:bg-slate-950/80 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-white dark:bg-slate-900 rounded-lg shadow-xl w-full max-w-lg p-6 border border-slate-200 dark:border-slate-800"
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-labelledby="aadhaar-reveal-title"
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 id="aadhaar-reveal-title" className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              Reveal Aadhaar — {student.name}
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              Stored as <span className="font-mono">{student.aadharMasked}</span>.
              Plaintext requires Step-Up authentication (4 steps).
            </p>
          </div>
          <button
            type="button"
            onClick={() => { setAadhaar(''); setTotpCode(''); onClose(); }}
            className="text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 text-xl leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {errorMsg && (
          <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded text-sm border border-red-200 dark:border-red-800">
            {errorMsg}
          </div>
        )}

        {/* ── Step 1: Enroll MFA ─────────────────────────────────────── */}
        {phase === 'idle' && (
          <div className="space-y-4">
            <ol className="text-sm text-slate-600 dark:text-slate-400 space-y-1 list-decimal list-inside">
              <li>Enroll your TOTP authenticator (Google Authenticator / Authy / 1Password)</li>
              <li>Scan the QR code the backend returns</li>
              <li>Type the 6-digit code the app shows</li>
              <li>View the plaintext — it auto-clears after {AUTO_CLEAR_MS / 1000}s</li>
            </ol>
            <button
              type="button"
              onClick={onEnroll}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded font-medium"
            >
              Begin Step-Up (Enroll MFA)
            </button>
          </div>
        )}

        {(phase === 'enrolling') && (
          <div className="text-sm text-slate-500 dark:text-slate-400">Enrolling MFA factor…</div>
        )}

        {/* ── Step 2: Show QR + TOTP entry ─────────────────────────── */}
        {phase === 'awaiting_totp' && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">Scan this QR in your TOTP authenticator app:</p>
              {qrDataUrl ? (
                <img src={qrDataUrl} alt="TOTP enrollment QR" className="mx-auto border border-slate-200 dark:border-slate-700 rounded p-1" width="180" height="180" />
              ) : (
                <div className="text-xs text-slate-500">Rendering QR…</div>
              )}
              <details className="mt-2">
                <summary className="text-xs text-slate-500 cursor-pointer">Show otpauth URI</summary>
                <code className="block text-xs break-all bg-slate-100 dark:bg-slate-800 p-2 mt-1 rounded">{otpauthUri}</code>
              </details>
            </div>
            <div>
              <label htmlFor="totp" className="block text-sm font-medium mb-1">
                6-digit TOTP code
              </label>
              <input
                id="totp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={e => setTotpCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 10))}
                placeholder="123456"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-700 rounded font-mono text-lg bg-white dark:bg-slate-800"
              />
              <p className="text-xs text-slate-500 mt-1">
                Challenge expires {new Date(expiresAt).toLocaleTimeString()}.
              </p>
            </div>
            <button
              type="button"
              onClick={onApprove}
              disabled={totpCode.length < 6}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-400 text-white rounded font-medium"
            >
              Approve &amp; Detokenize
            </button>
          </div>
        )}

        {(phase === 'approving' || phase === 'detokenizing') && (
          <div className="text-sm text-slate-500 dark:text-slate-400">
            {phase === 'approving' ? 'Verifying TOTP…' : 'Recovering plaintext…'}
          </div>
        )}

        {/* ── Step 3: Reveal plaintext ─────────────────────────────── */}
        {phase === 'revealed' && (
          <div className="space-y-3">
            <div className="p-4 bg-amber-50 dark:bg-amber-900/30 border border-amber-300 dark:border-amber-700 rounded">
              <p className="text-xs font-medium text-amber-700 dark:text-amber-300 uppercase tracking-wide">
                Plaintext Aadhaar — TEMPORARY
              </p>
              <p className="mt-1 text-2xl font-mono font-semibold tracking-wider text-slate-900 dark:text-slate-100">
                {aadhaar}
              </p>
              <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">
                Auto-clears in <span className="font-mono">{countdown}s</span>.
                Do not screenshot, copy to clipboard, or write down.
              </p>
            </div>
            <button
              type="button"
              onClick={() => { setAadhaar(''); setLast4(''); setPhase('idle'); }}
              className="w-full py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-900 dark:text-slate-100 rounded font-medium"
            >
              Clear Now
            </button>
          </div>
        )}

        {phase === 'error' && (
          <div className="space-y-3">
            <button
              type="button"
              onClick={() => { setErrorMsg(''); setPhase('idle'); }}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded font-medium"
            >
              Restart Step-Up
            </button>
          </div>
        )}
      </div>
    </div>
  );
};