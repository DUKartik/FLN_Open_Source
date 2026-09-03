// Admin Aadhaar Reveal — Step-Up UX dialog.
//
// Drives the three-stage vault step-up workflow from a single admin-facing
// dialog: (1) enroll MFA, (2) request challenge + show QR (first time
// only), (3) approve with TOTP, (4) detokenize. The plaintext Aadhaar is
// the ONLY time the backend returns it; this dialog auto-clears it after
// 60s and on dialog close.
//
// Two paths through the dialog — the cryptographic model is identical on
// both, only the UX differs:
//
//   First-time setup (no active factor):
//     idle → "Set up your authenticator" copy → click → enroll → QR +
//     manual URI toggle → awaiting_totp (challenge minted at the same
//     time) → TOTP code → approve → detokenize → revealed.
//
//   Returning admin (an active factor already exists):
//     preflight → alreadyEnrolled === true → awaiting_totp directly
//     (no QR; the secret never re-crosses the wire) → TOTP code →
//     approve → detokenize → revealed.
//
// SECURITY: this dialog talks ONLY to the FLN backend (/api/students/.../
// aadhaar/*). It never imports a Vault client, never holds the Vault
// service JWT, never persists plaintext Aadhaar in localStorage / IndexedDB.
import React, { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { apiFetch } from '../../services/apiClient';
import { Student } from '../../types';

type Phase =
  | 'preflight'      // GET /mfa/me in flight — checking for existing factor
  | 'idle'           // pre-enroll — show "Begin" button
  | 'enrolling'      // POST /mfa/enroll in flight
  | 'awaiting_totp'  // challenge minted; admin types TOTP
  | 'approving'      // POST /step-up/approve in flight
  | 'detokenizing'   // POST /detokenize in flight
  | 'revealed'       // plaintext visible (auto-clears)
  | 'error';

type MfaFactorMeta = {
  factorId: string;
  label: string | null;
  algorithm: string;
  digits: number;
  period: number;
  createdAt: string;
};

type Props = {
  student: Student;
  token: string;
  onClose: () => void;
};

const AUTO_CLEAR_MS = 60_000; // 60s — see AadhaarRevealPanel.tsx comment
const PREFLIGHT_TIMEOUT_MS = 8_000; // see comment on the preflight useEffect

export const AadhaarRevealDialog: React.FC<Props> = ({ student, token, onClose }) => {
  const [phase, setPhase] = useState<Phase>('preflight');
  const [alreadyEnrolled, setAlreadyEnrolled] = useState<boolean>(false);
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
  // Bump to force the preflight useEffect to re-run. Used by the
  // "Retry check" button in the error state — the effect's dep is
  // `[student.id, preflightNonce]` so changing the nonce is enough
  // to re-fire the probe.
  const [preflightNonce, setPreflightNonce] = useState<number>(0);

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

  // Pre-flight probe: on mount (or when the user retries from the
  // error state), ask the backend if this admin already has an active
  // TOTP factor. If yes, jump straight to awaiting_totp. If no, drop
  // into `idle` and show the first-time enrollment screen.
  //
  // The previous version had a parameterless `catch` that silently
  // fell through to `idle` on any error. That looked correct but had
  // one failure mode: a HUNG request (no resolve, no reject) — e.g. a
  // dead Mongo connection inside `mfa.listActiveByActor` — left the
  // dialog on "Checking your authenticator enrollment…" forever. The
  // admin saw no QR, no TOTP field, and no error message; the × close
  // button was the only working action.
  //
  // Fix: an AbortController with an 8s timeout, and a catch that
  // transitions to the `error` phase with a useful message instead
  // of silently dropping the user into the first-time enroll path
  // (where a hung server would just hang the enroll call too). The
  // error phase offers Retry (re-runs this effect) and "Set up new
  // authenticator" (the explicit opt-in to first-time enroll).
  useEffect(() => {
    let cancelled = false;
    setPhase('preflight');
    setErrorMsg('');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PREFLIGHT_TIMEOUT_MS);

    (async () => {
      try {
        const r = await apiCall<{ factors: MfaFactorMeta[] }>(
          'GET',
          `/api/students/${student.id}/aadhaar/mfa/me`,
          undefined,
          { signal: controller.signal },
        );
        if (cancelled) return;
        if (Array.isArray(r.factors) && r.factors.length > 0) {
          // Returning admin — reuse the existing factor for this
          // reveal. We do NOT log or render the secret; the dialog
          // simply skips the QR.
          setAlreadyEnrolled(true);
          setFactorId(r.factors[0].factorId);
          await onRequestStepUp(r.factors[0].factorId);
        } else {
          setAlreadyEnrolled(false);
          setPhase('idle');
        }
      } catch (err: any) {
        if (cancelled) return;
        // The error must be visible — both in the dialog (so the
        // admin knows what to do) and in the console (so an
        // engineer debugging the production hang can see the raw
        // error without DevTools Network snooping).
        const isAbort = err?.name === 'AbortError' || controller.signal.aborted;
        if (isAbort) {
          console.warn(
            '[AadhaarReveal] preflight GET /mfa/me aborted after',
            `${PREFLIGHT_TIMEOUT_MS}ms — likely a hung backend (e.g. dead Mongo connection in mfa.listActiveByActor).`,
            { studentId: student.id },
          );
          setErrorMsg(
            `The server did not respond within ${PREFLIGHT_TIMEOUT_MS / 1000}s while checking your authenticator enrollment. ` +
            'Click "Retry check" to try again, or "Set up new authenticator" to enroll one now.',
          );
        } else {
          console.error('[AadhaarReveal] preflight failed:', err);
          setErrorMsg(
            (err?.message || 'Could not check your authenticator enrollment.') +
            ' Click "Retry check" to try again.',
          );
        }
        setPhase('error');
      } finally {
        clearTimeout(timeoutId);
      }
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [student.id, preflightNonce]);

  // Auth helper — keeps the Auth header consistent with apiClient.ts's
  // behavior. We pass an explicit Authorization so the dialog works even
  // if apiClient's localStorage token check races. The `init` argument is
  // merged into the fetch options so callers can pass a `signal` (e.g.
  // for the preflight timeout) without us having to thread it through
  // every signature.
  const apiCall = async <T,>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> => {
    const res = await apiFetch(path, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
      ...(init ?? {}),
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
      const r = await apiCall<{
        factorId: string;
        otpauthUri?: string;
        alreadyEnrolled: boolean;
      }>(
        'POST',
        `/api/students/${student.id}/aadhaar/mfa/enroll`,
        { label: `FLN admin reveal for ${student.name}` },
      );
      setFactorId(r.factorId);
      setAlreadyEnrolled(r.alreadyEnrolled);
      // Only the first-time path returns an `otpauthUri`; on a
      // returning-admin call the backend reuses the existing factor
      // and intentionally does NOT re-emit the secret.
      if (r.otpauthUri) setOtpauthUri(r.otpauthUri);
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
              Plaintext requires Step-Up authentication with your authenticator app.
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

        {/* ── Pre-flight: checking for an existing factor ─────────────── */}
        {phase === 'preflight' && (
          <div className="text-sm text-slate-500 dark:text-slate-400">
            Checking your authenticator enrollment…
          </div>
        )}

        {/* ── First-time setup: enroll + QR + TOTP entry ────────────── */}
        {phase === 'idle' && !alreadyEnrolled && (
          <div className="space-y-4">
            <p className="text-sm text-slate-700 dark:text-slate-200 font-medium">
              Set up your authenticator app (one-time)
            </p>
            <p className="text-sm text-slate-600 dark:text-slate-400">
              You will need an authenticator app on your phone or computer.
              Any RFC 6238 TOTP app works — for example:
            </p>
            <ul className="text-sm text-slate-600 dark:text-slate-400 list-disc list-inside space-y-0.5">
              <li>Google Authenticator (Android / iOS)</li>
              <li>Microsoft Authenticator (Android / iOS)</li>
              <li>1Password, Bitwarden, or any password manager with TOTP</li>
            </ul>
            <ol className="text-sm text-slate-600 dark:text-slate-400 list-decimal list-inside space-y-1">
              <li>Click <strong>Set up authenticator</strong> below — a QR code will appear.</li>
              <li>In your app, choose <em>Add account</em> and scan the QR (or paste the setup URI manually).</li>
              <li>Type the 6-digit code the app shows you.</li>
              <li>The plaintext Aadhaar will appear, then auto-clear after {AUTO_CLEAR_MS / 1000}s.</li>
            </ol>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              You only do this once. Every future Aadhaar reveal will just ask for the 6-digit code.
            </p>
            <button
              type="button"
              onClick={onEnroll}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded font-medium"
            >
              Set up authenticator
            </button>
          </div>
        )}

        {(phase === 'enrolling') && (
          <div className="text-sm text-slate-500 dark:text-slate-400">Enrolling MFA factor…</div>
        )}

        {/* ── Show QR + TOTP entry (first-time path) ────────────────── */}
        {phase === 'awaiting_totp' && !alreadyEnrolled && otpauthUri && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-1 text-slate-700 dark:text-slate-200">
                Scan this QR in your authenticator app
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                This QR appears once. After this enrollment, you'll only need to type the 6-digit code.
              </p>
              {qrDataUrl ? (
                <img src={qrDataUrl} alt="TOTP enrollment QR" className="mx-auto border border-slate-200 dark:border-slate-700 rounded p-1" width="180" height="180" />
              ) : (
                <div className="text-xs text-slate-500">Rendering QR…</div>
              )}
              <details className="mt-2">
                <summary className="text-xs text-slate-500 dark:text-slate-400 cursor-pointer hover:text-slate-700 dark:hover:text-slate-200">
                  Can't scan? Show manual setup URI
                </summary>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  Copy this text and paste it into your app's <em>Enter setup key manually</em> field
                  (under <em>Add account</em>).
                </p>
                <code className="block text-xs break-all bg-slate-100 dark:bg-slate-800 p-2 mt-1 rounded select-all">{otpauthUri}</code>
              </details>
            </div>
            <div>
              <label htmlFor="totp" className="block text-sm font-medium mb-1 text-slate-700 dark:text-slate-200">
                6-digit code from your app
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
                Challenge expires at {new Date(expiresAt).toLocaleTimeString()}.
                If it expires, click <strong>Restart Step-Up</strong> at the bottom of this dialog.
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

        {/* ── Returning admin: TOTP entry only (no QR) ──────────────── */}
        {phase === 'awaiting_totp' && alreadyEnrolled && (
          <div className="space-y-4">
            <p className="text-sm text-slate-700 dark:text-slate-200 font-medium">
              Enter the current 6-digit code from your authenticator app
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Open the same authenticator app you used to enroll (Google Authenticator,
              Microsoft Authenticator, 1Password, etc.) and copy the 6-digit code it shows
              for this FLN account. The code refreshes every 30 seconds.
            </p>
            <div>
              <label htmlFor="totp" className="block text-sm font-medium mb-1 text-slate-700 dark:text-slate-200">
                6-digit code
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
                Challenge expires at {new Date(expiresAt).toLocaleTimeString()}.
                If it expires, click <strong>Restart Step-Up</strong> at the bottom of this dialog.
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
            {phase === 'approving' ? 'Verifying TOTP code…' : 'Recovering plaintext…'}
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
            {/* Two recovery paths:
                - "Retry check" bumps preflightNonce, which re-runs the
                  preflight useEffect from scratch. Use this when the
                  failure was a transient read-side issue (timeout,
                  momentary network blip, dead Mongo connection that has
                  since recovered).
                - "Set up new authenticator" drops into the first-time
                  enroll path. Use this when the preflight is
                  persistently broken but the admin needs to reveal
                  urgently — they'll pay the cost of an extra QR scan
                  once. We still call the real /mfa/enroll endpoint, so
                  the backend is the source of truth on whether the
                  actor already has a factor (it returns
                  `alreadyEnrolled: true` and skips the QR). */}
            <button
              type="button"
              onClick={() => { setErrorMsg(''); setPreflightNonce(n => n + 1); }}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded font-medium"
            >
              Retry check
            </button>
            <button
              type="button"
              onClick={() => { setErrorMsg(''); setAlreadyEnrolled(false); setOtpauthUri(''); setPhase('idle'); }}
              className="w-full py-2 bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-900 dark:text-slate-100 rounded font-medium"
            >
              Set up new authenticator
            </button>
          </div>
        )}
      </div>
    </div>
  );
};