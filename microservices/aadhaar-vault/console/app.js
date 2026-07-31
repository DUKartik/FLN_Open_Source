/* Aadhaar Vault Console — main page
 * (aadhaar-vault-console:main)
 *
 * Single page entry point. The console is a developer / demo tool
 * that exercises the Vault REST API.
 *
 * All cross-cutting concerns (storage, API, logging, status
 * indicator, micro-DOM helpers) live in small modules loaded
 * before this script:
 *
 *   config.js  — build-time constants (defaultSettings, role list, etc.)
 *   storage.js — localStorage wrapper, settings shape
 *   ui.js      — DOM helpers, status/connection UI, toasts, copy buttons,
 *                form draft persistence
 *   logger.js  — ring-buffer request log with per-row copy filters
 *   api.js     — fetch wrapper + mock fallback, JWT decoding, overrideBearer
 *
 * Loaded order: config → storage → ui → logger → api → app.
 *
 * This script binds every feature in the rendered DOM to the helpers
 * exported on `window.AV`. No feature in this file may reach into
 * another feature's private state — everything flows through `AV`.
 */
(function (root) {
  'use strict';

  var AV      = root.AV || {};
  var storage = AV.storage;
  var api     = AV.api;
  var ui      = AV.ui;
  var logger  = AV.logger;
  var config  = AV.config;

  // -------------------------------------------------- helpers
  // micro-aliases so the binding code below is short and readable.
  // All of these are pure forwarders to AV.ui; no behaviour added.
  var $           = ui.$;
  var on          = ui.on;
  var val         = ui.val;
  var setVal      = ui.setVal;
  var setText     = ui.setText;
  var toast       = ui.toast;
  var formData    = ui.formToObject;

  // -------------------------------------------------- console state
  // Values the demo wants to remember across workflows but that don't
  // belong to the long-lived `settings` blob.
  var session = {
    lastToken:      '',
    lastIdentityId: '',
    lastFactorId:   '',
    lastReason:     '',
    actorId:        '',
    auditFilters:   { limit: 25 }
  };

  /* ------------------------------------------------------------------
   * 1. SETTINGS (Persistent demo config)
   *
   * The polished Settings form lives in #form-settings. The original
   * (Phase 1) code used #baseUrl / #bearer / #actorId style IDs.
   * Bridge the two by reading values from the actual elements via their
   * id attribute then projecting into the canonical settings shape.
   * ------------------------------------------------------------------ */

  // Maps each settings-form input ID to the canonical storage key
  // returned by `storage.getSettings()` / accepted by `saveSettings()`.
  // Earlier versions of this array used projection keys such as
  // `baseUrl` / `actorId` that did not match the storage layer and
  // therefore silently dropped the user-typed values.
  var SETTINGS_FIELDS = [
    { id: 'set-base-url', key: 'apiBase'   },
    { id: 'set-bearer',   key: 'bearer'    },
    { id: 'set-actor',    key: 'actor'     },
    { id: 'set-role',     key: 'actorRole' },
    { id: 'set-mock',     key: 'useMock', kind: 'checkbox' }
  ];

  function readSettingsFromForm() {
    var s = storage.getSettings();
    SETTINGS_FIELDS.forEach(function (f) {
      var el = $('#' + f.id);
      if (!el) return;
      s[f.key] = val(el);
    });
    storage.saveSettings(s);
    return s;
  }

  function writeSettingsToForm() {
    var s = storage.getSettings();
    SETTINGS_FIELDS.forEach(function (f) {
      var el = $('#' + f.id);
      if (!el) return;
      setVal(el, s[f.key]);
    });
  }

  function bindSettingsForm() {
    var form = $('#form-settings');
    if (!form) return;
    on(form, 'submit', function (e) {
      e.preventDefault();
      var s = readSettingsFromForm();
      toast('Settings saved', 'ok');
      // Push the new bearer straight into the api layer if we have one.
      if (api && typeof api.overrideBearer === 'function' && s.bearer) {
        api.overrideBearer(s.bearer);
      }
    });
    var reset = $('#set-reset');
    if (reset) on(reset, 'click', function () {
      storage.saveSettings(Object.assign({}, config.defaultSettings));
      writeSettingsToForm();
      toast('Settings reset to defaults', 'ok');
    });
    writeSettingsToForm();
  }

  /* ------------------------------------------------------------------
   * 2. HEALTH PAGE
   *
   * Two buttons exist: probe liveness ("btn-probe") and the dashboard
   * refresh button ("btn-refresh-dashboard"). Both render into the raw
   * response viewers + the top-of-page status cards.
   * ------------------------------------------------------------------ */

  function paintHealth(cards, body) {
    cards.forEach(function (id, key) {
      var el = $('#' + id);
      if (!el) return;
      var val = (body && body[key]) || '—';
      setText(el, String(val));
    });
  }

  function bindHealth() {
    var probe = $('#btn-probe');
    if (probe) on(probe, 'click', function () {
      api.get('/health').then(function (r) {
        if (!r.ok) { toast('Health probe failed', 'err'); return; }
        var b = r.body || {};
        setText($('#hc-health'),  String(b.status   || '—'));
        setText($('#hc-version'), String(b.version  || '—'));
        setText($('#hc-km'),      String((b.dependencies && b.dependencies.keyManager) || '—'));
        setText($('#hc-db'),      String((b.dependencies && b.dependencies.database) || '—'));
        // Render into the response viewer
        paintResultInto($('#hc-health-body'), r);
        updateDashCards(b);
      });
    });

    var readyProbe = $('#btn-health-ready');
    if (readyProbe) on(readyProbe, 'click', function () {
      api.get('/health/ready').then(function (r) {
        paintResultInto($('#hc-ready-body'), r);
      });
    });

    var refreshDash = $('#btn-refresh-dashboard');
    if (refreshDash) on(refreshDash, 'click', function () {
      api.get('/health').then(function (r) {
        if (r.ok) updateDashCards(r.body);
      });
    });
  }

  function updateDashCards(b) {
    if (!b) return;
    setText($('#dash-health'), String(b.status || '—'));
    setText($('#dash-health-sub'), String('v' + (b.version || '?')));
    var deps = b.dependencies || {};
    setText($('#dash-db'),  String(deps.database  || '—'));
    setText($('#dash-db-sub'), 'readiness probe');
    setText($('#dash-km'),  String(deps.keyManager || '—'));
    setText($('#dash-km-sub'), 'crypto provider');
  }

  function paintResultInto(el, r) {
    if (!el) return;
    el.innerHTML = '';
    el.appendChild(ui.responseHeader(r));
    var code = document.createElement('code');
    code.textContent = JSON.stringify(r.body || {}, null, 2);
    el.appendChild(code);
  }

  /* ------------------------------------------------------------------
   * 3. TOKENIZE FORM
   *
   * Inputs are: #tz-raw, #tz-type, #tz-actor-id, #tz-actor-role,
   * #tz-reason. Output viewers: #tz-token + #tz-body.
   * ------------------------------------------------------------------ */

  function bindTokenize() {
    var form = $('#form-tokenize');
    if (!form) return;

    var sampleBtn = $('#tz-fill-sample');
    if (sampleBtn) on(sampleBtn, 'click', function () {
      var defaults = storage.getSettings();
      setVal($('#tz-raw'),        '123412341234');
      setVal($('#tz-actor-id'),   defaults.actor     || 'volunteer-789');
      setVal($('#tz-actor-role'), defaults.actorRole || 'TEACHER');
      setVal($('#tz-reason'),     'student-enrollment');
      toast('Filled sample values', 'ok');
    });

    on(form, 'submit', function (e) {
      e.preventDefault();
      var data = formData(form);
      var rawDigits = String(data.raw || '').replace(/\D/g, '');
      if (rawDigits.length < 12) { toast('Aadhaar must be 12 digits', 'err'); return; }
      var payload = {
        rawAadhaar: rawDigits,
        identityType: data.type || 'AADHAAR',
        actorId:   data['tz-actor-id'] || '',
        actorRole: data['tz-actor-role'] || '',
        reason:    data.reason || ''
      };
      var started = Date.now();
      api.post('/v1/tokenize', payload).then(function (r) {
        setText($('#tz-duration'), r.duration != null ? (r.duration + ' ms') : '');
        paintResultInto($('#tz-body'), r);
        if (r.ok && r.body) {
          session.lastToken = r.body.token || '';
          session.lastIdentityId = r.body.identityId || '';
          setText($('#tz-token'), session.lastToken || '—');
          toast('Tokenized', 'ok');
          // Phase 2: Auto-prefill into the detokenize form
          var dtToken = $('#dt-token');
          if (dtToken && !dtToken.value) setVal(dtToken, session.lastToken);
          // Phase 2: Prefill actor defaults from settings
          var dtRole = $('#dt-role'); if (dtRole && !dtRole.value) {
            var s = storage.getSettings();
            if (s.actorRole) setVal(dtRole, s.actorRole);
          }
        } else {
          toast(r.error || 'Tokenize failed', 'err');
        }
      });
    });
  }

  /* ------------------------------------------------------------------
   * 4. DETOKENIZE FORM
   *
   * Inputs: #dt-token, #dt-role, #dt-reason. Output: #dt-masked,
   * #dt-last4, #dt-body. Step-up button: #btn-request-stepup.
   * ------------------------------------------------------------------ */

  function bindDetokenize() {
    var form = $('#form-detokenize');
    if (!form) return;
    on(form, 'submit', function (e) {
      e.preventDefault();
      var data = formData(form);
      if (!data.token) { toast('Token required', 'err'); return; }
      session.lastReason = data.reason || '';
      var payload = {
        token:  data.token,
        reason: data.reason || 'operator-review'
      };
      // (Phase 8 P2 cleanup: session.lastMfaToken was dead — never assigned.)
      api.post('/v1/detokenize', payload).then(function (r) {
        setText($('#dt-duration'), r.duration != null ? (r.duration + ' ms') : '');
        paintResultInto($('#dt-body'), r);
        if (r.ok && r.body) {
          setText($('#dt-masked'), r.body.masked || '—');
          setText($('#dt-last4'),   r.body.last4   || '—');
          toast('Detokenized', 'ok');
        } else {
          toast(r.error || 'Detokenize failed', 'err');
        }
      });
    });
    // Phase 2 cleanup: Step-Up workflow lives entirely in stepup.html.
    // No #btn-request-stepup / #btn-approve-stepup / #stepup-* IDs exist
    // on index.html, so the dedicated handlers were dead code and are
    // removed. session.lastMfaToken is set by stepup.js when an approval
    // is performed in the dedicated page (see stepup.js).
  }

  /* ------------------------------------------------------------------
   * 5. MFA ENROLL
   *
   * Inputs: #me-actor, #me-role, #me-reason. Outputs: #me-uri, #me-factor-id,
   * #me-algo, #me-digits, #me-period, #me-created, #me-body.
   * ------------------------------------------------------------------ */

  function bindMfaEnroll() {
    var form = $('#form-mfa-enroll');
    if (!form) return;
    on(form, 'submit', function (e) {
      e.preventDefault();
      var data = formData(form);
      var payload = {
        actor:   data['me-actor'] || '',
        role:    data['me-role']  || '',
        reason:  data.reason      || 'admin-mfa-setup'
      };
      api.post('/v1/mfa/enroll', payload).then(function (r) {
        setText($('#me-duration'), r.duration != null ? (r.duration + ' ms') : '');
        paintResultInto($('#me-body'), r);
        if (r.ok && r.body) {
          session.lastFactorId = r.body.factorId || '';
          setText($('#me-uri'),       r.body.uri || '—');
          setText($('#me-factor-id'), r.body.factorId || '—');
          setText($('#me-algo'),      (r.body.algorithm || 'SHA-1'));
          setText($('#me-digits'),    String(r.body.digits  || 6));
          setText($('#me-period'),    String((r.body.period || 30) + 's'));
          setText($('#me-created'),   r.body.createdAt || '—');
          // Phase 2: Prefill mfa-verify form
          if (r.body.factorId) setVal($('#mv-factor'), r.body.factorId);
          toast('Factor enrolled', 'ok');
        } else {
          toast(r.error || 'MFA enroll failed', 'err');
        }
      });
    });
  }

  /* ------------------------------------------------------------------
   * 6. MFA VERIFY
   *
   * Inputs: #mv-factor, #mv-code, #mv-reason, #mv-role.
   * Outputs: #mv-success, #mv-failure, #mv-delta, #mv-body.
   * ------------------------------------------------------------------ */

  function bindMfaVerify() {
    var form = $('#form-mfa-verify');
    if (!form) return;
    on(form, 'submit', function (e) {
      e.preventDefault();
      var data = formData(form);
      if (!data.factor || !data.code) { toast('factor + code required', 'err'); return; }
      var payload = {
        factorId: data.factor,
        code:     data.code,
        reason:   data.reason || 'detokenize-step-up',
        role:     data['mv-role'] || ''
      };
      api.post('/v1/mfa/verify', payload).then(function (r) {
        setText($('#mv-duration'), r.duration != null ? (r.duration + ' ms') : '');
        paintResultInto($('#mv-body'), r);
        if (r.ok && r.body) {
          setText($('#mv-success'), r.body.verified ? 'YES' : 'NO');
          setText($('#mv-failure'), r.body.reason || '—');
          setText($('#mv-delta'),   r.body.delta != null ? String(r.body.delta) : '0');
          toast(r.body.verified ? 'Verified' : 'Verification failed', r.body.verified ? 'ok' : 'err');
        } else {
          toast(r.error || 'MFA verify failed', 'err');
        }
      });
    });
  }

  /* ------------------------------------------------------------------
   * 7. AUDIT HISTORY
   *
   * The HTML uses a single form (#form-audit). App.js binds by reading
   * every field present, applying defaults, and GETing /v1/audit.
   * ------------------------------------------------------------------ */

  function bindAudit() {
    var form = $('#form-audit');
    if (!form) return;
    on(form, 'submit', function (e) {
      e.preventDefault();
      var data = formData(form);
      var params = new URLSearchParams();
      if (data.limit)     params.set('limit',    String(data.limit));
      if (data.identity)  params.set('identity', String(data.identity));
      if (data.reason)    params.set('reason',   String(data.reason));
      if (data['au-role'])params.set('role',     String(data['au-role']));

      api.get('/v1/audit?' + params.toString()).then(function (r) {
        var tbody = $('#audit-tbody');
        var count = $('#audit-count');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (!r.ok || !r.body) {
          setText(count, '0 rows');
          if (r.error) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = 8;
            td.className = 'muted center';
            td.textContent = r.error;
            tr.appendChild(td);
            tbody.appendChild(tr);
          }
          return;
        }
        var rows = Array.isArray(r.body.events) ? r.body.events
                  : Array.isArray(r.body)        ? r.body
                  : [];
        setText(count, rows.length + ' rows');
        if (rows.length === 0) {
          var tr2 = document.createElement('tr');
          var td2 = document.createElement('td');
          td2.colSpan = 8;
          td2.className = 'muted center';
          td2.textContent = 'No audit events match your query.';
          tr2.appendChild(td2);
          tbody.appendChild(tr2);
          return;
        }
        rows.forEach(function (row, i) {
          var tr = document.createElement('tr');
          ['eventAt','event','actor','role','reason','tokenHash','chainHash'].forEach(function (k, idx) {
            var td = document.createElement('td');
            td.textContent = (idx === 0 ? '#' + (i + 1) : (row[k] || row[k === 'eventAt' ? 'at' : k] || '—'));
            if (k === 'tokenHash' || k === 'chainHash' || k === 'eventAt') td.className = 'mono';
            tr.appendChild(td);
          });
          tbody.appendChild(tr);
        });
      });
    });

    var search = $('#au-search');
    if (search) on(search, 'input', function () {
      var q = String(search.value || '').toLowerCase();
      var tbody = $('#audit-tbody');
      if (!tbody) return;
      var rows = tbody.querySelectorAll('tr');
      rows.forEach(function (tr) {
        var txt = (tr.textContent || '').toLowerCase();
        tr.style.display = (!q || txt.indexOf(q) !== -1) ? '' : 'none';
      });
    });

    var clr = $('#audit-search-clear');
    if (clr) on(clr, 'click', function () {
      setVal($('#au-search'), '');
      setVal($('#au-identity'), '');
      setVal($('#au-reason'),   '');
      setVal($('#au-limit'),   '50');
      setVal($('#au-role'),    '');
    });

    var toggle = $('#audit-toggle-json');
    if (toggle) on(toggle, 'click', function () {
      var tbody = $('#audit-tbody');
      if (!tbody) return;
      tbody.classList.toggle('json');
    });
  }

  /* ------------------------------------------------------------------
   * 8. SIDEBAR NAVIGATION
   * ------------------------------------------------------------------ */

  function bindNav() {
    var items = document.querySelectorAll('.nav-item');
    if (!items.length) return;
    items.forEach(function (item) {
      on(item, 'click', function (e) {
        e.preventDefault();
        var target = item.getAttribute('data-section');
        items.forEach(function (it) { it.classList.remove('active'); });
        item.classList.add('active');
        document.querySelectorAll('.page').forEach(function (p) {
          p.classList.toggle('active', p.id === 'page-' + target);
        });
      });
    });
  }

  /* ------------------------------------------------------------------
   * 9. LOG / EXPORT
   * ------------------------------------------------------------------ */

  function bindLog() {
    var clr = $('#log-clear');
    if (clr && logger && typeof logger.clear === 'function') {
      on(clr, 'click', function () {
        logger.clear();
        if (logger.render) logger.render($('#log-tbody'));
      });
    }
    var exp = $('#log-export');
    if (exp) on(exp, 'click', function () {
      var data = logger && typeof logger.all === 'function' ? logger.all() : [];
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      a.href = url;
      a.download = 'aadhaar-vault-log.json';
      a.click();
      URL.revokeObjectURL(url);
    });

    if (logger && typeof logger.render === 'function') {
      logger.render($('#log-tbody'));
    }
  }

  /* ------------------------------------------------------------------
   * 10. ARCHITECTURE TRACER
   *
   * Picks an endpoint from #arch-endpoint, then animates the trace by
   * lighting up #arch-live layers one at a time.
   * ------------------------------------------------------------------ */

  function bindArch() {
    var traceBtn = $('#arch-trace');
    var select   = $('#arch-endpoint');
    var log      = $('#arch-trace-log');
    if (!traceBtn || !select || !log) return;

    on(traceBtn, 'click', function () {
      var choice = select.value;
      if (!choice) { toast('Pick an endpoint to trace', 'err'); return; }
      var layers = ['frontend','route','command','repo','db','audit','event','response'];
      layers.forEach(function (l) {
        var node = document.querySelector('[data-trace="' + l + '"]');
        if (node) node.classList.remove('live');
      });
      log.innerHTML = '';
      var i = 0;
      function tick() {
        if (i >= layers.length) return;
        var node = document.querySelector('[data-trace="' + layers[i] + '"]');
        if (node) {
          node.classList.add('live');
          var line = document.createElement('div');
          line.className = 'trace-line';
          line.textContent = (new Date()).toISOString().slice(11,19) + ' · ' + layers[i];
          log.appendChild(line);
        }
        i++;
        setTimeout(tick, 220);
      }
      tick();
      // Issue the actual API call (best-effort: tokenize → returns id, etc.)
      runArchEndpoint(choice);
    });
  }

  function runArchEndpoint(kind) {
    if (kind === 'health')         return api.get('/health');
    if (kind === 'tokenize')       return api.post('/v1/tokenize', { rawAadhaar: '123412341234', identityType: 'AADHAAR', reason: 'student-enrollment' });
    if (kind === 'detokenize')     return api.post('/v1/detokenize', { token: 'vlt_v1_placeholder', reason: 'scholarship-kyc' });
    if (kind === 'mfa-enroll')     return api.post('/v1/mfa/enroll', { actor: 'arch-demo', role: 'SUPER_ADMIN', reason: 'admin-mfa-setup' });
    if (kind === 'mfa-verify')     return api.post('/v1/mfa/verify', { factorId: '00000000-0000-0000-0000-000000000000', code: '000000', reason: 'detokenize-step-up' });
    if (kind === 'audit')          return api.get('/v1/audit?limit=25');
  }

  /* ------------------------------------------------------------------
   * 11. CONNECTION PILL
   * ------------------------------------------------------------------ */

  function startConnectionPolling() {
    var pill = $('#connection-pill');
    if (!pill || !api || typeof api.get !== 'function') return;
    setText(pill, 'Checking…');
    function ping() {
      api.get('/health').then(function (r) {
        pill.setAttribute('data-state', r.ok ? 'ok' : 'err');
        var txt = pill.querySelector('.conn-text');
        if (txt) txt.textContent = r.ok ? 'Online' : 'Offline';
      }).catch(function () {
        pill.setAttribute('data-state', 'err');
        var txt = pill.querySelector('.conn-text');
        if (txt) txt.textContent = 'Offline';
      });
    }
    ping();
    setInterval(ping, 15000);
  }

  /* ------------------------------------------------------------------
   * 12. RESET EVERYTHING
   * ------------------------------------------------------------------ */

  function bindResetAll() {
    var btn = $('#btn-reset-all');
    if (!btn) return;
    on(btn, 'click', function () {
      if (ui && typeof ui.confirm === 'function') {
        if (!ui.confirm('Wipe all local console state?')) return;
      }
      if (storage && typeof storage.clearAll === 'function') storage.clearAll();
      if (logger  && typeof logger.clearAll === 'function')  logger.clearAll();
      try { location.reload(); } catch (_) { /* offline preview */ }
    });
  }

  /* ------------------------------------------------------------------
   * 13. COPY BUTTONS (icon-btn[data-copy-target])
   *
   * Bind *only* at boot so the helper has the freshest list of targets.
   * ------------------------------------------------------------------ */

  function bindCopyButtons() {
    if (!ui || typeof ui.attachCopyButtons !== 'function') return;
    ui.attachCopyButtons();
    // Also wire [data-copy-text] in case the helper only scans one of the
    // two selectors.
    document.querySelectorAll('[data-copy-text]').forEach(function (btn) {
      if (btn.__wiredCopy) return;
      btn.__wiredCopy = true;
      on(btn, 'click', function () {
        var t = btn.getAttribute('data-copy-text');
        if (t) {
          navigator.clipboard && navigator.clipboard.writeText(t).then(function () { toast('Copied', 'ok'); });
        }
      });
    });
  }

  /* ------------------------------------------------------------------
   * 14. JWT PANEL HELPER
   *
   * When the user pastes a bearer token into settings, decode and show
   * the claims inside the Service Information card.
   * ------------------------------------------------------------------ */

  function bindJwtInspection() {
    var bearer = $('#set-bearer');
    if (!bearer || !api || typeof api.parseJwt !== 'function') return;
    on(bearer, 'change', function () {
      var claims = api.parseJwt(bearer.value);
      var box = $('#si-jwt');
      if (box && claims) {
        setText(box, 'HS256 (' + (claims.alg || 'jose') + ') · ' + (claims.sub || 'no-sub'));
      }
    });
  }

  /* ------------------------------------------------------------------
   * 15. BOOT
   * ------------------------------------------------------------------ */

  function boot() {
    // Settings is the foundation everyone else depends on.
    bindSettingsForm();

    bindNav();
    bindHealth();
    bindTokenize();
    bindDetokenize();
    bindMfaEnroll();
    bindMfaVerify();
    bindAudit();
    bindLog();
    bindArch();
    bindResetAll();
    bindJwtInspection();
    bindCopyButtons();

    // Phase 4 — Persist form drafts (Phase 4: persistent drafts)
    if (ui && typeof ui.bindFormDrafts === 'function') {
      ui.bindFormDrafts([
        '#form-tokenize', '#form-detokenize',
        '#form-mfa-enroll', '#form-mfa-verify', '#form-audit'
      ]);
    }

    // The connection pill should auto-refresh.
    startConnectionPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof window !== 'undefined' ? window : globalThis);