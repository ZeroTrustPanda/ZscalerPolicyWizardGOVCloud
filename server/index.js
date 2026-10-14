/**
 * Zscaler Policy Wizard GovCloud Edition (legacy ZIA API, ZIA only) - Express Server
 * Coded by Steven Hajny, Distinguished Engineer
 *
 * Built from v1.8.2 with Mobile Admin (ZCC), Digital Experience (ZDX) and OneAPI removed.
 * Serves the web UI and provides REST API endpoints for:
 * - Authentication (legacy ZIA API: /api/v1/authenticatedSession)
 * - Template generation and customization
 * - Dry run / plan / apply / rollback
 * - Audit logging and export
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const { randomUUID: uuidv4 } = require('crypto'); // built-in (no uuid package)
const { LOG_DIR } = require('./paths');
const { ZIAClient, ZIA_CLOUDS } = require('./zia-client');
const { generateFullTemplate, COMPLIANCE_FRAMEWORKS, getActionCatalog } = require('./templates');
const { dowCatalog, resolveDowCategories, CATEGORY_NAME } = require('./dow-standard');
const { resolveForTenant } = require('./tenant-resolve');
const { AuditLogger } = require('./audit-logger');

const app = express();
const APP_VERSION = '1.0.0';  // GovCloud Edition: ZIA only, legacy API, DOW Standard
const PORT = process.env.ZPW_PORT || 3000;
const HOST = process.env.ZPW_HOST || '0.0.0.0';
const SESSION_TTL_MS = 60 * 60 * 1000;   // 1 hour
const MAX_SESSIONS = 50;                  // Max concurrent sessions

// In-memory session store (per-session, never persisted)
const sessions = new Map();

// Session cleanup: remove expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      try { session.client.logout(); } catch(e) { /* ignore */ }
      sessions.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) console.log(`[SESSION] Cleaned ${cleaned} expired sessions. Active: ${sessions.size}`);
}, 5 * 60 * 1000);

// No CORS middleware: the UI is served by this same server (same origin).
app.use(express.json({ limit: '10mb' }));

// ========================
// Request Logging Middleware
// ========================
// This logs EVERY incoming request to the Node.js console (stdout)
// and to a dedicated HTTP log file in ./logs/
const HTTP_LOG_DIR = LOG_DIR;
if (!fs.existsSync(HTTP_LOG_DIR)) fs.mkdirSync(HTTP_LOG_DIR, { recursive: true });

app.use((req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();

  // Log when response finishes
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLine = `[${timestamp}] ${req.method} ${req.originalUrl} → ${res.statusCode} (${duration}ms) from=${req.ip}`;
    
    // Console output (visible in terminal / service logs)
    console.log(logLine);

    // File output
    const dateStr = timestamp.split('T')[0];
    const logFile = path.join(HTTP_LOG_DIR, `zpw-http-${dateStr}.log`);
    try {
      fs.appendFileSync(logFile, logLine + '\n');
    } catch (e) { /* ignore write errors */ }
  });

  next();
});

// JSON parse error handler — catches malformed request bodies
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    console.error(`[JSON_PARSE_ERROR] ${req.method} ${req.originalUrl}: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});

// Standalone builds embed the compiled UI (global.__ZPW_EMBEDDED_HTML__); the server
// build serves public/ from disk as before.
const EMBEDDED_HTML = global.__ZPW_EMBEDDED_HTML__ || null;
const sendIndex = (res) => EMBEDDED_HTML
  ? res.type('html').set('Cache-Control', 'no-store').send(EMBEDDED_HTML)
  : res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
if (EMBEDDED_HTML) {
  app.get(['/', '/index.html'], (req, res) => sendIndex(res));
} else {
  app.use(express.static(path.join(__dirname, '..', 'public')));
}

// ========================
// Version endpoint (no auth required)
// ========================
app.get('/api/version', (req, res) => {
  res.json({
    version: APP_VERSION,
    name: 'Zscaler Policy Wizard GovCloud Edition',
    build: '2026-03-30',
    activeSessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    sessionTTL: SESSION_TTL_MS / 1000 + 's'
  });
});

// ========================
// Middleware
// ========================

function getSession(req) {
  const sessionId = req.headers['x-session-id'];
  if (!sessionId || !sessions.has(sessionId)) return null;
  return sessions.get(sessionId);
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session || !session.client || !session.client.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated. Please connect to ZIA first.' });
  }
  // Touch session — extend TTL on activity
  session.lastActivity = Date.now();
  req.session = session;
  next();
}

// ========================
// Authentication Routes
// ========================

// Legacy ZIA API only: POST /api/v1/authenticatedSession with an obfuscated API key.
// Credentials come from the login form, or from a credentials file next to the app (never sent to the browser).
function createSession(client, logger) {
  if (sessions.size >= MAX_SESSIONS) {
    let oldestId = null, oldestTime = Infinity;
    for (const [id, s] of sessions) { if (s.createdAt < oldestTime) { oldestTime = s.createdAt; oldestId = id; } }
    if (oldestId) { try { sessions.get(oldestId).client.logout(); } catch (e) {} sessions.delete(oldestId); }
  }
  const sessionId = uuidv4();
  sessions.set(sessionId, { client, logger, snapshots: {}, appliedChanges: [], template: null, createdAt: Date.now(), lastActivity: Date.now() });
  return sessionId;
}

async function legacyLogin(creds) {
  const { baseUrl, username, password, apiKey } = creds;
  if (!baseUrl || !username || !password || !apiKey) throw Object.assign(new Error('Base URL, admin username, password and API key are all required for the legacy ZIA API.'), { status: 400 });
  if (!/^[A-Za-z0-9]{12,}$/.test(String(apiKey).trim())) throw Object.assign(new Error('The API key should be the 12-character key from Administration > API Key Management.'), { status: 400 });
  const client = new ZIAClient();
  const logger = new AuditLogger();
  console.log(`[AUTH] Legacy auth attempt: ${baseUrl} as ${username}`);
  const result = await client.authenticateLegacy({ username: username.trim(), password, apiKey: String(apiKey).trim(), cloud: baseUrl.trim() });
  const sessionId = createSession(client, logger);
  logger.logAuthentication('legacy', client.baseUrl, true);
  console.log(`[AUTH] Legacy auth SUCCESS: ${client.baseUrl}`);
  return { success: true, sessionId, host: client.baseUrl, authType: result.authType, message: `Signed in to ${client.baseUrl} with the legacy ZIA API` };
}

app.post('/api/auth/legacy', async (req, res) => {
  try { res.json(await legacyLogin(req.body || {})); }
  catch (error) { console.error(`[AUTH] Legacy auth FAILED: ${error.message}`); res.status(error.status || 401).json({ error: error.message }); }
});

// Credentials file next to the app (e.g. APISpecial.txt) — read on the server, never returned to the browser
const { findCredentialFile, readCredentialFile } = require('./cred-file');
app.get('/api/auth/cred-file', (req, res) => {
  const f = findCredentialFile();
  if (!f) return res.json({ found: false });
  try { const c = readCredentialFile(f); res.json({ found: true, file: f, baseUrl: c.baseUrl || null, username: c.username || null, hasPassword: !!c.password, hasApiKey: !!c.apiKey, complete: !!(c.baseUrl && c.username && c.password && c.apiKey) }); }
  catch (e) { res.json({ found: true, file: f, error: e.message }); }
});
app.post('/api/auth/cred-file', async (req, res) => {
  try {
    const f = findCredentialFile();
    if (!f) return res.status(404).json({ error: 'No credentials file found next to the app.' });
    res.json(await legacyLogin(readCredentialFile(f)));
  } catch (error) { res.status(error.status || 401).json({ error: error.message }); }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await req.session.client.logout();
    const sessionId = req.headers['x-session-id'];
    sessions.delete(sessionId);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/status', (req, res) => {
  const session = getSession(req);
  if (session && session.client.isAuthenticated()) {
    res.json({
      authenticated: true,
      authMode: session.client.authMode,
      cloud: session.client.cloud
    });
  } else {
    res.json({ authenticated: false });
  }
});

// ========================
// Template Routes
// ========================

app.get('/api/templates/frameworks', (req, res) => {
  res.json(COMPLIANCE_FRAMEWORKS);
});

app.get('/api/templates/clouds', (req, res) => {
  res.json(ZIA_CLOUDS);
});

const TIERS = ['STRICT', 'BALANCED', 'PERMISSIVE'];
const POLICY_KEYS = ['urlFiltering', 'firewallFiltering', 'ipsControl', 'sslInspection', 'malwareProtection', 'advancedThreatProtection',
  'advancedSettings', 'sandbox', 'dnsSecurity', 'fileTypeControl', 'cloudAppControl', 'dlp'];

/** Validate a wizard config (built-in framework, or a framework file / tenant capture in baseTemplate). */
function validateConfig(config) {
  if (!config || typeof config !== 'object') return 'Missing configuration';
  if (config.baseTemplate) {
    const bt = config.baseTemplate;
    if (typeof bt !== 'object' || typeof bt.policies !== 'object') return 'The framework file has no policies';
    for (const k of Object.keys(bt.policies)) if (!POLICY_KEYS.includes(k)) return `Unknown policy type in framework: ${k}`;
  } else {
    if (config.complianceFramework !== 'DOW_STANDARD' && !TIERS.includes(config.tier)) return 'Invalid tier. Must be STRICT, BALANCED or PERMISSIVE';
    if (config.complianceFramework && !COMPLIANCE_FRAMEWORKS[config.complianceFramework]) return `Invalid framework: ${config.complianceFramework}`;
  }
  if (config.prefix && !/^[A-Za-z0-9_-]+$/.test(config.prefix)) return 'Prefix must contain only letters, numbers, hyphens, and underscores';
  if (config.actionSettings) {
    const ok = v => v === 'ALLOW' || v === 'BLOCK';
    for (const [k, v] of Object.entries(config.actionSettings.policy || {})) if (!(ok(v) || v === 'DEFAULT')) return `Invalid action for policy type ${k}: ${v}`;
    for (const [k, v] of Object.entries(config.actionSettings.rules || {})) if (!ok(v)) return `Invalid action for rule ${k}: ${v}`;
  }
  for (const f of ['disabledRules', 'disabledSettings']) {
    if (config[f] && (typeof config[f] !== 'object' || Object.values(config[f]).some(v => typeof v !== 'boolean'))) return `${f} must map keys to true/false`;
  }
  if (config.blockedCountries && (!Array.isArray(config.blockedCountries) || config.blockedCountries.some(c => !/^COUNTRY_[A-Z]{2}$/.test(c)))) return 'blockedCountries must be COUNTRY_XX codes';
  if (config.cbiProfile && (typeof config.cbiProfile !== 'object' || !config.cbiProfile.id || !config.cbiProfile.name)) return 'cbiProfile needs id and name';
  if (config.sslCertificate && (typeof config.sslCertificate !== 'object' || config.sslCertificate.id === undefined || !config.sslCertificate.name)) return 'sslCertificate needs id and name';
  return null;
}

app.post('/api/templates/generate', (req, res) => {
  try {
    const config = req.body;
    const err = validateConfig(config);
    if (err) return res.status(400).json({ error: err });
    const template = generateFullTemplate(config);
    const session = getSession(req);
    if (session) {
      session.template = template;
      session.logger.logTemplateGeneration({ ...config, baseTemplate: config.baseTemplate ? '(framework file)' : undefined }, template);
    }
    res.json(template);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rules step: every rule and ATP setting with defaults (no auth)
app.post('/api/templates/action-catalog', (req, res) => {
  try {
    const config = req.body || {};
    const err = validateConfig(config);
    if (err) return res.status(400).json({ error: err });
    res.json(getActionCatalog(config));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Policy Catalog (no auth required — read-only reference)
// DOW Standard, plus NIST 800-53 and NIST 800-171 on each tier
// ========================

function summarizeTemplate(template) {
  const summary = {};
  for (const [policyType, rules] of Object.entries(template.policies)) {
    if (Array.isArray(rules)) {
      summary[policyType] = rules.map(r => ({
        name: r.name,
        action: (typeof r.action === 'string' ? r.action : r.action?.type) || r.baRuleAction || r.filteringAction || (r.actions ? r.actions.join(', ') : '—'),
        state: r.state || '—', description: r.description || '', complianceMapping: r.complianceMapping || [],
        ...(r.urlCategories ? { urlCategories: r.urlCategories } : {}),
        ...(r.protocols ? { protocols: r.protocols } : {}),
        ...(r.severity ? { severity: r.severity } : {}),
        ...(r.dictionaryNames ? { dictionaryNames: r.dictionaryNames } : {}),
        ...(r.preferredEngineNames?.length ? { preferredEngines: r.preferredEngineNames } : {}),
        ...(r.fileTypes ? { fileTypes: r.fileTypes } : {}),
        ...(r.baPolicyCategories ? { baPolicyCategories: r.baPolicyCategories } : {}),
        ...(r.nwApplications ? { nwApplications: r.nwApplications } : {}),
        ...(r.firstTimeOperation ? { firstTimeOperation: r.firstTimeOperation } : {}),
        ...(r.threatCategoryLabel ? { threatCategory: r.threatCategoryLabel } : {}),
        ...(r.isolateAllOthers ? { isolateAllOthers: true } : {}),
        ...(r.tier ? { tier: r.tier } : {})
      }));
    } else if (rules && typeof rules === 'object') {
      summary[policyType] = {
        name: rules.name, description: rules.description || '', settings: rules.settings || {},
        ...(rules.blockedCountries ? { blockedCountries: rules.blockedCountries } : {}),
        complianceMapping: rules.complianceMapping || []
      };
    }
  }
  return {
    metadata: template.metadata,
    ruleCounts: Object.fromEntries(Object.entries(template.policies).map(([k, v]) => [k, Array.isArray(v) ? v.length : 1])),
    policies: summary,
    checklist: template.implementationChecklist
  };
}

app.get('/api/catalog', (req, res) => {
  try {
    const views = [{ id: 'DOW_STANDARD', framework: 'DOW_STANDARD', tier: null, label: 'DOW Standard' }];
    for (const fw of ['NIST_800_53', 'NIST_800_171']) for (const tier of TIERS) views.push({ id: `${fw}:${tier}`, framework: fw, tier, label: `${COMPLIANCE_FRAMEWORKS[fw].name} · ${tier[0] + tier.slice(1).toLowerCase()}` });
    const catalog = { generatedAt: new Date().toISOString(), version: APP_VERSION, frameworks: COMPLIANCE_FRAMEWORKS, dow: dowCatalog(), views: [] };
    for (const v of views) {
      const template = generateFullTemplate({ tier: v.tier || 'STRICT', complianceFramework: v.framework, prefix: 'GOV' });
      catalog.views.push({ ...v, ...summarizeTemplate(template) });
    }
    res.json(catalog);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Frameworks: save / upload / capture from tenant
// ========================
const { buildFrameworkFile, readFrameworkFile, captureFromTenant } = require('./framework-io');

// Build the file for the current wizard choices (the browser downloads it)
app.post('/api/frameworks/build', (req, res) => {
  try {
    const { name, description, config } = req.body || {};
    const err = validateConfig(config);
    if (err) return res.status(400).json({ error: err });
    const { baseTemplate, ...rest } = config;
    res.json(buildFrameworkFile({ name, description, config: rest, baseTemplate: baseTemplate || null, appVersion: APP_VERSION }));
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Check an uploaded framework file and return the wizard config it describes
app.post('/api/frameworks/read', (req, res) => {
  try {
    const out = readFrameworkFile(req.body && req.body.framework);
    const err = validateConfig({ tier: 'STRICT', ...out.config });
    if (err) return res.status(400).json({ error: err });
    res.json(out);
  } catch (error) { res.status(400).json({ error: error.message }); }
});

// Read the connected tenant's policies into a framework (read-only)
app.post('/api/frameworks/capture', requireAuth, async (req, res) => {
  try {
    const { client, logger } = req.session;
    const name = (req.body && req.body.name) || `Captured from ${client.baseUrl}`;
    const cap = await captureFromTenant(client, { name, host: client.baseUrl });
    const file = buildFrameworkFile({ name, description: (req.body && req.body.description) || `Policies captured from ${client.baseUrl} on ${new Date().toISOString().substring(0, 10)}`,
      config: { prefix: '', enableUrlFiltering: true }, baseTemplate: cap.baseTemplate, appVersion: APP_VERSION });
    logger.log('FRAMEWORK_CAPTURE', { host: client.baseUrl, counts: Object.fromEntries(Object.entries(cap.baseTemplate.policies).map(([k, v]) => [k, Array.isArray(v) ? v.length : 1])), notes: cap.notes.length });
    res.json({ framework: file, notes: cap.notes, skipped: cap.skipped });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Isolation profiles in the connected tenant (for the Isolate rule)
app.get('/api/isolation-profiles', requireAuth, async (req, res) => {
  try {
    const r = await req.session.client.getCbiProfiles();
    res.json((Array.isArray(r) ? r : []).map(p => ({ id: p.id, name: p.name, url: p.url, defaultProfile: !!p.defaultProfile })));
  } catch (error) { res.status(502).json({ error: error.message }); }
});

// ========================
// SSL interception certificates + bulk certificate change
// ========================
// Zscaler's SDKs use the singular path; the plural ones are kept as fallbacks
const SSL_CERT_PATHS = ['/api/v1/intermediateCaCertificate/readyToUse', '/api/v1/intermediateCaCertificate',
  '/api/v1/intermediateCaCertificate/lite', '/api/v1/intermediateCaCertificates'];

/**
 * PUT ATP settings. Some tenants return the newer switches (e.g. rogueVulnerableMcpBlocked, agenticAiBlocked) on GET
 * but reject them on PUT ("Feature Flag for ... is not enabled!"). Drop those fields and try again.
 */
async function putAtpSettings(client, body, notes = []) {
  const flagMsg = (e) => /feature flag/i.test(String(e && e.message || ''));
  const flagged = (msg) => {
    const words = (String(msg).match(/feature flag for (.+?) is not enabled/i) || [])[1] || '';
    const toks = words.toLowerCase().split(/[^a-z]+/).filter(w => w.length > 2 && !['and', 'the', 'for', 'servers'].includes(w));
    const hit = (k) => toks.some(t => k.toLowerCase().includes(t)) || /mcp|agentic/i.test(k);
    return Object.keys(body).filter(k => k !== 'blockedCountries' && hit(k));
  };
  try { await client.updateAtpSettings(body); return { sent: body }; }
  catch (e) {
    if (!flagMsg(e)) throw e;
    const keys = flagged(e.message);
    // 1) leave the flagged fields out   2) send them as null
    const without = { ...body }; for (const k of keys) delete without[k];
    try { await client.updateAtpSettings(without); notes.push(`Advanced Threat Protection: left out ${keys.join(', ') || 'a feature-flagged setting'} (not enabled on this tenant).`); return { sent: without }; }
    catch (e2) {
      if (!flagMsg(e2)) throw e2;
      const nulled = { ...body }; for (const k of keys) nulled[k] = null;
      try { await client.updateAtpSettings(nulled); notes.push(`Advanced Threat Protection: sent ${keys.join(', ')} as empty (not enabled on this tenant).`); return { sent: without }; }
      catch (e3) {
        if (!flagMsg(e3)) throw e3;
        const err = new Error(`Skipped — this tenant refuses Advanced Threat Protection updates through the API while a Zscaler feature flag is off (${(String(e.message).match(/Feature Flag[^"]*/i) || [''])[0]}). Set these ATP options in the portal, or ask Zscaler support to enable the flag.`);
        err.featureFlag = true; throw err;
      }
    }
  }
}

/** Certificates that SSL rules can use: the intermediate CA list when the API offers it, plus any already used by rules. */
async function listSslCertificates(client) {
  const out = { certificates: [], source: null, tried: [] };
  const seen = new Map();
  for (const p of SSL_CERT_PATHS) {
    try {
      const v = await client.apiCall('GET', p);
      const arr = Array.isArray(v) ? v : (v && (v.list || v.items)) || [];
      out.tried.push({ path: p, ok: true, count: arr.length });
      for (const c of arr) if (c && c.id !== undefined) seen.set(String(c.id), { id: c.id, name: c.name || `Certificate ${c.id}`, type: c.type || null, status: c.status || null, defaultCertificate: !!c.defaultCertificate, from: 'certificate list' });
      out.source = p; break;
    } catch (e) { out.tried.push({ path: p, ok: false, error: String(e.message).substring(0, 120) }); }
  }
  try {
    const rules = await client.getSslInspectionRules();
    for (const r of (Array.isArray(rules) ? rules : [])) {
      const c = r.action && r.action.sslInterceptionCert;
      if (c && c.id !== undefined && !seen.has(String(c.id))) seen.set(String(c.id), { id: c.id, name: c.name || `Certificate ${c.id}`, defaultCertificate: !!c.defaultCertificate, from: `used by rule "${r.name}"` });
    }
  } catch (e) { /* best-effort */ }
  out.certificates = [...seen.values()];
  return out;
}

app.get('/api/ssl/certificates', requireAuth, async (req, res) => {
  try { res.json(await listSslCertificates(req.session.client)); } catch (e) { res.status(502).json({ error: e.message }); }
});

// Every SSL inspection rule with the certificate it uses
app.get('/api/ssl/rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getSslInspectionRules();
    res.json((Array.isArray(rules) ? rules : []).sort((a, b) => (a.order || 0) - (b.order || 0)).map(r => ({
      id: r.id, name: r.name, order: r.order, state: r.state, predefined: !!r.predefined, defaultRule: !!r.defaultRule,
      action: r.action && r.action.type, override: !!(r.action && r.action.overrideDefaultCertificate),
      certificate: r.action && r.action.overrideDefaultCertificate && r.action.sslInterceptionCert ? { id: r.action.sslInterceptionCert.id, name: r.action.sslInterceptionCert.name } : null,
      changeable: !!(r.action && r.action.type === 'DECRYPT')
    })));
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Bulk change: point the selected Inspect (DECRYPT) rules at a certificate, or back to the Zscaler default (certificate = null)
app.post('/api/ssl/bulk-certificate', requireAuth, async (req, res) => {
  const { client, logger } = req.session;
  const { ruleIds = [], certificate = null, dryRun = false } = req.body || {};
  if (!Array.isArray(ruleIds) || !ruleIds.length) return res.status(400).json({ error: 'Choose at least one rule.' });
  if (certificate && (certificate.id === undefined || !certificate.name)) return res.status(400).json({ error: 'Certificate needs an id and a name.' });
  try {
    const rules = await client.getSslInspectionRules();
    const results = [];
    for (const id of ruleIds) {
      const r = (Array.isArray(rules) ? rules : []).find(x => String(x.id) === String(id));
      if (!r) { results.push({ id, ok: false, error: 'Rule not found' }); continue; }
      if (!r.action || r.action.type !== 'DECRYPT') { results.push({ id, name: r.name, ok: false, error: 'Only Inspect (DECRYPT) rules use an interception certificate' }); continue; }
      const before = r.action.overrideDefaultCertificate && r.action.sslInterceptionCert ? r.action.sslInterceptionCert.name : 'Zscaler default';
      const after = certificate ? certificate.name : 'Zscaler default';
      if (before === after) { results.push({ id, name: r.name, ok: true, unchanged: true, before, after }); continue; }
      if (dryRun) { results.push({ id, name: r.name, ok: true, before, after, dryRun: true }); continue; }
      const body = JSON.parse(JSON.stringify(r));
      delete body.lastModifiedTime; delete body.lastModifiedBy;
      body.action.overrideDefaultCertificate = !!certificate;
      if (certificate) body.action.sslInterceptionCert = { id: certificate.id, name: certificate.name };
      else delete body.action.sslInterceptionCert;
      try {
        await client.updateSslInspectionRule(r.id, body);
        results.push({ id, name: r.name, ok: true, before, after });
        logger.logPolicyApply('SSL Inspection', r.name, 'UPDATE', { certificate: after, before });
      } catch (e) { results.push({ id, name: r.name, ok: false, before, after, error: e.message }); }
    }
    let activated = null;
    if (!dryRun && results.some(r => r.ok && !r.unchanged && !r.dryRun)) {
      try { await client.activateChanges(); activated = true; } catch (e) { activated = false; results.push({ ok: false, name: 'Activation', error: e.message }); }
    }
    res.json({ results, activated, dryRun: !!dryRun });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ========================
// Plan / Dry Run Routes
// ========================

app.post('/api/plan/dryrun', requireAuth, async (req, res) => {
  try {
    const { template: templateIn, cbiProfile } = req.body;
    if (!templateIn) {
      return res.status(400).json({ error: 'No template provided' });
    }

    const { client, logger } = req.session;
    const plan = { actions: [], warnings: [], errors: [] };
    // resolve DOW categories, isolation profile and IPS threat category against this tenant
    const resolved = await resolveForTenant(client, templateIn, { cbiProfile });
    const template = resolved.template;
    plan.warnings.push(...resolved.warnings);
    plan.errors.push(...resolved.errors);
    plan.resolved = resolved.info;
    plan.resolvedTemplate = template;

    // Fetch current state
    let currentUrlRules = [];
    let currentFwRules = [];
    let currentSslRules = [];

    try {
      currentUrlRules = await client.getUrlFilteringRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current URL filtering rules: ${e.message}`);
    }

    try {
      currentFwRules = await client.getFirewallRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current firewall rules: ${e.message}`);
    }

    try {
      currentSslRules = await client.getSslInspectionRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current SSL inspection rules: ${e.message}`);
    }

    // Plan URL Filtering Rules
    if (template.policies?.urlFiltering) {
      for (const rule of template.policies.urlFiltering) {
        const existing = currentUrlRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'URL Filtering',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state, categories: (rule.urlCategories || []).length,
            ...(rule.action === 'ISOLATE' ? { isolationProfile: rule.cbiProfile ? rule.cbiProfile.name : '(none — rule will be skipped)' } : {}) },
          categoryNames: (rule.urlCategories || []).map(c => CATEGORY_NAME[c] || c),
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Plan IPS Control rules
    if (template.policies?.ipsControl) {
      let currentIps = [];
      try { currentIps = await client.getIpsRules() || []; } catch (e) { /* reported by resolveForTenant */ }
      for (const rule of template.policies.ipsControl) {
        const existing = Array.isArray(currentIps) ? currentIps.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE', category: 'IPS Control', name: rule.name, description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state, threatCategory: rule.threatCategories?.[0]?.name || `${rule.threatCategoryLabel} (not found — rule will be skipped)` },
          isRisky: false
        });
      }
    }

    // Plan Advanced Threat Protection settings: field-by-field against the tenant
    if (template.policies?.advancedThreatProtection) {
      const atp = template.policies.advancedThreatProtection;
      let current = null;
      try { current = await client.getAtpSettings(); } catch (e) { plan.warnings.push(`Could not read Advanced Threat Protection settings: ${e.message}`); }
      const changes = [];
      for (const [k, v] of Object.entries(atp.settings || {})) {
        if (!current || current[k] !== v) changes.push({ field: k, from: current ? current[k] : '?', to: v });
      }
      let countriesAdded = [];
      if (atp.blockedCountries && atp.blockedCountries.length) {
        const have = new Set((current && current.blockedCountries) || []);
        countriesAdded = atp.blockedCountries.filter(c => !have.has(c));
      }
      plan.actions.push({
        type: 'UPDATE', category: 'Advanced Threat Protection', name: atp.name,
        description: atp.description || 'Advanced Threat Protection settings',
        current: current ? { blockedCountries: current.blockedCountries || [] } : null,
        proposed: { settingsChanged: changes.length, countriesAdded },
        atpChanges: changes, countriesAdded, alreadyBlockedCountries: (atp.blockedCountries || []).filter(c => !countriesAdded.includes(c)),
        isRisky: false
      });
      req.session.atpSnapshot = current;
    }

    // Plan Firewall Rules
    if (template.policies?.firewallFiltering) {
      for (const rule of template.policies.firewallFiltering) {
        const existing = currentFwRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'Firewall',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Plan SSL Rules
    if (template.policies?.sslInspection) {
      for (const rule of template.policies.sslInspection) {
        const existing = currentSslRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'SSL Inspection',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Malware & Advanced Settings
    if (template.policies?.malwareProtection) {
      plan.actions.push({
        type: 'UPDATE',
        category: 'Malware Protection',
        name: template.policies.malwareProtection.name,
        description: 'Malware Protection settings (review in the portal: not applied by the API in this edition; ATP settings are applied separately)',
        current: null,
        proposed: { settings: template.policies.malwareProtection.settings },
        complianceMapping: template.policies.malwareProtection.complianceMapping
      });
    }

    if (template.policies?.advancedSettings) {
      plan.actions.push({
        type: 'UPDATE',
        category: 'Advanced Settings',
        name: template.policies.advancedSettings.name,
        description: 'Update advanced cloud configuration settings',
        current: null,
        proposed: { settings: template.policies.advancedSettings.settings },
        complianceMapping: template.policies.advancedSettings.complianceMapping
      });
    }

    // Plan Sandbox Rules
    if (template.policies?.sandbox) {
      let currentSandboxRules = [];
      try { currentSandboxRules = await client.getSandboxRules() || []; } catch(e) { plan.warnings.push(`Could not fetch sandbox rules: ${e.message}`); }
      for (const rule of template.policies.sandbox) {
        const existing = Array.isArray(currentSandboxRules) ? currentSandboxRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'Sandbox',
          name: rule.name,
          description: rule.description,
          current: existing ? { baRuleAction: existing.baRuleAction, state: existing.state } : null,
          proposed: { baRuleAction: rule.baRuleAction, state: rule.state, firstTimeOperation: rule.firstTimeOperation },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan DNS Security Rules
    if (template.policies?.dnsSecurity) {
      let currentDnsRules = [];
      try { currentDnsRules = await client.getDnsControlRules() || []; } catch(e) { plan.warnings.push(`Could not fetch DNS rules: ${e.message}`); }
      for (const rule of template.policies.dnsSecurity) {
        const existing = Array.isArray(currentDnsRules) ? currentDnsRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'DNS Security',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan File Type Control Rules
    if (template.policies?.fileTypeControl) {
      let currentFtcRules = [];
      try { currentFtcRules = await client.getFileTypeRules() || []; } catch(e) { plan.warnings.push(`Could not fetch file type rules: ${e.message}`); }
      for (const rule of template.policies.fileTypeControl) {
        const existing = Array.isArray(currentFtcRules) ? currentFtcRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'File Type Control',
          name: rule.name,
          description: rule.description,
          current: existing ? { filteringAction: existing.filteringAction, state: existing.state } : null,
          proposed: { filteringAction: rule.filteringAction, state: rule.state, operation: rule.operation },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan Cloud App Control Rules
    if (template.policies?.cloudAppControl) {
      for (const rule of template.policies.cloudAppControl) {
        plan.actions.push({
          type: 'CREATE',
          category: 'Cloud App Control',
          name: rule.name,
          description: rule.description,
          current: null,
          proposed: { actions: rule.actions, state: rule.state, ruleType: rule.ruleType },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan DLP Rules
    if (template.policies?.dlp) {
      let currentDlpRules = [];
      try { currentDlpRules = await client.getWebDlpRules() || []; } catch(e) { plan.warnings.push(`Could not fetch current DLP rules: ${e.message}`); }
      if (!Array.isArray(currentDlpRules)) currentDlpRules = [];

      // Fetch engines and dictionaries to validate availability
      let availableEngines = [];
      let availableDicts = [];
      try {
        availableEngines = await client.getDlpEngines() || [];
        if (!Array.isArray(availableEngines)) availableEngines = [];
      } catch(e) {
        plan.warnings.push(`Could not fetch DLP engines: ${e.message}`);
      }
      try {
        availableDicts = await client.getDlpDictionaries() || [];
        if (!Array.isArray(availableDicts)) availableDicts = [];
      } catch(e) {
        plan.warnings.push(`Could not fetch DLP dictionaries: ${e.message}`);
      }

      for (const rule of template.policies.dlp) {
        const existing = currentDlpRules.find(r => r.name === rule.name);

        // Check engine availability
        let engineMatch = null;
        if (rule.preferredEngineNames && rule.preferredEngineNames.length > 0) {
          for (const eName of rule.preferredEngineNames) {
            engineMatch = availableEngines.find(e => e.name && e.name.toLowerCase() === eName.toLowerCase());
            if (engineMatch) break;
          }
        }

        // Check dictionary availability
        let dictStatus = '';
        if (rule.dictionaryNames && rule.dictionaryNames.length > 0) {
          const foundCount = rule.dictionaryNames.filter(dName =>
            availableDicts.some(d => d.name && d.name.toLowerCase() === dName.toLowerCase())
          ).length;
          dictStatus = `${foundCount}/${rule.dictionaryNames.length} dictionaries available`;
          if (foundCount < rule.dictionaryNames.length) {
            const missing = rule.dictionaryNames.filter(dName =>
              !availableDicts.some(d => d.name && d.name.toLowerCase() === dName.toLowerCase())
            );
            plan.warnings.push(`${rule.name}: Missing dictionaries: ${missing.join(', ')}`);
          }
        }

        const resolution = engineMatch
          ? `Engine: ${engineMatch.name} (ID: ${engineMatch.id})`
          : rule.withoutContentInspection
            ? 'Without content inspection'
            : `Dictionary-based (${dictStatus})`;

        plan.actions.push({
          type: existing ? 'EXISTS' : 'CREATE',
          category: 'Data Loss Prevention',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: {
            action: rule.action,
            state: rule.state,
            severity: rule.severity,
            resolution,
            dictionaries: rule.dictionaryNames || [],
            preferredEngines: rule.preferredEngineNames || []
          },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Allow/Block overrides (v1.6.0): mark plan entries that differ from the tier default
    const overrideByName = {};
    for (const key of ['urlFiltering', 'firewallFiltering', 'dnsSecurity', 'fileTypeControl', 'cloudAppControl', 'dlp']) {
      for (const r of template.policies?.[key] || []) overrideByName[r.name] = r;
    }
    for (const a of plan.actions) {
      const r = overrideByName[a.name];
      if (!r || r.defaultAction === undefined) continue;
      a.defaultAction = r.defaultAction;
      a.actionChanged = !!r.actionChanged;
      a.weakened = !!r.weakened;
      if (r.weakened) a.isRisky = true;
    }

    // Store snapshot for rollback
    const snapshotId = uuidv4();
    let currentDlpSnapshot = [];
    try { currentDlpSnapshot = await client.getWebDlpRules() || []; } catch(e) { /* ignore */ }
    req.session.snapshots[snapshotId] = {
      urlRules: currentUrlRules,
      fwRules: currentFwRules,
      sslRules: currentSslRules,
      dlpRules: Array.isArray(currentDlpSnapshot) ? currentDlpSnapshot : [],
      atp: req.session.atpSnapshot || null,
      timestamp: new Date().toISOString()
    };

    plan.snapshotId = snapshotId;
    plan.summary = {
      totalActions: plan.actions.length,
      creates: plan.actions.filter(a => a.type === 'CREATE').length,
      updates: plan.actions.filter(a => a.type === 'UPDATE').length,
      existing: plan.actions.filter(a => a.type === 'EXISTS').length,
      riskyActions: plan.actions.filter(a => a.isRisky).length,
      actionOverrides: plan.actions.filter(a => a.actionChanged).length,
      weakenedRules: plan.actions.filter(a => a.weakened).length,
      categories: [...new Set(plan.actions.map(a => a.category))]
    };

    logger.log('DRY_RUN', plan.summary);

    res.json(plan);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Apply Routes
// ========================

app.post('/api/apply', requireAuth, async (req, res) => {
  try {
    const { template: templateIn, snapshotId, cbiProfile } = req.body;
    if (!templateIn) {
      return res.status(400).json({ error: 'No template provided' });
    }

    const { client, logger } = req.session;
    const results = { applied: [], errors: [], warnings: [] };
    // resolve again right before writing (the tenant may have changed since the dry run)
    const resolved = await resolveForTenant(client, templateIn, { cbiProfile });
    const template = resolved.template;
    results.warnings.push(...resolved.warnings);
    results.resolved = resolved.info;
    if (template.actionChanges?.length) {
      logger.log('ACTION_OVERRIDES', { changes: template.actionChanges });
    }

    // Apply URL Filtering Rules
    if (template.policies?.urlFiltering) {
      // Track custom category IDs: configuredName -> API-assigned ID
      const customCategoryIds = {};

      // First create custom categories if needed
      for (const rule of template.policies.urlFiltering) {
        if (rule.requiresCustomCategory) {
          try {
            const catResult = await client.createUrlCategory({
              configuredName: rule.customCategoryName,
              superCategory: 'USER_DEFINED',
              urls: ['placeholder.example.com'],
              description: `Custom block category created by Zscaler Policy Wizard`
            });
            // The API returns the category with its assigned ID (e.g., "CUSTOM_01")
            if (catResult && catResult.id) {
              customCategoryIds[rule.customCategoryName] = catResult.id;
              console.log(`[APPLY] Custom category created: ${rule.customCategoryName} -> ID: ${catResult.id}`);
            }
            results.applied.push({ type: 'CREATE', category: 'URL Category', name: rule.customCategoryName });
            logger.logPolicyApply('URL Category', rule.customCategoryName, 'CREATE', { success: true, id: catResult?.id });
          } catch (e) {
            if (e.message.includes('DUPLICATE_ITEM') || e.message.includes('already exists') || e.message.includes('already taken')) {
              // Category exists — try to find its ID by fetching custom categories
              results.warnings.push(`Custom category already exists: ${rule.customCategoryName}. Attempting to look up its ID.`);
              try {
                const existingCats = await client.getUrlCategories(true);
                if (Array.isArray(existingCats)) {
                  const match = existingCats.find(c => c.configuredName === rule.customCategoryName);
                  if (match && match.id) {
                    customCategoryIds[rule.customCategoryName] = match.id;
                    console.log(`[APPLY] Found existing custom category: ${rule.customCategoryName} -> ID: ${match.id}`);
                  }
                }
              } catch (lookupErr) {
                results.warnings.push(`Could not look up existing category: ${lookupErr.message}`);
              }
            } else {
              results.errors.push({ category: 'URL Category', name: rule.customCategoryName, error: e.message });
            }
          }
        }
      }

      // Custom categories carried in a captured framework: create (or find) them, then point the rules at the new IDs
      for (const cc of (template.customCategories || [])) {
        try {
          let existing = null;
          try { existing = (await client.getUrlCategories(true) || []).find(c => c.configuredName === cc.configuredName); } catch (e) { /* create below */ }
          let newId = existing && existing.id;
          if (!newId) {
            const created = await client.createUrlCategory({ configuredName: cc.configuredName, superCategory: cc.superCategory || 'USER_DEFINED',
              urls: cc.urls || [], dbCategorizedUrls: cc.dbCategorizedUrls || [], keywords: cc.keywords || [],
              keywordsRetainingParentCategory: cc.keywordsRetainingParentCategory || [], customCategory: true, description: cc.description || '' });
            newId = created && created.id;
            results.applied.push({ type: 'CREATE', category: 'URL Category', name: cc.configuredName, id: newId });
          } else results.warnings.push(`Custom category "${cc.configuredName}" already exists here (${newId}); it was reused, not changed.`);
          if (newId) customCategoryIds[cc.id] = newId;
        } catch (e) {
          results.errors.push({ category: 'URL Category', name: cc.configuredName, error: e.message });
        }
      }

      // Create URL filtering rules — track successful order for next rule
      let urlOrderTracker = 1;
      try {
        const existingUrlRules = await client.getUrlFilteringRules();
        if (Array.isArray(existingUrlRules) && existingUrlRules.length > 0) {
          // Place new rules after existing ones (before the default rule)
          const nonDefaultMaxOrder = Math.max(...existingUrlRules.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          urlOrderTracker = nonDefaultMaxOrder + 1;
        }
      } catch(e) { /* use order 1 */ }

      for (const rule of template.policies.urlFiltering) {
        if (rule.action === 'ISOLATE' && !rule.cbiProfile) {
          results.errors.push({ category: 'URL Filtering', name: rule.name, error: 'Skipped: no Cloud Browser Isolation profile in this tenant (create one in the Isolation portal).' });
          continue;
        }
        if (!rule.urlCategories || !rule.urlCategories.length) {
          results.warnings.push(`${rule.name}: no categories left after matching this tenant — skipped.`);
          continue;
        }
        try {
          // CAUTION supports CONNECT/GET/HEAD; ISOLATE rules in live tenants use GET + CONNECT
          const requestMethods = rule.action === 'CAUTION'
            ? ['CONNECT', 'GET', 'HEAD']
            : rule.action === 'ISOLATE' ? ['CONNECT', 'GET']
            : ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
               'CONNECT', 'OTHER', 'PROPFIND', 'PROPPATCH', 'MOVE', 'MKCOL',
               'LOCK', 'COPY', 'UNLOCK', 'PATCH'];

          // Replace custom category names with their API-assigned IDs
          const urlCategories = rule.urlCategories.map(cat => {
            if (customCategoryIds[cat]) {
              return customCategoryIds[cat];
            }
            return cat;
          });

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: urlOrderTracker,
            state: rule.state,
            rank: 7,
            action: rule.action,
            urlCategories,
            protocols: rule.action === 'ISOLATE' ? (rule.protocols || ['HTTPS_RULE', 'HTTP_RULE']) : ['ANY_RULE'],
            requestMethods,
            blockOverride: false,
            enforceTimeValidity: false
          };
          if (rule.action === 'ISOLATE') apiRule.userAgentTypes = (rule.userAgentTypes && rule.userAgentTypes.length) ? rule.userAgentTypes
            : ['OPERA', 'FIREFOX', 'MSIE', 'MSEDGE', 'CHROME', 'SAFARI', 'MSCHREDGE'];
          if (rule.action === 'ISOLATE') apiRule.cbiProfile = { id: rule.cbiProfile.id, name: rule.cbiProfile.name, url: rule.cbiProfile.url,
            ...(rule.cbiProfile.profileSeq !== undefined ? { profileSeq: rule.cbiProfile.profileSeq } : {}) };

          const result = await client.createUrlFilteringRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'URL Filtering', name: rule.name, id: result?.id });
          logger.logPolicyApply('URL Filtering', rule.name, 'CREATE', { success: true, id: result?.id });
          urlOrderTracker++; // Only increment on success
        } catch (e) {
          results.errors.push({ category: 'URL Filtering', name: rule.name, error: e.message });
          logger.logPolicyApply('URL Filtering', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Firewall Rules
    if (template.policies?.firewallFiltering) {
      let fwOrderTracker = 5; // Start after predefined rules
      try {
        const existingFwRules = await client.getFirewallRules();
        if (Array.isArray(existingFwRules) && existingFwRules.length > 0) {
          const nonDefaultMaxOrder = Math.max(...existingFwRules.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          fwOrderTracker = nonDefaultMaxOrder + 1;
        }
      } catch(e) { /* use default */ }

      for (const rule of template.policies.firewallFiltering) {
        try {
          const action = rule.action === 'BLOCK_ICMP_UNREACHABLE' ? 'BLOCK_DROP' : rule.action;
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: fwOrderTracker,
            state: rule.state,
            rank: 7,
            action: action,
            enableFullLogging: false
          };

          // Add network application categories (critical — without these, rules match ALL traffic)
          if (rule.nwApplications && rule.nwApplications.length > 0) {
            apiRule.nwApplications = rule.nwApplications;
          }

          // Add destination ports if specified
          if (rule.destPorts) {
            apiRule.destPorts = rule.destPorts;
          }

          // Add protocols if specified (e.g., UDP_RULE for QUIC block)
          if (rule.protocols && rule.protocols.length > 0) {
            apiRule.protocols = rule.protocols;
          }

          // Add destIpCategories if present
          if (rule.destIpCategories && rule.destIpCategories.length > 0) {
            apiRule.destIpCategories = rule.destIpCategories;
          }
          const result = await client.createFirewallRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'Firewall', name: rule.name, id: result?.id });
          logger.logPolicyApply('Firewall', rule.name, 'CREATE', { success: true, id: result?.id });
          fwOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'Firewall', name: rule.name, error: e.message });
          logger.logPolicyApply('Firewall', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply SSL Inspection Rules
    if (template.policies?.sslInspection) {
      // Place the new rules right after Zscaler's predefined rules (so they win over older custom rules);
      // if the tenant refuses that position ("rank 7 is not allowed at order N"), append after the last rule.
      let sslOrder = 1, sslLast = 1;
      try {
        const existingSsl = (await client.getSslInspectionRules()) || [];
        const nonDefault = existingSsl.filter(r => !r.defaultRule);
        sslLast = Math.max(...nonDefault.map(r => r.order || 0), 0) + 1;
        sslOrder = Math.max(...nonDefault.filter(r => r.predefined).map(r => r.order || 0), 0) + 1;
      } catch (e) { /* order 1 */ }
      for (const rule of template.policies.sslInspection) {
        const noCats = !rule.urlCategories || !rule.urlCategories.length;
        if ((rule.action === 'DO_NOT_DECRYPT' || rule.sslExempt) && noCats) {
          // An exemption with no categories would stop inspection of ALL traffic — never create it
          results.warnings.push(`${rule.name}: no categories left after matching this tenant — skipped.`);
          continue;
        }
        try {
          // Per Zscaler API docs (automate.zscaler.com):
          // - action is a nested object: { type, decryptSubActions/doNotDecryptSubActions, showEUN, etc }
          // - urlCategories is NOT a string array for SSL — it's an object array
          // - decryptSubActions uses minClientTLSVersion (uppercase TLS), not minClientTlsVersion
          const actionType = (rule.action === 'INSPECT' || rule.action === 'DECRYPT')
            ? 'DECRYPT' : 'DO_NOT_DECRYPT';

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: sslOrder,
            state: rule.state,
            rank: 7,
            roadWarriorForKerberos: false
          };

          if (actionType === 'DO_NOT_DECRYPT') {
            apiRule.action = {
              type: 'DO_NOT_DECRYPT',
              doNotDecryptSubActions: {
                serverCertificates: 'ALLOW',
                bypassOtherPolicies: false,
                ocspCheck: false,
                blockSslTrafficWithNoSniEnabled: false
              },
              showEUN: false,
              showEUNATP: false,
              overrideDefaultCertificate: false
            };
          } else {
            // DECRYPT action — field names must match API doc exactly
            // API doc shows: minClientTLSVersion (not minClientTlsVersion)
            // ZTH Ebook uses TLS 1.2 minimum; standard tiers use TLS 1.0
            const clientTLS = rule.minClientTLS || 'CLIENT_TLS_1_0';
            const serverTLS = rule.minServerTLS || 'SERVER_TLS_1_0';
            apiRule.action = {
              type: 'DECRYPT',
              decryptSubActions: {
                serverCertificates: 'ALLOW',
                ocspCheck: true,
                blockSslTrafficWithNoSniEnabled: true,
                minClientTLSVersion: clientTLS,
                minServerTLSVersion: serverTLS,
                blockUndecrypt: true,
                http2Enabled: false
              },
              showEUN: false,
              showEUNATP: false,
              overrideDefaultCertificate: false
            };
          }

          // urlCategories: use plain string array for specific categories (proven working in v1.0.8/1.0.9)
          // For catch-all (ANY), omit urlCategories entirely (proven working in v1.0.9)
          if (actionType === 'DECRYPT' && rule.sslInterceptionCert && rule.sslInterceptionCert.id !== undefined) {
            apiRule.action.overrideDefaultCertificate = true;
            apiRule.action.sslInterceptionCert = { id: rule.sslInterceptionCert.id, name: rule.sslInterceptionCert.name };
          }
          if (rule.urlCategories && rule.urlCategories.length > 0 &&
              !(rule.urlCategories.length === 1 && rule.urlCategories[0] === 'ANY')) {
            apiRule.urlCategories = rule.urlCategories;
          }
          // When urlCategories is ["ANY"] or empty, we omit it — matches all traffic

          let result;
          try { result = await client.createSslInspectionRule(apiRule); }
          catch (e) {
            if (!/not allowed at order/i.test(String(e.message))) throw e;
            apiRule.order = sslOrder = Math.max(sslOrder, sslLast);
            result = await client.createSslInspectionRule(apiRule);
            results.warnings.push(`${rule.name}: placed at order ${apiRule.order} (the tenant did not allow it higher). Check that rules above it don't catch the same traffic.`);
          }
          sslOrder = apiRule.order + 1; sslLast = Math.max(sslLast, apiRule.order) + 1;
          results.applied.push({ type: 'CREATE', category: 'SSL Inspection', name: rule.name, id: result?.id, order: apiRule.order });
          logger.logPolicyApply('SSL Inspection', rule.name, 'CREATE', { success: true, id: result?.id });
        } catch (e) {
          results.errors.push({ category: 'SSL Inspection', name: rule.name, error: e.message });
          logger.logPolicyApply('SSL Inspection', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Sandbox Rules
    if (template.policies?.sandbox) {
      let sbOrderTracker = 1;
      // Some tenants refuse ANY / NONE ("ANY/NONE/null are not valid entries"): name the file types and protocols.
      // Prefer the file types on the tenant's own default Sandbox rule, else every sandbox-able type except images.
      let sbDefaultTypes = null;
      try {
        const existingSb = await client.getSandboxRules();
        if (Array.isArray(existingSb) && existingSb.length > 0) {
          const nonDefaultMax = Math.max(...existingSb.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          sbOrderTracker = nonDefaultMax + 1;
          const def = existingSb.find(r => r.defaultRule && Array.isArray(r.fileTypes));
          const t = def ? def.fileTypes.filter(x => !/^(ANY|NONE)$/.test(x)) : [];
          if (t.length) sbDefaultTypes = t;
        }
      } catch(e) { /* use 1 */ }
      const SANDBOX_FILE_TYPES = ['FTCATEGORY_FLASH', 'FTCATEGORY_JAVA_APPLET', 'FTCATEGORY_HTA', 'FTCATEGORY_ZIP', 'FTCATEGORY_TAR',
        'FTCATEGORY_BZIP2', 'FTCATEGORY_RAR', 'FTCATEGORY_ISO', 'FTCATEGORY_P7Z', 'FTCATEGORY_SCZIP', 'FTCATEGORY_DMG',
        'FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_MICROSOFT_INSTALLER', 'FTCATEGORY_WINDOWS_LIBRARY', 'FTCATEGORY_PYTHON',
        'FTCATEGORY_POWERSHELL', 'FTCATEGORY_VISUAL_BASIC_SCRIPT', 'FTCATEGORY_BAT', 'FTCATEGORY_WINDOWS_SCRIPT_FILES', 'FTCATEGORY_APK',
        'FTCATEGORY_MS_POWERPOINT', 'FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_RTF', 'FTCATEGORY_PDF_DOCUMENT'];
      const SANDBOX_PROTOCOLS = ['FOHTTP_RULE', 'FTP_RULE', 'HTTPS_RULE', 'HTTP_RULE'];

      // Look up CBI isolation profile if any rule needs QUARANTINE_ISOLATE
      let cbiProfileId = null;
      const needsCbi = template.policies.sandbox.some(r => r.firstTimeOperation === 'QUARANTINE_ISOLATE');
      if (needsCbi) {
        try {
          // Fetch isolation profiles from the API
          const profiles = await client.getCbiProfiles();
          if (Array.isArray(profiles)) {
            const defaultProfile = profiles.find(p =>
              p.name === 'Default Isolation Profile' || p.defaultProfile === true
            );
            if (defaultProfile) {
              cbiProfileId = defaultProfile.id;
              console.log(`[APPLY] Found CBI profile: "${defaultProfile.name}" -> ID: ${cbiProfileId}`);
            } else if (profiles.length > 0) {
              // Use first available profile as fallback
              cbiProfileId = profiles[0].id;
              console.log(`[APPLY] Using first CBI profile: "${profiles[0].name}" -> ID: ${cbiProfileId}`);
            }
          }
        } catch(e) {
          results.warnings.push(`Could not fetch CBI profiles: ${e.message}. QUARANTINE_ISOLATE rules will fall back to QUARANTINE.`);
          console.log(`[APPLY] CBI profile lookup failed: ${e.message}`);
        }
      }

      for (const rule of template.policies.sandbox) {
        try {
          let firstTimeOp = rule.firstTimeOperation || 'QUARANTINE';
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: sbOrderTracker,
            state: rule.state,
            rank: 7,
            protocols: (() => { const p = (rule.protocols || []).filter(x => x !== 'ANY_RULE' && x !== 'ANY'); return p.length ? p : SANDBOX_PROTOCOLS; })(),
            fileTypes: (() => { const f = (rule.fileTypes || []).filter(x => !/^(ANY|NONE)$/.test(x)); return f.length ? f : (sbDefaultTypes || SANDBOX_FILE_TYPES); })(),
            baPolicyCategories: rule.baPolicyCategories || [],
            baRuleAction: rule.baRuleAction || 'BLOCK',
            firstTimeEnable: rule.firstTimeEnable || false,
            mlActionEnabled: rule.mlActionEnabled || false
          };

          // Handle QUARANTINE_ISOLATE — needs cbiProfile
          if (firstTimeOp === 'QUARANTINE_ISOLATE' && cbiProfileId) {
            apiRule.firstTimeOperation = 'QUARANTINE_ISOLATE';
            apiRule.cbiProfileId = cbiProfileId;
          } else if (firstTimeOp === 'QUARANTINE_ISOLATE' && !cbiProfileId) {
            // Fall back to plain QUARANTINE if no CBI profile found
            apiRule.firstTimeOperation = 'QUARANTINE';
            results.warnings.push(`${rule.name}: Fell back to QUARANTINE (no CBI profile available for QUARANTINE_ISOLATE)`);
          } else {
            apiRule.firstTimeOperation = firstTimeOp;
          }

          const result = await client.createSandboxRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'Sandbox', name: rule.name, id: result?.id });
          logger.logPolicyApply('Sandbox', rule.name, 'CREATE', { success: true, id: result?.id });
          sbOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'Sandbox', name: rule.name, error: e.message });
          logger.logPolicyApply('Sandbox', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply DNS Security Rules
    if (template.policies?.dnsSecurity) {
      let dnsOrderTracker = 1;
      try {
        const existingDns = await client.getDnsControlRules();
        if (Array.isArray(existingDns) && existingDns.length > 0) {
          const nonDefaultMax = Math.max(...existingDns.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          dnsOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      for (const rule of template.policies.dnsSecurity) {
        try {
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: dnsOrderTracker,
            state: rule.state,
            rank: rule.rank || 7,
            action: rule.action || 'BLOCK',
            protocols: rule.protocols || ['ANY_RULE']
          };
          if (rule.applications && rule.applications.length > 0) {
            apiRule.applications = rule.applications;
          }
          const result = await client.createDnsControlRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'DNS Security', name: rule.name, id: result?.id });
          logger.logPolicyApply('DNS Security', rule.name, 'CREATE', { success: true, id: result?.id });
          dnsOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'DNS Security', name: rule.name, error: e.message });
          logger.logPolicyApply('DNS Security', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply File Type Control Rules
    if (template.policies?.fileTypeControl) {
      let ftcOrderTracker = 1;
      try {
        const existingFtc = await client.getFileTypeRules();
        if (Array.isArray(existingFtc) && existingFtc.length > 0) {
          const nonDefaultMax = Math.max(...existingFtc.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          ftcOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      for (const rule of template.policies.fileTypeControl) {
        try {
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: ftcOrderTracker,
            state: rule.state,
            rank: 7,
            protocols: rule.protocols || ['ANY_RULE'],
            fileTypes: rule.fileTypes || [],
            filteringAction: rule.filteringAction || 'BLOCK',
            operation: rule.operation || 'UPLOAD_DOWNLOAD'
          };
          if (rule.passwordProtected !== undefined) {
            apiRule.passwordProtected = rule.passwordProtected;
          }
          const result = await client.createFileTypeRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'File Type Control', name: rule.name, id: result?.id });
          logger.logPolicyApply('File Type Control', rule.name, 'CREATE', { success: true, id: result?.id });
          ftcOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'File Type Control', name: rule.name, error: e.message });
          logger.logPolicyApply('File Type Control', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Cloud App Control Rules
    if (template.policies?.cloudAppControl) {
      // Track order per rule type since each CAC category has its own order space
      const cacOrderTrackers = {};

      for (const rule of template.policies.cloudAppControl) {
        try {
          const ruleType = rule.ruleType || rule.type || 'AI_ML';

          // Fetch current max order for this rule type if not yet cached
          if (cacOrderTrackers[ruleType] === undefined) {
            try {
              const existing = await client.getCloudAppControlRules(ruleType);
              if (Array.isArray(existing) && existing.length > 0) {
                const nonDefaultMax = Math.max(...existing.filter(r => !r.predefined).map(r => r.order || 0), 0);
                cacOrderTrackers[ruleType] = nonDefaultMax + 1;
              } else {
                cacOrderTrackers[ruleType] = 1;
              }
            } catch(e) { cacOrderTrackers[ruleType] = 1; }
          }

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: cacOrderTrackers[ruleType],
            state: rule.state,
            rank: 7,
            type: ruleType,
            actions: rule.actions || []
          };

          const result = await client.createCloudAppControlRule(ruleType, apiRule);
          results.applied.push({ type: 'CREATE', category: 'Cloud App Control', name: rule.name, id: result?.id });
          logger.logPolicyApply('Cloud App Control', rule.name, 'CREATE', { success: true, id: result?.id });
          cacOrderTrackers[ruleType]++;
        } catch (e) {
          results.errors.push({ category: 'Cloud App Control', name: rule.name, error: e.message });
          logger.logPolicyApply('Cloud App Control', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply DLP Rules (Web DLP Rules) — Dictionary-first hybrid approach
    if (template.policies?.dlp) {
      const dlpPrefix = template.metadata?.prefix || 'GOV';

      // Step 1: Fetch engines and dictionaries from tenant
      let dlpEngines = [];
      let dlpDictionaries = [];
      try {
        dlpEngines = await client.getDlpEngines() || [];
        if (!Array.isArray(dlpEngines)) dlpEngines = [];
        console.log(`[APPLY] Found ${dlpEngines.length} DLP engines on tenant:`);
        dlpEngines.forEach(e => console.log(`[APPLY]   Engine ID=${e.id} name="${e.name}"`));
      } catch(e) {
        results.warnings.push(`Could not fetch DLP engines: ${e.message}`);
      }

      try {
        dlpDictionaries = await client.getDlpDictionaries() || [];
        if (!Array.isArray(dlpDictionaries)) dlpDictionaries = [];
        console.log(`[APPLY] Found ${dlpDictionaries.length} DLP dictionaries on tenant`);
        // Log predefined dictionaries to see their actual names
        const predefinedDicts = dlpDictionaries.filter(d => !d.custom);
        const customDicts = dlpDictionaries.filter(d => d.custom);
        console.log(`[APPLY] Predefined: ${predefinedDicts.length}, Custom: ${customDicts.length}`);
        predefinedDicts.forEach(d => console.log(`[APPLY]   PREDEF Dict ID=${d.id} name="${d.name}" nameL10n=${d.nameL10nTag} desc="${(d.description || '').substring(0, 60)}"`));
        customDicts.slice(0, 5).forEach(d => console.log(`[APPLY]   CUSTOM Dict ID=${d.id} name="${d.name}"`));
      } catch(e) {
        results.warnings.push(`Could not fetch DLP dictionaries: ${e.message}`);
      }

      // Step 2: Order tracking
      let dlpOrderTracker = 1;
      try {
        const existingDlp = await client.getWebDlpRules();
        if (Array.isArray(existingDlp) && existingDlp.length > 0) {
          const nonDefaultMax = Math.max(...existingDlp.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          dlpOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      // Helper: find engine by name (flexible matching)
      function findEngine(name) {
        if (!name || dlpEngines.length === 0) return null;
        let match = dlpEngines.find(e => e.name === name);
        if (match) return match;
        match = dlpEngines.find(e => e.name && e.name.toLowerCase() === name.toLowerCase());
        if (match) return match;
        const words = name.toLowerCase().split(/[\s\-()]+/).filter(w => w.length > 2);
        if (words.length > 0) {
          match = dlpEngines.find(e => e.name && words.every(w => e.name.toLowerCase().includes(w)));
        }
        return match || null;
      }

      // Helper: get the display name from a dictionary object (API may use different fields)
      function getDictName(d) {
        return d.name || d.dictionaryName || d.configuredName || d.displayName || '';
      }

      // Predefined dictionary display-name to internal-name mapping
      // Built from the actual tenant dump — predefined dicts use _LEAKAGE suffix codes
      const DICT_DISPLAY_TO_INTERNAL = {
        'social security numbers (us)': ['SSN'],
        'credit cards': ['CREDIT_CARD'],
        'medical information': ['MEDICAL'],
        'medical document': ['ML_MEDICAL_DOC_LEAKAGE'],
        'diseases information': ['DISEASES_LEAKAGE'],
        'drugs information': ['DRUGS_LEAKAGE'],
        'treatments information': ['TREATMENTS_LEAKAGE'],
        'financial statements': ['FINANCIAL'],
        'names (us)': ['NAME_LEAKAGE'],
        "driver's license (united states)": ['USDL_LEAKAGE', 'EN_USDL_LEAKAGE'],
        'credentials and secrets': ['CRED_LEAKAGE'],
        'source code': ['SOURCE_CODE', 'ML_SOURCE_CODE_DOCUMENT_LEAKAGE'],
        'adult content': ['ADULT_CONTENT'],
        'self-harm & cyberbullying': ['CYBER_BULLY'],
        'tax identification number (us)': ['TIN_LEAKAGE', 'USITIN_LEAKAGE'],
        'individual taxpayer registry id (brazil)': ['CPF_LEAKAGE'],
        'invoice document': ['ML_INVOICE_LEAKAGE'],
        'tax document': ['ML_TAX_LEAKAGE'],
        'corporate finance document': ['ML_CORPORATE_FINANCE_LEAKAGE'],
        'aba bank routing numbers': ['ABA_LEAKAGE'],
        'international bank account number (iban)': ['EUIBAN_LEAKAGE'],
        'legal document': ['ML_LEGAL_LEAKAGE'],
        'court document': ['ML_COURT_LEAKAGE'],
        'immigration document': ['ML_IMMIGRATION_LEAKAGE'],
        'resume document': ['ML_RESUME_LEAKAGE'],
        'insurance document': ['ML_INSURANCE_LEAKAGE'],
        'national identification number (france)': ['INSEE_LEAKAGE'],
        'national identification number (spain)': ['DNI_LEAKAGE'],
        'national identification number (poland)': ['PESEL_LEAKAGE'],
        'passport number (european union)': ['PPEU_LEAKAGE'],
        'citizen service numbers (netherlands)': ['BSN_LEAKAGE'],
        'fiscal code (italy)': ['FISCAL_LEAKAGE'],
        'national insurance number (uk)': ['NINO_LEAKAGE'],
        'national health service number (uk)': ['NHS_LEAKAGE']
      };

      // Helper: find dictionary by display name using exact internal name mapping
      function findDictionary(targetName) {
        if (!targetName || dlpDictionaries.length === 0) return null;
        const target = targetName.toLowerCase().trim();

        // Strategy 1: Exact match on name field
        let match = dlpDictionaries.find(d => getDictName(d).toLowerCase() === target);
        if (match) return match;

        // Strategy 2: Use the display-to-internal mapping (exact match on internal code)
        const internalNames = DICT_DISPLAY_TO_INTERNAL[target];
        if (internalNames) {
          for (const iName of internalNames) {
            match = dlpDictionaries.find(d => getDictName(d) === iName);
            if (match) return match;
          }
        }

        // Strategy 3: Description field contains target (only for predefined dicts)
        // Skip this — it caused too many false matches

        return null;
      }

      // Step 3: Create each DLP rule
      for (const rule of template.policies.dlp) {
        try {
          const isWCI = rule.withoutContentInspection === true;
          let resolvedEngine = null;
          let resolvedDictIds = [];

          if (!isWCI) {
            // Try preferred engines first
            if (rule.preferredEngineNames && rule.preferredEngineNames.length > 0) {
              for (const eName of rule.preferredEngineNames) {
                resolvedEngine = findEngine(eName);
                if (resolvedEngine) {
                  console.log(`[APPLY] "${rule.name}" engine: "${resolvedEngine.name}" (ID: ${resolvedEngine.id})`);
                  break;
                }
              }
            }

            // No engine — resolve dictionaries and create a custom engine from them
            if (!resolvedEngine && rule.dictionaryNames && rule.dictionaryNames.length > 0) {
              const found = [];
              const missing = [];
              for (const dName of rule.dictionaryNames) {
                const dict = findDictionary(dName);
                if (dict) {
                  found.push(dict);
                  resolvedDictIds.push(dict.id);
                  console.log(`[APPLY]   Dict match: "${dName}" -> "${getDictName(dict)}" (ID: ${dict.id})`);
                } else {
                  missing.push(dName);
                  console.log(`[APPLY]   Dict NOT found: "${dName}"`);
                }
              }
              if (missing.length > 0) {
                results.warnings.push(`${rule.name}: Dictionaries not found: ${missing.join(', ')}`);
              }

              // Create a custom DLP engine from resolved dictionaries
              if (found.length > 0) {
                try {
                  const engineName = rule.name.replace(dlpPrefix + '-DLP-', dlpPrefix + '-Engine-');
                  // engineExpression format from API docs:
                  //   Single:  ((D63.S> 1))
                  //   OR:      ((D38.S> 1) OR (D63.S> 1))
                  //   AND:     ((D38.S> 1) AND (D63.S> 1))
                  // Each dictionary ID is wrapped with prefix D and suffix .S
                  let engineExpression;
                  if (found.length === 1) {
                    engineExpression = `((D${found[0].id}.S> 1))`;
                  } else {
                    const parts = found.map(d => `(D${d.id}.S> 1)`).join(' OR ');
                    engineExpression = `(${parts})`;
                  }

                  const customEngine = {
                    name: engineName,
                    description: `Auto-created by Zscaler Policy Wizard. Dictionaries: ${found.map(d => getDictName(d)).join(', ')}`,
                    customDlpEngine: true,
                    engineExpression: engineExpression
                  };

                  console.log(`[APPLY] Creating custom engine "${engineName}" engineExpression: ${engineExpression}`);
                  const result = await client.createCustomDlpEngine(customEngine);
                  if (result && result.id) {
                    resolvedEngine = result;
                    console.log(`[APPLY] Created custom DLP engine: "${engineName}" (ID: ${result.id})`);
                    results.applied.push({ type: 'CREATE', category: 'DLP Engine', name: engineName, id: result.id });
                  }
                } catch (engineErr) {
                  console.log(`[APPLY] Custom engine creation failed: ${engineErr.message}`);
                  // Fall through — will try without engine below
                }
              }

              if (resolvedDictIds.length === 0 && !resolvedEngine) {
                results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: `No engines or dictionaries found. Needed: ${rule.dictionaryNames.join(', ')}` });
                continue;
              }
            }

            // If we have dictionaries but still no engine, try withoutContentInspection as last resort
            if (!resolvedEngine && resolvedDictIds.length > 0) {
              console.log(`[APPLY] "${rule.name}" — has ${resolvedDictIds.length} dictionaries but no engine. Will attempt rule creation with engine fallbacks.`);
            }

            if (!resolvedEngine && resolvedDictIds.length === 0) {
              results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: 'No engine or dictionaries resolved' });
              continue;
            }
          }

          // --- Build API payload ---
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: dlpOrderTracker,
            state: 'ENABLED',
            rank: 7,
            protocols: ['ANY_RULE'],
            action: rule.action === 'BLOCK' ? 'BLOCK' : 'ALLOW', // v1.6.0: Allow/Block choice
            severity: rule.severity || 'RULE_SEVERITY_MEDIUM'
          };

          // Text-based file type categories — avoid OCR-heavy image types
          const TEXT_FILE_TYPES = [
            'FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_POWERPOINT',
            'FTCATEGORY_MS_RTF', 'FTCATEGORY_PDF_DOCUMENT', 'FTCATEGORY_TEXT',
            'FTCATEGORY_CSV', 'FTCATEGORY_HTML'
          ];

          if (isWCI || (!resolvedEngine)) {
            // Without content inspection — fallback when no engine created
            apiRule.withoutContentInspection = true;
            // WCI rules REQUIRE fileTypes — use text-based categories
            apiRule.fileTypes = TEXT_FILE_TYPES;
            if (!isWCI && !resolvedEngine) {
              results.warnings.push(`${rule.name}: No DLP engine matched. Created as without-content-inspection rule. For full scanning, create a custom DLP engine from: ${(rule.dictionaryNames || []).join(', ')}`);
            }
          } else if (resolvedEngine) {
            apiRule.dlpEngines = [{ id: resolvedEngine.id }];
          }

          // Attempt 1: Without incident receiver (it causes 400 on this tenant)
          let created = false;
          try {
            const result = await client.createWebDlpRule(apiRule);
            results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
            logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id });
            dlpOrderTracker++;
            created = true;
          } catch (e1) {
            console.log(`[APPLY] DLP attempt 1 failed "${rule.name}": ${e1.message}`);
            // Attempt 2: Add zscalerIncidentReceiver (works on some tenants)
            try {
              apiRule.zscalerIncidentReceiver = true;
              const result = await client.createWebDlpRule(apiRule);
              results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
              logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id, fallback: 'with-receiver' });
              dlpOrderTracker++;
              created = true;
            } catch (e2) {
              console.log(`[APPLY] DLP attempt 2 failed "${rule.name}": ${e2.message}`);
              // Attempt 3: Bare minimum with text fileTypes for WCI
              try {
                const bareRule = {
                  name: rule.name,
                  order: dlpOrderTracker,
                  rank: 7,
                  state: 'ENABLED',
                  action: rule.action === 'BLOCK' ? 'BLOCK' : 'ALLOW',
                  protocols: ['ANY_RULE']
                };
                if (resolvedEngine) {
                  bareRule.dlpEngines = [{ id: resolvedEngine.id }];
                } else {
                  bareRule.withoutContentInspection = true;
                  bareRule.fileTypes = TEXT_FILE_TYPES;
                }
                const result = await client.createWebDlpRule(bareRule);
                results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
                results.warnings.push(`${rule.name}: Created with bare minimum fields`);
                logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id, fallback: 'bare' });
                dlpOrderTracker++;
                created = true;
              } catch (e3) {
                const dictInfo = rule.dictionaryNames ? ` Dictionaries: ${rule.dictionaryNames.join(', ')}` : '';
                results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: `All attempts failed. ${e3.message}.${dictInfo} Use /api/diag/dlp to inspect tenant.` });
                logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { error: e3.message });
              }
            }
          }
        } catch (e) {
          results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: e.message });
          logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // IPS Control rules
    if (template.policies?.ipsControl) {
      let ipsOrder = 1;
      try {
        const existing = await client.getIpsRules();
        if (Array.isArray(existing) && existing.length) ipsOrder = Math.max(...existing.filter(r => !r.defaultRule && !r.predefined).map(r => r.order || 0), 0) + 1;
      } catch (e) { /* default order */ }
      for (const rule of template.policies.ipsControl) {
        if (!rule.threatCategories || !rule.threatCategories.length) {
          results.errors.push({ category: 'IPS Control', name: rule.name, error: `Skipped: the "${rule.threatCategoryLabel}" threat category was not found in this tenant.` });
          continue;
        }
        try {
          const apiRule = { name: rule.name.substring(0, 31), description: rule.description || '', order: ipsOrder, rank: 7, state: rule.state || 'ENABLED',
            action: rule.action || 'BLOCK_DROP', threatCategories: rule.threatCategories.map(t => ({ id: t.id })) };
          const result = await client.createIpsRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'IPS Control', name: apiRule.name, id: result?.id });
          logger.logPolicyApply('IPS Control', apiRule.name, 'CREATE', { success: true, id: result?.id });
          ipsOrder++;
        } catch (e) {
          results.errors.push({ category: 'IPS Control', name: rule.name, error: e.message });
          logger.logPolicyApply('IPS Control', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Advanced Threat Protection settings: GET, merge, PUT, read back.
    // Countries are added to whatever the tenant already blocks (nothing is unblocked).
    if (template.policies?.advancedThreatProtection) {
      const atp = template.policies.advancedThreatProtection;
      try {
        const current = await client.getAtpSettings();
        const body = { ...current, ...(atp.settings || {}) };
        if (atp.blockedCountries && atp.blockedCountries.length) {
          const merged = new Set([...(current.blockedCountries || []).filter(c => c !== 'NONE'), ...atp.blockedCountries]);
          body.blockedCountries = [...merged];
        }
        const { sent } = await putAtpSettings(client, body, results.warnings);
        const after = await client.getAtpSettings();
        const notApplied = Object.entries(atp.settings || {}).filter(([k, v]) => k in sent && after[k] !== v).map(([k]) => k);
        const missingCountries = (atp.blockedCountries || []).filter(c => !(after.blockedCountries || []).includes(c));
        results.applied.push({ type: 'UPDATE', category: 'Advanced Threat Protection', name: atp.name,
          detail: `${Object.keys(atp.settings || {}).length} settings, ${(atp.blockedCountries || []).length} blocked countries` });
        if (notApplied.length) results.errors.push({ category: 'Advanced Threat Protection', name: atp.name, error: `Read back shows these not set: ${notApplied.join(', ')}` });
        if (missingCountries.length) results.errors.push({ category: 'Advanced Threat Protection', name: atp.name, error: `Read back is missing blocked countries: ${missingCountries.join(', ')}` });
        logger.logPolicyApply('Advanced Threat Protection', atp.name, 'UPDATE', { success: !notApplied.length && !missingCountries.length, before: current, settings: atp.settings, blockedCountries: body.blockedCountries });
      } catch (e) {
        if (e.featureFlag) {
          results.warnings.push(`Advanced Threat Protection: ${e.message}`);
          results.skipped = results.skipped || []; results.skipped.push({ category: 'Advanced Threat Protection', name: atp.name, reason: e.message });
        } else results.errors.push({ category: 'Advanced Threat Protection', name: atp.name, error: e.message });
        logger.logPolicyApply('Advanced Threat Protection', atp.name, 'UPDATE', { error: e.message });
      }
    }

    // Activate changes
    try {
      await client.activateChanges();
      results.activated = true;
      logger.log('ACTIVATION', { success: true });
    } catch (e) {
      results.activated = false;
      results.errors.push({ category: 'Activation', error: e.message });
      logger.log('ACTIVATION', { success: false, error: e.message }, 'error');
    }

    // A rule that already exists by name is left as it is (this tool creates, it never overwrites)
    const dup = (e) => /DUPLICATE_ITEM|already exists/i.test(String(e && e.error || ''));
    results.skippedExisting = results.errors.filter(dup).map(e => ({ category: e.category, name: e.name }));
    results.errors = results.errors.filter(e => !dup(e));
    for (const s2 of results.skippedExisting) results.warnings.push(`${s2.category} "${s2.name}" already exists — left unchanged.`);

    results.summary = {
      skippedExisting: results.skippedExisting.length,
      applied: results.applied.length,
      errors: results.errors.length,
      activated: results.activated,
      snapshotId
    };

    req.session.appliedChanges.push({
      timestamp: new Date().toISOString(),
      template: template.metadata,
      results
    });

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Rollback Routes
// ========================

app.post('/api/rollback', requireAuth, async (req, res) => {
  try {
    const { snapshotId } = req.body;
    const session = req.session;
    const snapshot = session.snapshots[snapshotId];

    if (!snapshot) {
      return res.status(404).json({ error: 'Snapshot not found. Rollback not available.' });
    }

    // Best-effort rollback: we note this is limited since we only create, not delete
    const results = {
      message: 'Rollback is best-effort. Created rules must be manually removed from ZIA admin portal. Snapshot state has been recorded for reference.',
      snapshotTimestamp: snapshot.timestamp,
      originalState: {
        urlRulesCount: snapshot.urlRules.length,
        fwRulesCount: snapshot.fwRules.length,
        sslRulesCount: snapshot.sslRules.length,
        dlpRulesCount: (snapshot.dlpRules || []).length
      }
    };

    // ATP settings are a single object, so they can be put back exactly
    if (snapshot.atp) {
      try {
        await putAtpSettings(session.client, snapshot.atp, []);
        await session.client.activateChanges();
        results.atpRestored = true;
        results.message += ' Advanced Threat Protection settings (including blocked countries) were restored to the dry-run snapshot and activated.';
      } catch (e) { results.atpRestored = false; results.atpError = e.message; }
    }
    session.logger.logRollback(snapshotId, results);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Current State Routes
// ========================

// Diagnostic route — fetches a sample of current rules to show API schema
app.get('/api/diag/schema', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const diag = {};
    
    try {
      const urlRules = await client.getUrlFilteringRules();
      diag.urlFilteringRules = {
        count: Array.isArray(urlRules) ? urlRules.length : 'unknown',
        sample: Array.isArray(urlRules) && urlRules[0] ? urlRules[0] : urlRules
      };
    } catch (e) { diag.urlFilteringRules = { error: e.message }; }
    
    try {
      const fwRules = await client.getFirewallRules();
      diag.firewallRules = {
        count: Array.isArray(fwRules) ? fwRules.length : 'unknown',
        sample: Array.isArray(fwRules) && fwRules[0] ? fwRules[0] : fwRules
      };
    } catch (e) { diag.firewallRules = { error: e.message }; }
    
    try {
      const sslRules = await client.getSslInspectionRules();
      diag.sslInspectionRules = {
        count: Array.isArray(sslRules) ? sslRules.length : 'unknown',
        sample: Array.isArray(sslRules) && sslRules[0] ? sslRules[0] : sslRules,
        // Show ALL SSL rules so we can see DECRYPT rule format
        allRules: Array.isArray(sslRules) ? sslRules.map(r => ({
          id: r.id, name: r.name, order: r.order,
          action: r.action,
          urlCategories: r.urlCategories,
          platforms: r.platforms,
          predefined: r.predefined, defaultRule: r.defaultRule
        })) : []
      };
    } catch (e) { diag.sslInspectionRules = { error: e.message }; }

    try {
      const cats = await client.getUrlCategories();
      diag.urlCategories = {
        count: Array.isArray(cats) ? cats.length : 'unknown',
        names: Array.isArray(cats) ? cats.map(c => c.id || c.configuredName || c.name) : 'unknown'
      };
    } catch (e) { diag.urlCategories = { error: e.message }; }

    res.json(diag);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/url-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getUrlFilteringRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/firewall-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getFirewallRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/ssl-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getSslInspectionRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/url-categories', requireAuth, async (req, res) => {
  try {
    const cats = await req.session.client.getUrlCategories(req.query.customOnly === 'true');
    res.json(cats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/activation', requireAuth, async (req, res) => {
  try {
    const status = await req.session.client.getActivationStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- New v1.2.0 State Routes ---

app.get('/api/state/sandbox-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getSandboxRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dns-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getDnsControlRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/file-type-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getFileTypeRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/cloud-app-rules/:ruleType', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getCloudAppControlRules(req.params.ruleType);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- v1.5.0 DLP State Routes ---

app.get('/api/state/dlp-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getWebDlpRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-engines', requireAuth, async (req, res) => {
  try {
    const engines = await req.session.client.getDlpEngines();
    res.json(engines);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-dictionaries', requireAuth, async (req, res) => {
  try {
    const dicts = await req.session.client.getDlpDictionaries();
    res.json(dicts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-notification-templates', requireAuth, async (req, res) => {
  try {
    const templates = await req.session.client.getDlpNotificationTemplates();
    res.json(templates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DLP diagnostic — full dump of engines, dictionaries, existing rules, notification templates
app.get('/api/diag/dlp', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const diag = {};

    try {
      const engines = await client.getDlpEngines();
      diag.engines = {
        count: Array.isArray(engines) ? engines.length : 'unknown',
        list: Array.isArray(engines) ? engines.map(e => ({ id: e.id, name: e.name, predefinedEngineName: e.predefinedEngineName, customDlpEngine: e.customDlpEngine })) : engines
      };
    } catch (e) { diag.engines = { error: e.message }; }

    try {
      const dicts = await client.getDlpDictionaries();
      diag.dictionaries = {
        count: Array.isArray(dicts) ? dicts.length : 'unknown',
        list: Array.isArray(dicts) ? dicts.map(d => ({ id: d.id, name: d.name, predefinedDlpDictionary: d.predefinedDlpDictionary, custom: d.custom })) : dicts
      };
    } catch (e) { diag.dictionaries = { error: e.message }; }

    try {
      const rules = await client.getWebDlpRules();
      diag.existingRules = {
        count: Array.isArray(rules) ? rules.length : 'unknown',
        list: Array.isArray(rules) ? rules.map(r => ({ id: r.id, name: r.name, order: r.order, action: r.action, state: r.state, dlpEngines: r.dlpEngines })) : rules
      };
    } catch (e) { diag.existingRules = { error: e.message }; }

    try {
      const notif = await client.getDlpNotificationTemplates();
      diag.notificationTemplates = {
        count: Array.isArray(notif) ? notif.length : 'unknown',
        list: Array.isArray(notif) ? notif : notif
      };
    } catch (e) { diag.notificationTemplates = { error: e.message }; }

    try {
      const receivers = await client.getDlpIncidentReceiverServers();
      diag.incidentReceivers = {
        count: Array.isArray(receivers) ? receivers.length : 'unknown',
        list: Array.isArray(receivers) ? receivers : receivers
      };
    } catch (e) { diag.incidentReceivers = { error: e.message }; }

    res.json(diag);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Bulk Delete Routes (v1.2.0)
// ========================

app.post('/api/bulk-delete', requireAuth, async (req, res) => {
  try {
    const { rules } = req.body;
    // rules: array of { category, id, name, ruleType? }
    // category: 'url-filtering' | 'firewall' | 'ssl' | 'sandbox' | 'dns' | 'file-type' | 'cloud-app'
    if (!rules || !Array.isArray(rules) || rules.length === 0) {
      return res.status(400).json({ error: 'No rules specified for deletion. Provide an array of { category, id, name }.' });
    }

    const { client, logger } = req.session;
    const results = { deleted: [], errors: [], skipped: [] };

    for (const rule of rules) {
      if (!rule.id || !rule.category) {
        results.skipped.push({ name: rule.name, reason: 'Missing id or category' });
        continue;
      }

      // Skip default/predefined rules
      if (rule.defaultRule || rule.predefined) {
        results.skipped.push({ name: rule.name, id: rule.id, reason: 'Cannot delete predefined/default rules' });
        continue;
      }

      try {
        switch (rule.category) {
          case 'url-filtering':
            await client.deleteUrlFilteringRule(rule.id);
            break;
          case 'firewall':
            await client.deleteFirewallRule(rule.id);
            break;
          case 'ssl':
            await client.deleteSslInspectionRule(rule.id);
            break;
          case 'sandbox':
            await client.deleteSandboxRule(rule.id);
            break;
          case 'dns':
            await client.deleteDnsControlRule(rule.id);
            break;
          case 'file-type':
            await client.deleteFileTypeRule(rule.id);
            break;
          case 'cloud-app':
            await client.deleteCloudAppControlRule(rule.ruleType || 'AI_ML', rule.id);
            break;
          case 'dlp':
            await client.deleteWebDlpRule(rule.id);
            break;
          case 'dlp-engine':
            await client.deleteCustomDlpEngine(rule.id);
            break;
          case 'dlp-dictionary':
            // Only custom dictionaries can be deleted
            await client.apiCall('DELETE', `/api/v1/dlpDictionaries/${rule.id}`);
            break;
          default:
            results.skipped.push({ name: rule.name, id: rule.id, reason: `Unknown category: ${rule.category}` });
            continue;
        }
        results.deleted.push({ category: rule.category, name: rule.name, id: rule.id });
        logger.log('BULK_DELETE', { category: rule.category, name: rule.name, id: rule.id });
      } catch (e) {
        results.errors.push({ category: rule.category, name: rule.name, id: rule.id, error: e.message });
      }
    }

    // Activate after bulk delete
    try {
      await client.activateChanges();
      results.activated = true;
    } catch (e) {
      results.activated = false;
      results.errors.push({ category: 'Activation', error: e.message });
    }

    results.summary = {
      deleted: results.deleted.length,
      errors: results.errors.length,
      skipped: results.skipped.length,
      activated: results.activated
    };

    logger.log('BULK_DELETE_COMPLETE', results.summary);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Convenience: List all rules across all categories for bulk delete UI
app.get('/api/state/all-rules', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const allRules = {};
    const prefix = req.query.prefix || ''; // Empty = return all rules

    const fetchCategory = async (name, fn) => {
      try {
        const data = await fn();
        let rules = Array.isArray(data) ? data : [];
        // If prefix filter specified, case-insensitive match
        if (prefix) {
          const lowerPrefix = prefix.toLowerCase();
          rules = rules.filter(r => r.name && r.name.toLowerCase().startsWith(lowerPrefix));
        }
        return rules.map(r => {
          // Normalize action to a string — SSL rules return action as an object { type: 'DECRYPT', ... }
          let action = r.action || r.baRuleAction || r.filteringAction || '';
          if (typeof action === 'object' && action !== null) {
            action = action.type || JSON.stringify(action);
          }
          return {
            id: r.id, name: r.name || '(unnamed)', order: r.order,
            state: r.state, action: String(action),
            defaultRule: r.defaultRule || r.predefined || false
          };
        });
      } catch (e) {
        console.error(`[ALL-RULES] Failed to fetch ${name}: ${e.message}`);
        return [];
      }
    };

    allRules.urlFiltering = await fetchCategory('url', () => client.getUrlFilteringRules());
    allRules.firewall = await fetchCategory('fw', () => client.getFirewallRules());
    allRules.ssl = await fetchCategory('ssl', () => client.getSslInspectionRules());
    allRules.sandbox = await fetchCategory('sandbox', () => client.getSandboxRules());
    allRules.dns = await fetchCategory('dns', () => client.getDnsControlRules());
    allRules.fileType = await fetchCategory('ftc', () => client.getFileTypeRules());
    allRules.dlp = await fetchCategory('dlp', () => client.getWebDlpRules());

    // DLP Engines (custom only — predefined engines can't be deleted)
    try {
      const engines = await client.getDlpEngines();
      const engineList = Array.isArray(engines) ? engines : [];
      allRules.dlpEngines = engineList
        .filter(e => e.customDlpEngine === true)
        .filter(e => !prefix || (e.name && e.name.toLowerCase().startsWith(prefix.toLowerCase())))
        .map(e => ({
          id: e.id, name: e.name || '(unnamed)', order: 0,
          state: 'ENABLED', action: e.engineExpression ? 'CUSTOM' : 'PREDEFINED',
          defaultRule: false
        }));
    } catch (e) {
      console.error(`[ALL-RULES] Failed to fetch DLP engines: ${e.message}`);
      allRules.dlpEngines = [];
    }

    // DLP Dictionaries (custom only)
    try {
      const dicts = await client.getDlpDictionaries();
      const dictList = Array.isArray(dicts) ? dicts : [];
      allRules.dlpDictionaries = dictList
        .filter(d => d.custom === true)
        .filter(d => !prefix || (d.name && d.name.toLowerCase().startsWith(prefix.toLowerCase())))
        .map(d => ({
          id: d.id, name: d.name || '(unnamed)', order: 0,
          state: 'ENABLED', action: 'CUSTOM',
          defaultRule: false
        }));
    } catch (e) {
      console.error(`[ALL-RULES] Failed to fetch DLP dictionaries: ${e.message}`);
      allRules.dlpDictionaries = [];
    }

    // Cloud app rules removed from bulk fetch — each type requires a separate API call
    // with rate limiting, adding ~10s to the total. Cloud app rules can be managed
    // individually via the ZIA admin portal.

    res.json(allRules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Audit Log Routes
// ========================

app.get('/api/audit/logs', requireAuth, (req, res) => {
  res.json(req.session.logger.getEntries());
});

app.get('/api/audit/export/csv', requireAuth, (req, res) => {
  const csv = req.session.logger.exportToCSV();
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="zpw-audit-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csv);
});

app.get('/api/audit/export/json', requireAuth, (req, res) => {
  const data = JSON.stringify(req.session.logger.getEntries(), null, 2);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="zpw-audit-${new Date().toISOString().split('T')[0]}.json"`);
  res.send(data);
});



// ========================
// Global Error Handler
// ========================
// Catches any unhandled errors in route handlers
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  const errMsg = `[${timestamp}] UNHANDLED ERROR: ${req.method} ${req.originalUrl} — ${err.stack || err.message}`;
  console.error(errMsg);

  // Also write to error log file
  const dateStr = timestamp.split('T')[0];
  const logFile = path.join(LOG_DIR, `zpw-errors-${dateStr}.log`);
  try {
    fs.appendFileSync(logFile, errMsg + '\n');
  } catch (e) { /* ignore */ }

  res.status(500).json({ error: 'Internal server error. Check server logs for details.' });
});

// ========================
// SPA Fallback
// ========================

app.get('*', (req, res) => sendIndex(res));

// ========================
// Start Server
// ========================

const server = app.listen(PORT, HOST, () => {
  if (typeof global.__ZPW_ON_LISTEN__ === 'function') return global.__ZPW_ON_LISTEN__({ host: HOST, port: PORT, version: APP_VERSION, logDir: LOG_DIR });
  console.log(`
╔══════════════════════════════════════════════════════════╗
║   Zscaler Policy Wizard GovCloud ${APP_VERSION}
║   GovCloud Edition - ZIA only, legacy ZIA API            ║
╠══════════════════════════════════════════════════════════╣
║  Server running at: http://${HOST}:${PORT}                  ║
║  Auth: legacy ZIA API (username, password, API key)      ║
║  Modules: URL | FW | SSL | Sandbox | DNS | FTC | CAC   ║
║  Frameworks: NIST 800-53 | NIST 800-171 | DOW Standard  ║
║  Logs: ./logs/                                          ║
║                                                          ║
║  Log files:                                              ║
║    HTTP requests: ./logs/zpw-http-YYYY-MM-DD.log         ║
║    Audit events:  ./logs/zpw-audit-YYYY-MM-DD.jsonl      ║
║    Errors:        ./logs/zpw-errors-YYYY-MM-DD.log       ║
╚══════════════════════════════════════════════════════════╝
  `);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[FATAL] Port ${PORT} is already in use. Another process is listening on it.`);
    console.error(`  Fix: Change ZPW_PORT or stop the other process.\n`);
  } else if (err.code === 'EACCES') {
    console.error(`\n[FATAL] Permission denied binding to ${HOST}:${PORT}.`);
    console.error(`  Fix: Use a port > 1024 or run as administrator.\n`);
  } else {
    console.error(`\n[FATAL] Server failed to start:`, err.message, '\n');
  }
  process.exit(1);
});

// Log uncaught exceptions so the process doesn't die silently
process.on('uncaughtException', (err) => {
  console.error(`[UNCAUGHT EXCEPTION] ${err.stack || err.message}`);
  const logFile = path.join(LOG_DIR, `zpw-errors-${new Date().toISOString().split('T')[0]}.log`);
  try { fs.appendFileSync(logFile, `[UNCAUGHT] ${err.stack || err.message}\n`); } catch(e) {}
});

process.on('unhandledRejection', (reason) => {
  console.error(`[UNHANDLED REJECTION] ${reason}`);
  const logFile = path.join(LOG_DIR, `zpw-errors-${new Date().toISOString().split('T')[0]}.log`);
  try { fs.appendFileSync(logFile, `[UNHANDLED_REJECTION] ${reason}\n`); } catch(e) {}
});

module.exports = app;
