/**
 * Zscaler Policy Wizard GovCloud Edition — standalone launcher.
 * Coded by Steven Hajny, Distinguished Engineer.
 * Starts the wizard on 127.0.0.1 (this computer only), opens the default browser,
 * and keeps running until the window is closed or Ctrl+C is pressed.
 */
const net = require('net');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

// The compiled UI is embedded in the executable
global.__ZPW_EMBEDDED_HTML__ = require('./dist/ui-bundle.js');

function freePort(start = 3000, end = 3020) {
  return new Promise((resolve) => {
    const tryPort = (p) => {
      const s = net.createServer();
      s.once('error', () => (p < end ? tryPort(p + 1) : resolve(0)));
      s.once('listening', () => s.close(() => resolve(p)));
      s.listen(p, '127.0.0.1');
    };
    tryPort(start);
  });
}

function openBrowser(url) {
  const done = (err) => { if (err) console.log(`  Could not open a browser automatically. Open ${url} yourself.`); };
  if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '', url], { windowsHide: true }, done);
  else if (process.platform === 'darwin') execFile('open', [url], done);
  else execFile('xdg-open', [url], done);
}

// --livecheck: READ-ONLY test of the legacy ZIA API with the credentials file next to the exe.
// Signs in, reads what the DOW Standard needs, runs the dry-run matching and a capture, signs out.
// Writes livecheck.json next to the exe. Never creates, changes or deletes anything; never writes secrets.
async function liveCheck() {
  const fs = require('fs');
  const { findCredentialFile, readCredentialFile } = require('../server/cred-file.js');
  const { ZIAClient } = require('../server/zia-client.js');
  const { generateFullTemplate } = require('../server/templates.js');
  const { resolveForTenant } = require('../server/tenant-resolve.js');
  const { captureFromTenant } = require('../server/framework-io.js');
  const { resolveDowCategories } = require('../server/dow-standard.js');
  const out = { time: new Date().toISOString(), version: require('../package.json').version, steps: {} };
  const outFile = path.join(path.dirname(process.execPath), 'livecheck.json');
  const save = () => fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  const step = async (name, fn) => {
    const t = Date.now();
    try { out.steps[name] = { ok: true, value: await fn() }; }
    catch (e) { out.steps[name] = { ok: false, error: String(e.message || e).replace(/"password"\s*:\s*"[^"]*"/g, '"password":"***"').substring(0, 800) }; }
    out.steps[name].ms = Date.now() - t; save();
    console.log(`  ${out.steps[name].ok ? 'OK  ' : 'FAIL'} ${name}`);
    return out.steps[name];
  };
  const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
  console.log('\n  Zscaler Policy Wizard GovCloud Edition - live check (read-only)\n');
  const f = findCredentialFile();
  out.credentialFile = f;
  if (!f) { out.error = 'No GovCloudAPI.txt (or APISpecial.txt) next to the exe'; save(); console.log('  ' + out.error); return; }
  let creds;
  try { creds = readCredentialFile(f); } catch (e) { out.error = e.message; save(); console.log('  ' + e.message); return; }
  out.credentialsFound = { baseUrl: creds.baseUrl || null, username: !!creds.username, password: !!creds.password, apiKey: creds.apiKey ? creds.apiKey.length + ' chars' : false };
  if (!creds.baseUrl || !creds.username || !creds.password || !creds.apiKey) {
    out.error = 'The legacy API needs the base URL, admin username, password and API key in the credentials file'; save(); console.log('  ' + out.error); return;
  }
  const client = new ZIAClient();
  const login = await step('1-login', async () => { const r = await client.authenticateLegacy({ username: creds.username, password: creds.password, apiKey: creds.apiKey, cloud: creds.baseUrl }); return { host: client.baseUrl, authType: r.authType }; });
  if (!login.ok) return;
  try {
    await step('2-urlCategories', async () => {
      const cats = list(await client.getUrlCategories());
      const res = resolveDowCategories(cats);
      return { total: cats.length, custom: cats.filter(c => c.customCategory).length,
        sampleKeys: cats[0] ? Object.keys(cats[0]) : [], superCategories: [...new Set(cats.map(c => c.superCategory))].slice(0, 60),
        dow: { block: res.block, allow: res.allow, isolateCount: res.isolate.length, missing: res.missing, notes: res.notes },
        notInPublishedList: cats.filter(c => !c.customCategory).map(c => c.id).filter(id => !require('../server/dow-standard.js').CATEGORY_NAME[id]) };
    });
    await step('3-isolationProfiles', async () => {
      const r = {};
      for (const p of ['/api/v1/browserIsolation/profiles', '/api/v1/browserIsolationProfile']) {
        try { const v = await client.apiCall('GET', p); r[p] = { ok: true, count: list(v).length, profiles: list(v).map(x => ({ id: x.id, name: x.name, hasUrl: !!x.url, defaultProfile: !!x.defaultProfile, keys: Object.keys(x) })) }; }
        catch (e) { r[p] = { ok: false, error: e.message.substring(0, 300) }; }
      }
      return r;
    });
    await step('4-ipsRules', async () => {
      const rules = list(await client.getIpsRules());
      const cats = new Map();
      for (const r of rules) for (const t of (r.threatCategories || [])) cats.set(String(t.id), t.name);
      return { count: rules.length, rules: rules.map(r => ({ name: r.name, action: r.action, order: r.order, defaultRule: !!r.defaultRule, predefined: !!r.predefined, threatCategories: (r.threatCategories || []).length })),
        threatCategories: [...cats].map(([id, name]) => ({ id, name })), sampleKeys: rules[0] ? Object.keys(rules[0]) : [] };
    });
    await step('5-atpSettings', async () => {
      const a = await client.getAtpSettings();
      return { keys: Object.keys(a || {}), blockedCountries: (a && a.blockedCountries) || [], blockedFlags: Object.fromEntries(Object.entries(a || {}).filter(([k, v]) => typeof v === 'boolean' && /Blocked$/.test(k))) };
    });
    await step('6-urlRules', async () => {
      const rules = list(await client.getUrlFilteringRules());
      const iso = rules.find(r => r.action === 'ISOLATE');
      return { count: rules.length, names: rules.map(r => `${r.order}. ${r.name} [${r.action}]`), existingIsolateRule: iso ? { protocols: iso.protocols, cbiProfileKeys: iso.cbiProfile ? Object.keys(iso.cbiProfile) : null, requestMethods: iso.requestMethods } : null };
    });
    await step('7-dowDryRunMatching', async () => {
      const t = generateFullTemplate({ complianceFramework: 'DOW_STANDARD', prefix: 'GOV' });
      const r = await resolveForTenant(client, t, {});
      return { errors: r.errors, warnings: r.warnings, info: { ...r.info, categories: r.info.categories ? { ...r.info.categories, isolateNames: undefined } : null } };
    });
    await step('8-captureReadOnly', async () => {
      const c = await captureFromTenant(client, { name: 'livecheck', host: client.baseUrl });
      return { counts: Object.fromEntries(Object.entries(c.baseTemplate.policies).map(([k, v]) => [k, Array.isArray(v) ? v.length : 1])), customCategories: c.baseTemplate.customCategories.length, notes: c.notes, skipped: c.skipped };
    });
    await step('10-sslRulesAndCerts', async () => {
      const r = {};
      try {
        const rules = list(await client.getSslInspectionRules());
        r.sslRules = rules.map(x => ({ name: x.name, order: x.order, predefined: !!x.predefined, defaultRule: !!x.defaultRule, state: x.state, action: x.action, urlCategories: (x.urlCategories || []).length, keys: Object.keys(x) }));
      } catch (e) { r.sslRulesError = e.message.substring(0, 300); }
      for (const p of ['/api/v1/intermediateCaCertificate/readyToUse', '/api/v1/intermediateCaCertificate', '/api/v1/intermediateCaCertificate/lite']) {
        try {
          const v = await client.apiCall('GET', p);
          const arr = list(v);
          r[p] = Array.isArray(v) ? { count: arr.length, items: arr.map(c => ({ id: c.id, name: c.name, type: c.type, status: c.status, defaultCertificate: c.defaultCertificate, currentState: c.currentState, keys: Object.keys(c) })) } : { object: v };
        } catch (e) { r[p] = { error: e.message.substring(0, 300) }; }
      }
      try {
        const apps = list(await client.getNetworkApplications());
        r.networkApplications = { count: apps.length, deprecated: apps.filter(a => a.deprecated).map(a => a.id).slice(0, 200) };
      } catch (e) { r.networkApplications = { error: e.message.substring(0, 300) }; }
      try {
        const iso = list(await client.getUrlFilteringRules()).filter(x => x.action === 'ISOLATE');
        r.isolateUserAgents = iso.map(x => ({ name: x.name, userAgentTypes: x.userAgentTypes || null }));
      } catch (e) { r.isolateUserAgents = { error: e.message.substring(0, 300) }; }
      return r;
    });
  } finally {
    await step('9-logout', async () => { await client.logout(); return 'signed out'; });
  }
}

(async () => {
  if (process.argv.includes('--livecheck')) { await liveCheck(); console.log(`\n  Report: ${path.join(path.dirname(process.execPath), 'livecheck.json')}\n`); process.exit(0); }
  const port = Number(process.env.ZPW_PORT) || await freePort();
  process.env.ZPW_HOST = process.env.ZPW_HOST || '127.0.0.1';
  process.env.ZPW_PORT = String(port);
  process.env.ZPW_LOG_DIR = process.env.ZPW_LOG_DIR || path.join(os.homedir(), 'ZscalerPolicyWizard-GovCloud', 'logs');
  // The credentials file (GovCloudAPI.txt or APISpecial.txt) is looked for next to the executable
  process.env.ZPW_APP_DIR = process.env.ZPW_APP_DIR || path.dirname(process.execPath);

  global.__ZPW_ON_LISTEN__ = ({ host, port, version, logDir }) => {
    const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
    console.log('');
    console.log(`  Zscaler Policy Wizard GovCloud Edition ${version} (legacy ZIA API)`);
    console.log('  Coded by Steven Hajny, Distinguished Engineer');
    console.log(`  Running at ${url}  (this computer only)`);
    console.log(`  Logs: ${logDir}`);
    console.log('');
    console.log('  Keep this window open while you use the wizard.');
    console.log('  Close it (or press Ctrl+C) to stop.');
    console.log('');
    if (!process.env.ZPW_NO_BROWSER) openBrowser(url);
  };

  require('../server/index.js');
})();
