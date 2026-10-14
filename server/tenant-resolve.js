/**
 * Resolve a policy set against the connected tenant before dry run / apply.
 *  - DOW URL rules: Block / Allow lists keep only categories this tenant has; the Isolate rule is
 *    rebuilt as "every predefined category not Blocked or Allowed" from GET /urlCategories.
 *  - ISOLATE rules: attach the chosen Cloud Browser Isolation profile (profiles can only be created
 *    in the Isolation portal; the ZIA API reads them).
 *  - IPS rules: look up the "Command and Control" threat category ID from the tenant's IPS rules.
 * Returns { template, info, warnings, errors } and never changes the tenant.
 */
const { resolveDowCategories, CATEGORY_NAME } = require('./dow-standard');

// Browsers an Isolate rule applies to (ZIA requires user agents with the Isolate action)
const ISOLATE_USER_AGENTS = ['OPERA', 'FIREFOX', 'MSIE', 'MSEDGE', 'CHROME', 'SAFARI', 'MSCHREDGE'];

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

async function resolveForTenant(client, templateIn, { cbiProfile = null } = {}) {
  const template = JSON.parse(JSON.stringify(templateIn));
  const warnings = [], errors = [];
  const info = { categories: null, cbi: null, ips: null };
  const url = template.policies.urlFiltering || [];

  // ---- URL categories (DOW lists, SSL exemptions)
  let tenantCats = null;
  const ssl = template.policies.sslInspection || [];
  if (url.some(r => r.dowList) || ssl.some(r => r.sslExempt)) {
    try { tenantCats = list(await client.getUrlCategories()); } catch (e) { tenantCats = null; }
  }
  for (const r of ssl.filter(x => x.sslExempt)) {
    if (!tenantCats || !tenantCats.length) continue;
    const have = new Set(tenantCats.map(c => c.id));
    const missing = r.urlCategories.filter(c => !have.has(c));
    r.urlCategories = r.urlCategories.filter(c => have.has(c));
    if (missing.length) warnings.push(`${r.name}: categories not in this tenant, left out: ${missing.join(', ')}`);
  }
  if (url.some(r => r.dowList)) {
    let cats = tenantCats;
    try { if (!cats) cats = list(await client.getUrlCategories()); }
    catch (e) { warnings.push(`Could not read the tenant's URL categories (${e.message}); using Zscaler's published list for Block / Allow / Isolate.`); }
    const res = resolveDowCategories(cats && cats.length ? cats : null);
    for (const r of url) {
      if (r.dowList === 'block') r.urlCategories = res.block;
      if (r.dowList === 'allow') r.urlCategories = res.allow;
      if (r.dowList === 'isolate') r.urlCategories = res.isolate;
    }
    // A DOW Block / Allow rule the user switched off must not drop its categories into Isolate
    const hasBlock = url.some(r => r.dowList === 'block'), hasAllow = url.some(r => r.dowList === 'allow');
    const iso = url.find(r => r.dowList === 'isolate');
    if (iso && (!hasBlock || !hasAllow)) {
      const keepOut = new Set([...(!hasBlock ? res.block : []), ...(!hasAllow ? res.allow : [])]);
      iso.urlCategories = iso.urlCategories.filter(c => !keepOut.has(c));
      warnings.push(`${!hasBlock ? 'Block' : 'Allow'} rule is off: its categories are left out of Isolate too (they fall through to the tenant's other rules).`);
    }
    for (const m of res.missing) warnings.push(`Category not in this tenant, skipped: ${m}`);
    for (const n of res.notes) warnings.push(`Not in this tenant: ${n}`);
    info.categories = { source: res.source, block: res.block.length, allow: res.allow.length, isolate: res.isolate.length,
      isolateNames: res.isolate.map(id => CATEGORY_NAME[id] || id) };
  }

  // ---- Isolation profile
  const isolateRules = url.filter(r => r.action === 'ISOLATE');
  if (isolateRules.length) {
    let profiles = [];
    try { profiles = list(await client.getCbiProfiles()); }
    catch (e) { errors.push(`Could not read Cloud Browser Isolation profiles: ${e.message}`); }
    const want = (cbiProfile && (cbiProfile.id || cbiProfile.name)) ? cbiProfile : (isolateRules[0].cbiProfile || null);
    let chosen = null;
    if (want) chosen = profiles.find(p => String(p.id) === String(want.id)) || profiles.find(p => p.name === want.name) || null;
    if (!chosen && !want && profiles.length) {
      chosen = profiles.find(p => p.defaultProfile) || profiles[0];
      warnings.push(`No isolation profile chosen — using "${chosen.name}"${chosen.defaultProfile ? ' (the default profile)' : ''}.`);
    }
    if (!profiles.length && !errors.length) errors.push('This tenant has no Cloud Browser Isolation profile. Create one in the Isolation admin portal (the ZIA API can only read profiles), then run the dry run again.');
    else if (want && !chosen) errors.push(`Isolation profile "${want.name}" was not found in this tenant.`);
    // User agents: copy them from an Isolate rule the tenant already has, else every supported browser
    let agents = null;
    try {
      const existingIso = list(await client.getUrlFilteringRules()).find(r => r.action === 'ISOLATE' && Array.isArray(r.userAgentTypes) && r.userAgentTypes.length);
      if (existingIso) agents = existingIso.userAgentTypes.slice();
    } catch (e) { /* default list */ }
    for (const r of isolateRules) if (!r.userAgentTypes || !r.userAgentTypes.length) r.userAgentTypes = agents || ISOLATE_USER_AGENTS.slice();
    if (chosen) {
      const cbi = { id: chosen.id, name: chosen.name, url: chosen.url, ...(chosen.profileSeq !== undefined ? { profileSeq: chosen.profileSeq } : {}) };
      for (const r of isolateRules) r.cbiProfile = cbi;
      info.cbi = { ...cbi, defaultProfile: !!chosen.defaultProfile, available: profiles.map(p => ({ id: p.id, name: p.name, url: p.url, defaultProfile: !!p.defaultProfile })) };
    } else info.cbi = { available: profiles.map(p => ({ id: p.id, name: p.name, url: p.url, defaultProfile: !!p.defaultProfile })) };
  }

  // ---- IPS threat categories
  const ips = template.policies.ipsControl || [];
  if (ips.length) {
    let existing = [];
    try { existing = list(await client.getIpsRules()); }
    catch (e) { errors.push(`Could not read IPS Control rules (${e.message}). IPS Control needs the Cloud Firewall IPS subscription and API access.`); }
    const seen = new Map();
    for (const r of existing) for (const t of (r.threatCategories || [])) if (t && t.id !== undefined) seen.set(String(t.id), t);
    info.ips = { knownCategories: [...seen.values()].map(t => ({ id: t.id, name: t.name })) };
    for (const r of ips) {
      if (r.threatCategories && r.threatCategories.length) continue;
      const norm = (x) => String(x || '').toLowerCase().replace(/&/g, ' and ').replace(/[^a-z0-9]/g, '');
      const all = [...seen.values()];
      // exact enum names first (e.g. BOTNET + UNKNOWN_COMMAND_AND_CONTROL), then a loose name match
      let hits = (r.threatCategoryMatches || []).map(m => all.find(t => norm(t.name) === norm(m))).filter(Boolean);
      if (!hits.length) {
        const want = norm(r.threatCategoryMatch);
        const loose = want ? all.find(t => norm(t.name) === want || norm(t.name).includes(want)) : null;
        if (loose) hits = [loose];
      }
      const missingNames = (r.threatCategoryMatches || []).filter(m => !all.some(t => norm(t.name) === norm(m)));
      if (hits.length && missingNames.length) warnings.push(`${r.name}: threat categories not found in this tenant: ${missingNames.join(', ')}`);
      const hit = hits[0];
      if (hit) { r.threatCategories = hits.map(t => ({ id: t.id, name: t.name })); info.ips.resolved = { id: hits.map(t => t.id).join(', '), name: hits.map(t => t.name).join(' + ') }; }
      else if (r.capturedThreatCategories && r.capturedThreatCategories.length) {
        r.threatCategories = r.capturedThreatCategories;
        warnings.push(`${r.name}: threat category "${r.threatCategoryLabel}" not seen in this tenant's IPS rules; using the ID captured from the source tenant.`);
      }
      else if (!errors.length) errors.push(`Could not find the "${r.threatCategoryLabel}" IPS threat category in this tenant's IPS rules. Turn the IPS rule off, or add the category to any IPS rule in the portal once so the API can see its ID.`);
    }
  }
  // ---- Cloud Firewall network applications: ZIA refuses deprecated or unknown ones
  const fw = template.policies.firewallFiltering || [];
  if (fw.some(r => Array.isArray(r.nwApplications) && r.nwApplications.length)) {
    let apps = null;
    try { apps = list(await client.getNetworkApplications()); }
    catch (e) { warnings.push(`Could not read the tenant's network applications (${e.message}); firewall rules are sent as written.`); }
    if (apps && apps.length) {
      const ok = new Set(apps.filter(a => !a.deprecated).map(a => a.id));
      const dep = new Set(apps.filter(a => a.deprecated).map(a => a.id));
      info.firewallApps = { checked: apps.length, deprecated: dep.size };
      template.policies.firewallFiltering = fw.filter(r => {
        if (!Array.isArray(r.nwApplications) || !r.nwApplications.length) return true;
        const keep = r.nwApplications.filter(a => ok.has(a));
        const gone = r.nwApplications.filter(a => !ok.has(a));
        if (gone.length) warnings.push(`${r.name}: left out ${gone.map(a => `${a}${dep.has(a) ? ' (deprecated)' : ' (not in this tenant)'}`).join(', ')}`);
        r.nwApplications = keep;
        if (!keep.length) {
          // A firewall rule with no applications would match ALL traffic — never create it
          warnings.push(`${r.name}: none of its network applications are usable in this tenant — rule skipped.`);
          return false;
        }
        return true;
      });
      if (!template.policies.firewallFiltering.length) delete template.policies.firewallFiltering;
    }
  }
  return { template, info, warnings, errors };
}

module.exports = { resolveForTenant };
