/**
 * DOW Standard framework.
 *
 * Source: the customer's DOW category sheet (Block / Allow / Isolate / IPS / ATP / Sandbox / File Type).
 * Category IDs come from Zscaler's published URL category list (display name -> enum). Rows marked
 * "custom" on the sheet are matched to existing ZIA categories (no custom categories are created);
 * rows with no ZIA equivalent are left out and therefore land in Isolate, because the rule is:
 *   every category that is not explicitly Blocked or Allowed is Isolated.
 * The Isolate list is resolved against the tenant's live category list at dry run / apply time, so
 * categories Zscaler adds later (for example the AI categories) are isolated automatically.
 */

// Published display name -> enum (Zscaler URL category list) for the names used on the sheet
const BLOCK = [
  { sheet: 'Pornography', ids: ['PORNOGRAPHY'] },
  { sheet: 'Adult Themes', ids: ['ADULT_THEMES'] },
  { sheet: 'Other Adult Material', ids: ['OTHER_ADULT_MATERIAL'] },
  { sheet: 'Nudity', ids: ['NUDITY'] },
  { sheet: 'Lingerie/Bikini', ids: ['LINGERIE_BIKINI'] },
  { sheet: 'Gambling', ids: ['GAMBLING'] },
  { sheet: 'Copyright Infringement', ids: ['COPYRIGHT_INFRINGEMENT'] },
  { sheet: 'Anonymizer', ids: ['ANONYMIZER'] },
  { sheet: 'Translators', ids: ['TRANSLATORS'] },
  { sheet: 'Militancy/Hate and Extremism', ids: ['MILITANCY_HATE_AND_EXTREMISM'] },
  { sheet: 'custom: State sponsors of terrorism', ids: ['MILITANCY_HATE_AND_EXTREMISM'], matched: 'No ZIA category for state sponsors; covered by Militancy/Hate and Extremism, and the ATP country block covers Iran, North Korea and the other listed countries' },
  { sheet: 'custom: Crypto Currency', ids: ['CRYPTOCURRENCY', 'CRYPTO_CURRENCY'], matched: 'Uses the tenant\'s Cryptocurrency category when it has one; otherwise it is isolated like other unlisted categories', optional: true },
  { sheet: 'Other Drugs', ids: ['DRUGS', 'OTHER_DRUGS'] },
  { sheet: 'Marijuana', ids: ['MARIJUANA'] },
  { sheet: 'Custom: Human Trafficking', ids: ['OTHER_ILLEGAL_OR_QUESTIONABLE'], matched: 'Matched to Other Illegal or Questionable' },
  { sheet: 'Custom: Academic Cheating', ids: [], matched: 'No ZIA equivalent — left to Isolate' },
  { sheet: 'Custom: Classified Leaks', ids: ['OTHER_ILLEGAL_OR_QUESTIONABLE'], matched: 'Matched to Other Illegal or Questionable' },
  { sheet: 'Violence', ids: ['VIOLENCE'] },
  { sheet: 'Tasteless', ids: ['TASTELESS'] },
  { sheet: 'Social Networking Adult', ids: ['SOCIAL_ADULT'] },
  { sheet: 'Spyware/Adware', ids: ['ADWARE_OR_SPYWARE'] }
];

const ALLOW = [
  { sheet: 'Social Issues', ids: ['SOCIAL_ISSUES'] },
  { sheet: 'Image Host', ids: ['IMAGE_HOST'] },
  { sheet: 'Safe Search Engine', ids: ['SAFE_SEARCH_ENGINE'] },
  { sheet: 'Web Search', ids: ['WEB_SEARCH'] },
  { sheet: 'Web Host', ids: ['WEB_HOST'] },
  { sheet: 'CDN', ids: ['CDN'] }
];

// Published category list (Zscaler, display name -> enum), used to show the Isolate list before a tenant
// is connected. The tenant's own list replaces it at dry run / apply.
const PUBLISHED_CATEGORIES = [
  ['ENTERTAINMENT', 'Entertainment'], ['MUSIC', 'Music and Audio Streaming'], ['OTHER_ENTERTAINMENT_AND_RECREATION', 'Other Entertainment/Recreation'],
  ['RADIO_STATIONS', 'Radio'], ['TELEVISION_AND_MOVIES', 'Television/Movies'], ['STREAMING_MEDIA', 'Video Streaming'], ['NEWS_AND_MEDIA', 'News and Media'],
  ['CLASSIFIEDS', 'Classifieds'], ['CORPORATE_MARKETING', 'Corporate Marketing'], ['FINANCE', 'Finance'], ['TRADING_BROKERAGE_INSURANCE', 'Online Trading, Brokerage, Insurance'],
  ['OTHER_BUSINESS_AND_ECONOMY', 'Other Business and Economy'], ['PROFESSIONAL_SERVICES', 'Professional Services'], ['CONTINUING_EDUCATION_COLLEGES', 'Continuing Education/Colleges'],
  ['HISTORY', 'History'], ['K_12', 'K-12'], ['OTHER_EDUCATION', 'Other Education'], ['REFERENCE_SITES', 'Reference Sites'], ['SCIENCE_AND_TECHNOLOGY', 'Science/Tech'],
  ['WEB_BANNERS', 'Advertising'], ['AI_ML_APPS', 'AI and ML Applications'], ['CDN', 'CDN'], ['DNS_OVER_HTTPS', 'DNS Over HTTPS Services'], ['FILE_HOST', 'File Host'],
  ['IMAGE_HOST', 'Image Host'], ['OSS_UPDATES', 'Operating System and Software Updates'], ['OTHER_INFORMATION_TECHNOLOGY', 'Other Information Technology'], ['PORTALS', 'Portals'],
  ['SAFE_SEARCH_ENGINE', 'Safe Search Engine'], ['SHAREWARE_DOWNLOAD', 'Shareware Download'], ['TRANSLATORS', 'Translators'], ['WEB_HOST', 'Web Host'], ['WEB_SEARCH', 'Web Search'],
  ['BLOG', 'Blogs'], ['DISCUSSION_FORUMS', 'Discussion Forums'], ['INTERNET_SERVICES', 'Internet Services'], ['ONLINE_CHAT', 'Online Chat'],
  ['OTHER_INTERNET_COMMUNICATION', 'Other Internet Communication'], ['P2P_COMMUNICATION', 'Peer-to-Peer Site'], ['REMOTE_ACCESS', 'Remote Access Tools'], ['WEB_CONFERENCING', 'Web Conferencing'],
  ['EMAIL_HOST', 'Webmail'], ['JOB_SEARCH', 'Job/Employment Search'], ['GOVERNMENT', 'Government'], ['MILITARY', 'Military'], ['OTHER_GOVERNMENT_AND_POLITICS', 'Other Government and Politics'],
  ['POLITICS', 'Politics'], ['MISCELLANEOUS_OR_UNKNOWN', 'Miscellaneous or Unknown'], ['NEWLY_REG_DOMAINS', 'Newly Registered and Observed Domains'], ['NON_CATEGORIZABLE', 'Non Categorizable'],
  ['OTHER_MISCELLANEOUS', 'Other Miscellaneous'], ['TRAVEL', 'Travel'], ['VEHICLES', 'Vehicles'], ['ADULT_SEX_EDUCATION', 'Adult Sex Education'], ['ADULT_THEMES', 'Adult Themes'],
  ['SEXUALITY', 'Body Art'], ['K_12_SEX_EDUCATION', 'K-12 Sex Education'], ['LINGERIE_BIKINI', 'Lingerie/Bikini'], ['NUDITY', 'Nudity'], ['OTHER_ADULT_MATERIAL', 'Other Adult Material'],
  ['PORNOGRAPHY', 'Pornography'], ['SOCIAL_ADULT', 'Social Networking Adult'], ['MARIJUANA', 'Marijuana'], ['DRUGS', 'Other Drugs'], ['GAMBLING', 'Gambling'], ['ANONYMIZER', 'Anonymizer'],
  ['COMPUTER_HACKING', 'Computer Hacking'], ['COPYRIGHT_INFRINGEMENT', 'Copyright Infringement'], ['MATURE_HUMOR', 'Mature Humor'], ['OTHER_ILLEGAL_OR_QUESTIONABLE', 'Other Illegal or Questionable'],
  ['PROFANITY', 'Profanity'], ['QUESTIONABLE', 'Questionable'], ['MILITANCY_HATE_AND_EXTREMISM', 'Militancy/Hate and Extremism'], ['TASTELESS', 'Tasteless'], ['VIOLENCE', 'Violence'],
  ['WEAPONS_AND_BOMBS', 'Weapons/Bombs'], ['OTHER_GAMES', 'Online and Other Games'], ['SOCIAL_NETWORKING_GAMES', 'Social Networking Games'], ['HEALTH', 'Health'],
  ['ALT_NEW_AGE', 'Alt/New Age'], ['CULT', 'Cult'], ['OTHER_RELIGION', 'Other Religion'], ['TRADITIONAL_RELIGION', 'Traditional Religion'], ['ONLINE_AUCTIONS', 'Online Auctions'],
  ['SPECIALIZED_SHOPPING', 'Online Shopping'], ['OTHER_SHOPPING_AND_AUCTIONS', 'Other Shopping and Auctions'], ['REAL_ESTATE', 'Real Estate'], ['FAMILY_ISSUES', 'Family Issues'],
  ['OTHER_SOCIAL_AND_FAMILY_ISSUES', 'Other Social and Family Issues'], ['SOCIAL_ISSUES', 'Social Issues'], ['ALCOHOL_TOBACCO', 'Alcohol/Tobacco'], ['ART_CULTURE', 'Art/Culture'],
  ['DINING_AND_RESTAURANT', 'Dining/Restaurant'], ['HOBBIES_AND_LEISURE', 'Hobbies/Leisure'], ['LIFESTYLE', 'Lifestyle'], ['OTHER_SOCIETY_AND_LIFESTYLE', 'Other Society and Lifestyle'],
  ['SOCIAL_NETWORKING', 'Social Networking'], ['SPECIAL_INTERESTS', 'Special Interests/Social Organizations'], ['SPORTS', 'Sports'], ['ENCR_WEB_CONTENT', 'Custom Encrypted Content'],
  ['DYNAMIC_DNS', 'Dynamic DNS Host'], ['NEWLY_REVIVED_DOMAINS', 'Newly Revived Domains'], ['OTHER_SECURITY', 'Other Security'], ['ADWARE_OR_SPYWARE', 'Spyware/Adware']
];
// Category IDs seen in live tenants that are newer than (or spelled differently from) the published list
const EXTRA_NAMES = { OTHER_DRUGS: 'Other Drugs', GENERAL_AI_ML: 'General AI and ML Applications', DEVELOPER_TOOLS: 'Developer Tools', INSURANCE: 'Insurance',
  FILE_CONVERTORS: 'File Converters', ALTERNATE_LIFESTYLE: 'Alternate Lifestyle', TRADING_BROKARAGE_INSURANCE: 'Online Trading and Brokerage',
  CRYPTOCURRENCY: 'Cryptocurrency' };
const CATEGORY_NAME = { ...Object.fromEntries(PUBLISHED_CATEGORIES), ...EXTRA_NAMES };

// Never part of "everything else": ATP-only and SSL-only (Office 365) categories, placeholders
const NOT_ISOLATABLE_IDS = new Set(['ANY', 'NONE', 'USER_DEFINED', 'ZSPROXY_IPS', 'OTHER_ADULT_MATERIAL_DEPRECATED']);
const NOT_ISOLATABLE_SUPER = new Set(['ADVANCED_SECURITY', 'OFFICE_365', 'GLOBAL_INT_OFC365', 'USER_DEFINED']);
const isOffice365 = (id) => /^GLOBAL_INT_OFC365/.test(id);

const BLOCKED_COUNTRIES = [
  { code: 'COUNTRY_CN', name: 'China' }, { code: 'COUNTRY_RU', name: 'Russia' }, { code: 'COUNTRY_IR', name: 'Iran' },
  { code: 'COUNTRY_IQ', name: 'Iraq' }, { code: 'COUNTRY_SO', name: 'Somalia' }, { code: 'COUNTRY_KP', name: 'North Korea' }
];

// ATP column of the sheet -> /cyberThreatProtection/advancedThreatSettings fields
const ATP_SETTINGS = [
  { key: 'bitTorrentBlocked', sheet: 'P2P', label: 'Block BitTorrent (P2P)', group: 'P2P' },
  { key: 'torBlocked', sheet: 'P2P', label: 'Block Tor (P2P anonymizer)', group: 'P2P' },
  { key: 'cryptoMiningBlocked', sheet: 'Cryptocurrency Mining', label: 'Block cryptomining', group: 'Cryptocurrency Mining' },
  { key: 'cmdCtlServerBlocked', sheet: 'Botnet', label: 'Block connections to known Command & Control servers', group: 'Botnet' },
  { key: 'cmdCtlTrafficBlocked', sheet: 'Botnet', label: 'Block botnet Command & Control traffic to unknown servers', group: 'Botnet' },
  { key: 'malwareSitesBlocked', sheet: 'Compromised Host', label: 'Block known malicious / compromised sites and content', group: 'Compromised Host' },
  { key: 'browserExploitsBlocked', sheet: 'Compromised Host', label: 'Block known browser exploits', group: 'Compromised Host' },
  { key: 'fileFormatVunerabilitesBlocked', sheet: 'Compromised Host', label: 'Block file format vulnerabilities (Office / PDF)', group: 'Compromised Host' },
  { key: 'activeXBlocked', sheet: 'Compromised Host', label: 'Block vulnerable ActiveX controls', group: 'Compromised Host' },
  { key: 'knownPhishingSitesBlocked', sheet: 'Phishing', label: 'Block known phishing sites', group: 'Phishing' },
  { key: 'suspectedPhishingSitesBlocked', sheet: 'Phishing', label: 'Block suspected phishing sites (heuristics)', group: 'Phishing' },
  { key: 'webspamBlocked', sheet: 'Spam', label: 'Block web spam', group: 'Spam' }
];

/**
 * Resolve the three URL rules' categories against the tenant's category list
 * (GET /urlCategories). Without a tenant list, the published list is used.
 */
function resolveDowCategories(tenantCategories = null) {
  const known = tenantCategories
    ? tenantCategories.filter(c => c && c.id && !c.customCategory)
    : PUBLISHED_CATEGORIES.map(([id]) => ({ id, superCategory: null }));
  const has = new Set(known.map(c => c.id));
  const pick = (rows) => {
    const ids = [], notes = [], missing = [];
    for (const r of rows) {
      const hit = r.ids.find(id => has.has(id));
      if (hit) ids.push(hit);
      else if (r.ids.length) (r.optional ? notes : missing).push(`${r.sheet} (${r.ids.join(' / ')})`);
    }
    return { ids: [...new Set(ids)], missing, notes };
  };
  const block = pick(BLOCK), allow = pick(ALLOW);
  const listed = new Set([...block.ids, ...allow.ids]);
  const isolate = known
    .filter(c => !listed.has(c.id) && !NOT_ISOLATABLE_IDS.has(c.id) && !NOT_ISOLATABLE_SUPER.has(c.superCategory) && !isOffice365(c.id) && !c.deprecated)
    .map(c => c.id);
  return {
    block: block.ids, allow: allow.ids, isolate,
    missing: [...block.missing, ...allow.missing],
    notes: [...block.notes],
    source: tenantCategories ? 'tenant' : 'published list'
  };
}

// SSL privacy exemptions (do not inspect). Matched against the tenant's categories at dry run.
const SSL_EXEMPT_CATEGORIES = ['HEALTH', 'FINANCE'];

function generateDowPolicies(prefix = 'GOV') {
  const cats = resolveDowCategories(null);
  const urlFiltering = [
    {
      name: `${prefix}-DOW-Block`, order: 1, state: 'ENABLED', action: 'BLOCK', protocols: ['ANY_RULE'],
      urlCategories: cats.block, dowList: 'block',
      description: 'DOW Standard: categories the DOW sheet marks Block.', tier: 'DOW_STANDARD'
    },
    {
      name: `${prefix}-DOW-Allow`, order: 2, state: 'ENABLED', action: 'ALLOW', protocols: ['ANY_RULE'],
      urlCategories: cats.allow, dowList: 'allow',
      description: 'DOW Standard: categories the DOW sheet marks Allow.', tier: 'DOW_STANDARD'
    },
    {
      name: `${prefix}-DOW-Isolate`, order: 3, state: 'ENABLED', action: 'ISOLATE', protocols: ['HTTPS_RULE', 'HTTP_RULE'],
      urlCategories: cats.isolate, dowList: 'isolate', isolateAllOthers: true, cbiProfileName: null,
      description: 'DOW Standard: every other URL category opens in Cloud Browser Isolation (list is rebuilt from the tenant at dry run).',
      tier: 'DOW_STANDARD'
    }
  ];
  const advancedThreatProtection = {
    name: `${prefix}-DOW-ATP`,
    settings: Object.fromEntries(ATP_SETTINGS.map(s => [s.key, true])),
    settingMeta: ATP_SETTINGS,
    blockedCountries: BLOCKED_COUNTRIES.map(c => c.code),
    description: 'DOW Standard ATP: P2P, cryptomining, botnet, compromised host, phishing and spam blocked; block traffic to China, Russia, Iran, Iraq, Somalia and North Korea.'
  };
  const ipsControl = [{
    name: `${prefix}-DOW-IPS-Block-C2`, order: 1, state: 'ENABLED', action: 'BLOCK_DROP',
    // IPS threat categories are enums in the API (seen live): BOTNET = known C2, UNKNOWN_COMMAND_AND_CONTROL = unknown / suspicious C2
    threatCategoryMatches: ['BOTNET', 'UNKNOWN_COMMAND_AND_CONTROL'], threatCategoryMatch: 'command and control',
    threatCategoryLabel: 'Command and Control (Botnet + Unknown C2)',
    description: 'DOW Standard IPS: block Command and Control threat signatures.', tier: 'DOW_STANDARD'
  }];
  const sandbox = [{
    name: `${prefix}-DOW-Sandbox-Block`, order: 1, state: 'ENABLED',
    baRuleAction: 'BLOCK', baPolicyCategories: ['BOTMAL_BLOCK', 'RANSOMWARE_BLOCK'], fileTypes: ['ANY'], protocols: ['ANY_RULE'],
    firstTimeEnable: false, mlActionEnabled: false,
    description: 'DOW Standard Sandbox: block files with a Malware (botnet / malware) or Ransomware verdict.', tier: 'DOW_STANDARD'
  }];
  const fileTypeControl = [{
    name: `${prefix}-DOW-Block-Flash`, order: 1, state: 'ENABLED', filteringAction: 'BLOCK',
    fileTypes: ['FTCATEGORY_FLASH'], operation: 'UPLOAD_DOWNLOAD', protocols: ['ANY_RULE'],
    description: 'DOW Standard File Type Control: block Adobe Flash uploads and downloads.', tier: 'DOW_STANDARD'
  }];
  // Usual privacy exemptions first (Health, Finance), then inspect everything else
  const sslInspection = [{
    name: `${prefix}-DOW-SSL-Exempt-Hlth-Fin`, order: 1, state: 'ENABLED', action: 'DO_NOT_DECRYPT',
    urlCategories: SSL_EXEMPT_CATEGORIES.slice(), sslExempt: true,
    description: 'DOW Standard: do not inspect Health and Finance sites (privacy exemption).', tier: 'DOW_STANDARD'
  }, {
    name: `${prefix}-DOW-SSL-Inspect-All`, order: 2, state: 'ENABLED', action: 'DECRYPT', urlCategories: ['ANY'],
    minClientTLS: 'CLIENT_TLS_1_2', minServerTLS: 'SERVER_TLS_1_2',
    description: 'DOW Standard: inspect all SSL/TLS traffic (TLS 1.2 minimum, undecryptable traffic blocked). Zscaler\'s predefined exemption rules still apply first.',
    tier: 'DOW_STANDARD'
  }];
  return { urlFiltering, advancedThreatProtection, ipsControl, sandbox, fileTypeControl, sslInspection };
}

function dowCatalog() {
  const cats = resolveDowCategories(null);
  const nm = (id) => CATEGORY_NAME[id] || id;
  return {
    block: BLOCK.map(r => ({ sheet: r.sheet, ids: r.ids, names: r.ids.map(nm), note: r.matched || null })),
    allow: ALLOW.map(r => ({ sheet: r.sheet, ids: r.ids, names: r.ids.map(nm) })),
    isolate: cats.isolate.map(id => ({ id, name: nm(id) })),
    atp: ATP_SETTINGS, countries: BLOCKED_COUNTRIES,
    ips: [{ sheet: 'Command and Control', action: 'Block (drop)' }],
    sandbox: [{ sheet: 'Malware; Ransomware', categories: ['BOTMAL_BLOCK', 'RANSOMWARE_BLOCK'] }],
    fileType: [{ sheet: 'Flash', fileTypes: ['FTCATEGORY_FLASH'], action: 'Block' }],
    ssl: [{ rule: 'Exempt (do not inspect)', categories: SSL_EXEMPT_CATEGORIES.map(nm) }, { rule: 'Inspect', categories: ['All other traffic (TLS 1.2 minimum)'] }]
  };
}

module.exports = { SSL_EXEMPT_CATEGORIES, BLOCK, ALLOW, PUBLISHED_CATEGORIES, CATEGORY_NAME, BLOCKED_COUNTRIES, ATP_SETTINGS, resolveDowCategories, generateDowPolicies, dowCatalog };
