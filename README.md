# Zscaler Policy Wizard — GovCloud Edition

**Coded by Steven Hajny, Distinguished Engineer**

Automates Zscaler Internet Access (ZIA) policy for government tenants using **only the legacy ZIA API** (`zsapi.<cloud>.net`, admin username + password + API key). The wizard applies the **DOW Standard**, **NIST 800-53 Rev 5** or **NIST 800-171** frameworks — or a framework you saved or captured from another tenant — and gives every rule and setting its own on/off switch.

It is a standalone Windows app: no Node.js, nothing to install. Credentials stay on the computer running it.

---

## Download and run

Download `ZscalerPolicyWizard-GovCloud-<version>-windows-x64.zip` from **[Releases](../../releases)**, unzip it and double-click `ZscalerPolicyWizard-GovCloud.exe`. Your browser opens the wizard on `http://127.0.0.1:3000` (or the next free port). Keep the console window open while you use it.

macOS builds (`macos-arm64` for Apple Silicon, `macos-x64` for Intel) are on the same release page.

The builds are not code-signed yet:
- **Windows:** if SmartScreen says *Windows protected your PC*, choose **More info → Run anyway**.
- **Mac:** right-click the app → **Open** → **Open**. If macOS still refuses, run `xattr -d com.apple.quarantine ZscalerPolicyWizard-GovCloud` in the unzipped folder.

**Credentials file (optional).** Put `GovCloudAPI.txt` next to the exe and the Connect page offers *Connect with this file*. The file needs four lines, as `name=value` or just the values (see [`credentials-example.txt`](credentials-example.txt)):

```
baseurl=https://zsapi.zscalergov.net
username=admin@agency.gov
password=...
apikey=<12-character API key>
```

`APISpecial.txt` is also recognised. The file is read only on this computer. It is never sent to the browser or written to the logs, and `.gitignore` keeps it out of git.

**Read-only tenant check.** `ZscalerPolicyWizard-GovCloud.exe --livecheck` signs in and reads categories, isolation profiles, IPS, ATP, URL and SSL rules, certificates and network applications. It runs a DOW dry run and writes `livecheck.json` next to the exe. Nothing in the tenant changes.

## What it does

### DOW Standard
| Area | What is applied |
|---|---|
| URL Filtering | **Block** and **Allow** lists from the DOW category sheet. **Every other category is isolated** in Cloud Browser Isolation; the Isolate list is rebuilt from the tenant's own categories at dry run, so newer categories are included. Sheet rows marked *custom* are matched to existing ZIA categories; unmatched rows fall into Isolate. |
| Cloud Browser Isolation | Uses the tenant's **Default Isolation Profile** unless you pick another; **↻ Refresh** picks up profiles created since the page loaded. Browser types are copied from an existing Isolate rule when there is one. |
| Advanced Threat Protection | P2P (BitTorrent, Tor), cryptomining, botnet, compromised host, phishing and spam blocked. **China, Russia, Iran, Iraq, Somalia and North Korea** are added to the countries the tenant already blocks; nothing is unblocked. |
| IPS | Block Command and Control (Botnet + Unknown C2). |
| Sandbox | Block Malware and Ransomware verdicts. File types are named explicitly, because tenants refuse `ANY`. |
| File Type Control | Block Flash. |
| SSL Inspection | **Do not inspect Health and Finance**, then **inspect everything else** (TLS 1.2 minimum), signed with the interception certificate you choose. Rules go directly after Zscaler's predefined rules. |

### Everything else
- **Toggles:** every rule in every policy area, and every ATP setting, can be switched on or off. Allow / Block can be overridden where the policy type allows it, and the blocked-country list is editable.
- **Portable frameworks:** *Save framework* writes a `.zpw-framework.json` with your toggles, choices, countries, isolation profile and certificate (stored by name). *Load* applies it to another tenant. *Capture this tenant's policies* reads URL Filtering (with custom categories), Cloud Firewall, IPS, SSL, Sandbox, DNS, File Type and ATP into a framework without changing anything.
- **SSL Certificate Manager:** lists every SSL rule and the certificate it signs with. Move selected Inspect rules off the Zscaler default certificate onto an imported intermediate CA, or back again, in one change, with a preview first.
- **Dry run before every apply:** shows the categories matched to the tenant, the isolation profile, IPS categories, firewall applications that are deprecated or missing, and every ATP field that will change. Rules that already exist by name are left alone. Rollback restores ATP exactly.
- **Tenant differences:** rule names are kept within ZIA's 31-character limit. Deprecated firewall applications are dropped, and a firewall rule left with no applications is skipped rather than created. If a Zscaler feature flag makes the tenant refuse ATP updates, ATP is reported as skipped, not failed.
- **Audit log:** every change is logged. Logs are written to `ZscalerPolicyWizard-GovCloud\logs` in your home folder.

### Not done through the API
- **Isolation profiles:** these are created in the Isolation portal; the ZIA API can only read them.
- **Malware Protection and Advanced Cloud Settings:** shown for review only.
- **Not captured into frameworks:** Cloud App Control and DLP rules (they point at tenant-specific apps, engines and dictionaries), and user / group / location scoping.

## Build from source

Needs Node 18+, python3 and zip.

```
npm ci
cd standalone && npm ci && cd ..
node standalone/build.js windows-x64     # -> standalone/release/ZscalerPolicyWizard-GovCloud-<version>-windows-x64.zip
npm run build:standalone                 # Windows + macOS (arm64, x64)
```

Running from source also works: `npm ci && npm start`, then open `http://localhost:3000`.

| Path | Purpose |
|---|---|
| `server/index.js` | Express server: legacy auth, dry run, apply, rollback, frameworks, SSL manager |
| `server/zia-client.js` | Legacy ZIA API client (session cookie, obfuscated key, paced calls) |
| `server/dow-standard.js` | DOW Standard sheet mapping |
| `server/templates.js` | NIST 800-53 / 800-171 templates, toggles, rule-name limits |
| `server/tenant-resolve.js` | Matches a policy set to the connected tenant before dry run / apply |
| `server/framework-io.js` | Framework save / load / tenant capture |
| `public/index.html` | The wizard UI (compiled ahead of time into the standalone build) |
| `standalone/` | Launcher, UI build and Bun compile scripts |

Environment variables: `ZPW_PORT`, `ZPW_HOST`, `ZPW_NO_BROWSER=1`, `ZPW_LOG_DIR`, `ZPW_CRED_FILE`.

## Version history

See [CHANGELOG.md](CHANGELOG.md).
