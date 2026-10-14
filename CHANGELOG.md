# Changelog

## 1.0.0 — first GovCloud Edition release

- **ZIA only, legacy API only:** signs in with `POST /api/v1/authenticatedSession` (admin username, password, obfuscated API key). Reads `GovCloudAPI.txt` (or `APISpecial.txt`) next to the app.
- **Frameworks:** DOW Standard, NIST 800-53 Rev 5 and NIST 800-171 (Strict / Balanced / Permissive).
- **DOW Standard covers:**
  - URL Block / Allow / Isolate-everything-else, with the Isolate list rebuilt from the tenant.
  - ATP with country blocking.
  - IPS Command and Control.
  - Sandbox malware and ransomware.
  - Flash blocked.
  - SSL: exempt Health and Finance, then inspect everything else.
- **Rule control:** an on/off switch for every rule and ATP setting, plus Allow / Block overrides and a country list editor.
- **Cloud Browser Isolation:** uses the Default Isolation Profile, with a refresh to pick up new profiles. Isolate rules carry browser types.
- **SSL certificates:** an interception-certificate picker on Customize, and the SSL Certificate Manager for changing existing rules' certificates in bulk.
- **Portable frameworks:** save, load, and capture a tenant's policies.
- **Fixes from live testing:**
  - Rule names kept within 31 characters.
  - Deprecated firewall network applications removed.
  - SSL rules placed after Zscaler's predefined rules.
  - Sandbox file types and protocols named explicitly instead of `ANY`.
  - ATP feature-flag refusals reported as skipped.
- **Standalone app:** a Windows exe with a `--livecheck` read-only tenant check.
