Zscaler Policy Wizard - GovCloud Edition (standalone)
=====================================================
Coded by Steven Hajny, Distinguished Engineer

ZIA only. Legacy ZIA API only (admin username, password and API key). No Node.js, nothing to install.

1. Put ZscalerPolicyWizard-GovCloud.exe in a folder of its own.
2. Optional: put GovCloudAPI.txt in the same folder with four lines (or name=value pairs):
       baseurl=https://zsapi.<cloud>.net
       username=admin@agency.gov
       password=...
       apikey=<12-character API key>
   (APISpecial.txt is also recognised.) The Connect page then offers "Connect with this file".
   The file is only read on this computer and is never sent to the browser or written to the logs.
3. Double-click ZscalerPolicyWizard-GovCloud.exe. If SmartScreen says "Windows protected your PC"
   (the build is not code-signed): More info -> Run anyway.
4. Your browser opens the wizard on http://127.0.0.1 (port 3000 or the next free one).
   Keep the console window open while you use it; close it to stop.

Read-only check of a tenant (changes nothing):  ZscalerPolicyWizard-GovCloud.exe --livecheck
  -> writes livecheck.json next to the exe.

Frameworks: DOW Standard, NIST 800-53, NIST 800-171, or a framework file you saved /
captured from another tenant. Every rule and ATP setting has an on/off switch.

Logs: ZscalerPolicyWizard-GovCloud\logs in your home folder.
Options (environment variables): ZPW_PORT=4000, ZPW_NO_BROWSER=1, ZPW_LOG_DIR=<folder>,
ZPW_CRED_FILE=<full path to a credentials file>.
