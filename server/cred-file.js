/**
 * Credentials file for the legacy ZIA API.
 *
 * Looks next to the app (and in the current folder) for GovCloudAPI.txt (or APISpecial.txt), or any *.txt whose name
 * contains "api". Accepted formats, one value per line:
 *   labelled:   baseurl=https://zsapi.zscalertwo.net   (also base url:, url:, cloud:)
 *               username=admin@example.com             (also user:, admin:, login:)
 *               password=...                           (also pass:, pwd:)
 *               apikey=AbCdEf123456                    (also api key:, key:)
 *   unlabelled: lines are recognised by shape — the URL/host, the address with @ (username),
 *               a 12+ character letters-and-digits key, and the remaining line as the password.
 * Values are only ever used on this computer to sign in; they are never sent to the browser or logged.
 */
const fs = require('fs');
const path = require('path');

function candidateDirs() {
  const dirs = [];
  if (process.env.ZPW_APP_DIR) dirs.push(process.env.ZPW_APP_DIR);
  dirs.push(path.dirname(process.execPath), process.cwd());
  return [...new Set(dirs)];
}

function findCredentialFile() {
  if (process.env.ZPW_CRED_FILE && fs.existsSync(process.env.ZPW_CRED_FILE)) return process.env.ZPW_CRED_FILE;
  for (const d of candidateDirs()) {
    let names = [];
    try { names = fs.readdirSync(d); } catch (e) { continue; }
    const exact = names.find(n => n.toLowerCase() === 'govcloudapi.txt') || names.find(n => n.toLowerCase() === 'apispecial.txt');
    const loose = names.find(n => /api/i.test(n) && /\.txt$/i.test(n));
    const pick = exact || loose;
    if (pick) return path.join(d, pick);
  }
  return null;
}

// Labels are matched loosely: "API BASE URL", "Base URL", "url", "API Key", "Admin user", "Password", ...
const LABELS = [
  ['apiKey', /\bkey\b|apikey/i],
  ['baseUrl', /url|host|cloud|base/i],
  ['password', /pass|pwd/i],
  ['username', /user|admin|login|e-?mail/i]
];

function normaliseBaseUrl(v) {
  return String(v || '').trim().replace(/^["']|["']$/g, '');
}

function parseCredentials(text) {
  const out = {};
  const loose = [];
  for (const raw of String(text).replace(/^﻿/, '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^([A-Za-z][A-Za-z _\-]{1,30}?)\s*[:=]\s*(.+)$/);
    const label = m && LABELS.find(([, re]) => re.test(m[1].trim()));
    if (label && !(label[0] === 'baseUrl' && /^https?$/i.test(m[1].trim()))) { out[label[0]] = m[2].trim().replace(/^["']|["']$/g, ''); continue; }
    loose.push(line);
  }
  for (const v of loose) {
    if (!out.baseUrl && /^(https?:\/\/)?[a-z0-9.-]+\.(net|com)(\/.*)?$/i.test(v)) { out.baseUrl = v; continue; }
    if (!out.username && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) { out.username = v; continue; }
    if (!out.apiKey && /^[A-Za-z0-9]{12}$/.test(v)) { out.apiKey = v; continue; }
    if (!out.password) { out.password = v; continue; }
  }
  if (out.baseUrl) out.baseUrl = normaliseBaseUrl(out.baseUrl);
  return out;
}

function readCredentialFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) throw new Error(`${path.basename(file)} is empty. Add the base URL, admin username, password and API key (one per line, or name=value).`);
  return parseCredentials(text);
}

module.exports = { findCredentialFile, readCredentialFile, parseCredentials };
