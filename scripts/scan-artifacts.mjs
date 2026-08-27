#!/usr/bin/env node
/**
 * scan-artifacts.mjs — scan a BUILT artifact for credentials and shipped debug material.
 *
 * Source scanning misses values that the bundler injects at build time. This scans what
 * you actually distribute: the APK, AAB, IPA, app.asar, or output directory.
 *
 *   node scripts/scan-artifacts.mjs <path> [options]
 *
 * Accepts:  .apk .aab .ipa .zip  (ZIP containers, entries inflated in memory)
 *           .asar                (Electron archive — stored uncompressed)
 *           .so .dylib .exe .bin (native binaries — printable-string extraction)
 *           a directory          (walked recursively)
 *
 * Options:
 *   --json        Emit findings as JSON.
 *   --no-color    Disable ANSI colour.
 *   --max-mb <n>  Skip entries larger than n megabytes (default 64).
 *
 * Exit codes:  0 = clean   1 = findings   2 = usage error
 *
 * Zero dependencies. Node 18+.
 * Reference: modules/03-binary-trust-and-gateways.md
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { join, extname, basename, relative, sep } from 'node:path';

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

const PATTERNS = [
  { id: 'SECRET-STRIPE',   sev: 'ERROR',   rotate: true,  re: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}/g,          what: 'Stripe secret or restricted key' },
  { id: 'SECRET-OPENAI',   sev: 'ERROR',   rotate: true,  re: /\bsk-[A-Za-z0-9_-]{32,}/g,                          what: 'OpenAI-style API key' },
  { id: 'SECRET-AWS',      sev: 'ERROR',   rotate: true,  re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,                      what: 'AWS access key id' },
  { id: 'SECRET-GITHUB',   sev: 'ERROR',   rotate: true,  re: /\bgh[pousr]_[A-Za-z0-9]{30,}/g,                     what: 'GitHub token' },
  { id: 'SECRET-SLACK',    sev: 'ERROR',   rotate: true,  re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,                   what: 'Slack token' },
  { id: 'SECRET-SENDGRID', sev: 'ERROR',   rotate: true,  re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,     what: 'SendGrid API key' },
  { id: 'SECRET-GOOGLE',   sev: 'WARNING', rotate: false, re: /\bAIza[0-9A-Za-z_-]{35}\b/g,                        what: 'Google API key (safe only with platform + package restrictions)' },
  { id: 'SECRET-PRIVKEY',  sev: 'ERROR',   rotate: true,  re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, what: 'Private key block' },
  { id: 'SECRET-JWT',      sev: 'ERROR',   rotate: true,  re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g, what: 'JSON Web Token' },
  { id: 'SECRET-SUPABASE', sev: 'ERROR',   rotate: true,  re: /\bservice_role\b/g,                                 what: 'Supabase service-role reference' },
  { id: 'SECRET-BASIC',    sev: 'WARNING', rotate: true,  re: /https?:\/\/[A-Za-z0-9._%-]+:[^@\s/"']{4,}@/g,        what: 'Credentials embedded in a URL' },
  { id: 'SECRET-ASSIGN',   sev: 'WARNING', rotate: false, re: /(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|private[_-]?key|master[_-]?key|signing[_-]?key)["']?\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{20,}["']/gi, what: 'Constant named like a secret with a long literal value' },

  { id: 'NET-CLEARTEXT',   sev: 'WARNING', rotate: false, re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|schemas\.|www\.w3\.org|xmlns|ns\.adobe|java\.sun|apache\.org|purl\.org)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/gi, what: 'Cleartext http:// endpoint in the shipped artifact' },
  { id: 'NET-INTERNAL',    sev: 'WARNING', rotate: false, re: /https?:\/\/[a-z0-9.-]*\b(staging|internal|preprod|qa|sandbox|dev)\b[a-z0-9.-]*\.[a-z]{2,}/gi, what: 'Non-production endpoint shipped to users' },

  { id: 'DEBUG-SOURCEMAP', sev: 'WARNING', rotate: false, re: /\/\/#\s*sourceMappingURL=/g,                          what: 'Source map reference in the shipped bundle' },
  { id: 'DEBUG-ELECTRON',  sev: 'ERROR',   rotate: false, re: /nodeIntegration\s*:\s*!?0|nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false/g, what: 'Unsafe Electron flag present in the packaged application' },
  { id: 'DEBUG-INSPECT',   sev: 'ERROR',   rotate: false, re: /--remote-debugging-port|--inspect-brk|ELECTRON_DISABLE_SECURITY_WARNINGS/g, what: 'Debug channel enabled in the packaged application' },
];

// Entries whose content is worth inflating and scanning.
const TEXTY = /\.(js|jsx|ts|json|bundle|map|xml|plist|txt|properties|yaml|yml|html|css|dart|kt|java|swift|env|cfg|conf|ini|pem|key|md)$/i;
const BINARY_STRINGS = /\.(so|dylib|dll|exe|bin|a|framework|app|hbc|dex|jar|aar)$/i;
const NOISY_PATHS = /(^|\/)(META-INF|res\/drawable|res\/mipmap|assets\/fonts|kotlin\/|okhttp3\/|androidx\/|com\/google\/android\/gms\/)/i;

let MAX_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Minimal ZIP reader (central directory + stored/deflate entries)
// ---------------------------------------------------------------------------

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

function findEocd(buf) {
  const start = Math.max(0, buf.length - 66_000);
  for (let i = buf.length - 22; i >= start; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  return -1;
}

/** @returns {Array<{name:string, method:number, csize:number, usize:number, offset:number}>} */
function readZipEntries(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error('not a ZIP archive (no end-of-central-directory record)');
  let count = buf.readUInt16LE(eocd + 10);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // Zip64: the 32-bit fields are saturated; locate the Zip64 EOCD record.
  if (cdOffset === 0xffffffff || count === 0xffff) {
    for (let i = eocd - 20; i >= 0; i--) {
      if (buf.readUInt32LE(i) === 0x07064b50) {                 // Zip64 EOCD locator
        const z64 = Number(buf.readBigUInt64LE(i + 8));
        if (buf.readUInt32LE(z64) === 0x06064b50) {
          count = Number(buf.readBigUInt64LE(z64 + 32));
          cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
        }
        break;
      }
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== CEN_SIG) break;
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const offset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    entries.push({ name, method, csize, usize, offset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readZipEntryData(buf, entry) {
  if (entry.offset + 30 > buf.length) return null;
  if (buf.readUInt32LE(entry.offset) !== LOC_SIG) return null;
  const nameLen = buf.readUInt16LE(entry.offset + 26);
  const extraLen = buf.readUInt16LE(entry.offset + 28);
  const start = entry.offset + 30 + nameLen + extraLen;
  const raw = buf.subarray(start, start + entry.csize);
  try {
    if (entry.method === 0) return raw;
    if (entry.method === 8) return inflateRawSync(raw);
  } catch { /* truncated or unsupported entry */ }
  return null;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/** Extract printable ASCII runs from a binary buffer, the way `strings` does. */
function printableStrings(buf, min = 8) {
  const out = [];
  let cur = [];
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      cur.push(c);
    } else {
      if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
      cur = [];
    }
  }
  if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
  return out.join('\n');
}

function redact(s) {
  if (s.length <= 12) return s.slice(0, 4) + '…';
  return s.slice(0, 8) + '…' + s.slice(-4);
}

function scanText(text, where, findings, seen) {
  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags);
    let m, hits = 0;
    while ((m = re.exec(text)) !== null) {
      const sample = m[0].slice(0, 120);
      const key = `${p.id}|${where}|${sample}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({ id: p.id, severity: p.sev, rotate: p.rotate, where, what: p.what, sample: redact(sample) });
      }
      if (++hits >= 5) break;
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
}

function scanBuffer(buf, where, findings, seen) {
  const looksBinary = buf.includes(0);
  const text = looksBinary ? printableStrings(buf) : buf.toString('utf8');
  scanText(text, where, findings, seen);
}

function scanZip(path, findings, seen, notes) {
  const buf = readFileSync(path);
  const entries = readZipEntries(buf);
  notes.push(`${entries.length} entries in ${basename(path)}`);

  for (const e of entries) {
    if (!e.usize || e.usize > MAX_BYTES) continue;
    if (NOISY_PATHS.test(e.name) && !TEXTY.test(e.name)) continue;
    const interesting = TEXTY.test(e.name) || BINARY_STRINGS.test(e.name)
      || /(^|\/)(AndroidManifest\.xml|resources\.arsc|Info\.plist|\.env)$/i.test(e.name)
      || /index\.(android|ios)\.bundle$/i.test(e.name)
      || /(^|\/)Payload\/[^/]+\.app\/[^/.]+$/.test(e.name);      // iOS main binary
    if (!interesting) continue;

    const data = readZipEntryData(buf, e);
    if (!data) continue;
    scanBuffer(data, `${basename(path)}!${e.name}`, findings, seen);

    if (/\.map$/i.test(e.name)) {
      findings.push({ id: 'DEBUG-SOURCEMAP', severity: 'WARNING', rotate: false,
        where: `${basename(path)}!${e.name}`, what: 'Source map shipped inside the artifact', sample: '' });
    }
  }

  // Nested archives (an IPA carries the .app payload; an AAB carries base/ modules).
  for (const e of entries) {
    if (!/\.(apk|zip)$/i.test(e.name) || !e.usize || e.usize > MAX_BYTES) continue;
    const data = readZipEntryData(buf, e);
    if (!data) continue;
    try {
      for (const inner of readZipEntries(data)) {
        if (!inner.usize || inner.usize > MAX_BYTES) continue;
        if (!TEXTY.test(inner.name) && !BINARY_STRINGS.test(inner.name)) continue;
        const d = readZipEntryData(data, inner);
        if (d) scanBuffer(d, `${basename(path)}!${e.name}!${inner.name}`, findings, seen);
      }
    } catch { /* not a nested archive after all */ }
  }
}

function scanDirectory(dir, findings, seen, notes) {
  const skip = new Set(['node_modules', '.git', '.gradle', 'DerivedData']);
  let count = 0;
  const walk = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = join(d, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(full); continue; }
      if (!e.isFile()) continue;
      let size; try { size = statSync(full).size; } catch { continue; }
      if (size > MAX_BYTES) continue;
      if (/\.(apk|aab|ipa|asar)$/i.test(e.name)) { scanPath(full, findings, seen, notes); continue; }
      if (!TEXTY.test(e.name) && !BINARY_STRINGS.test(e.name)) continue;
      count++;
      try { scanBuffer(readFileSync(full), relative(dir, full).split(sep).join('/'), findings, seen); } catch { /* unreadable */ }
    }
  };
  walk(dir);
  notes.push(`${count} files scanned in ${basename(dir) || dir}`);
}

function scanPath(path, findings, seen, notes) {
  const ext = extname(path).toLowerCase();
  if (['.apk', '.aab', '.ipa', '.zip'].includes(ext)) {
    scanZip(path, findings, seen, notes);
  } else if (ext === '.asar') {
    // asar stores file contents uncompressed after a JSON header — a raw scan sees everything.
    scanBuffer(readFileSync(path), basename(path), findings, seen);
    notes.push(`asar archive scanned: ${basename(path)}`);
  } else {
    scanBuffer(readFileSync(path), basename(path), findings, seen);
    notes.push(`file scanned: ${basename(path)}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const argv = process.argv.slice(2);
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  const maxIdx = argv.indexOf('--max-mb');
  if (maxIdx >= 0 && argv[maxIdx + 1]) MAX_BYTES = Number(argv[maxIdx + 1]) * 1024 * 1024;
  const target = argv.find((a, i) => !a.startsWith('--') && argv[i - 1] !== '--max-mb');

  if (!target || flags.has('--help') || flags.has('-h')) {
    console.log('usage: node scripts/scan-artifacts.mjs <path-to-apk|aab|ipa|asar|binary|directory> [--json] [--no-color] [--max-mb n]');
    process.exit(target ? 0 : 2);
  }
  if (!existsSync(target)) {
    console.error(`scan-artifacts: path not found: ${target}`);
    process.exit(2);
  }

  const findings = [];
  const seen = new Set();
  const notes = [];

  try {
    if (statSync(target).isDirectory()) scanDirectory(target, findings, seen, notes);
    else scanPath(target, findings, seen, notes);
  } catch (e) {
    console.error(`scan-artifacts: ${e.message}`);
    process.exit(2);
  }

  const color = !flags.has('--no-color') && process.stdout.isTTY !== false;
  const c = color
    ? { red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`,
        green: (s) => `\x1b[32m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m` }
    : { red: (s) => s, yellow: (s) => s, green: (s) => s, dim: (s) => s, bold: (s) => s };

  if (flags.has('--json')) {
    console.log(JSON.stringify({ target, notes, findings }, null, 2));
  } else {
    const errors = findings.filter((f) => f.severity === 'ERROR');
    const warnings = findings.filter((f) => f.severity === 'WARNING');
    console.log('');
    console.log(c.bold('  App-Vibe-Security — shipped artifact scan'));
    console.log(c.dim(`  ${target}`));
    for (const n of notes) console.log(c.dim(`  ${n}`));
    console.log('');
    for (const [label, list, paint] of [['ERROR', errors, c.red], ['WARNING', warnings, c.yellow]]) {
      if (!list.length) continue;
      console.log(paint(`  ${label} (${list.length})`));
      console.log('');
      for (const f of list) {
        console.log(`    ${paint(f.id)}  ${f.what}`);
        console.log(`      ${c.dim('in:')} ${f.where}`);
        if (f.sample) console.log(`      ${c.dim('match:')} ${f.sample}`);
        if (f.rotate) console.log(`      ${c.red('ROTATE THIS CREDENTIAL NOW — it is in every installed copy.')}`);
        console.log('');
      }
    }
    if (!findings.length) {
      console.log(c.green('  No credentials or debug material found in the artifact.'));
      console.log('');
    }
    console.log(c.dim('  ─────────────────────────────────────────────────────────────'));
    console.log(`  ${c.red(`ERROR: ${errors.length}`)}   ${c.yellow(`WARNING: ${warnings.length}`)}`);
    if (findings.some((f) => f.rotate)) {
      console.log(c.red('  A credential in a published build cannot be recalled. Revoke it at the'));
      console.log(c.red('  vendor first; removing the string from main is cleanup, not remediation.'));
    }
    console.log('');
    console.log(c.dim('  Deeper inspection when a finding needs context:'));
    console.log(c.dim('    apktool d -f app-release.apk -o apk_src'));
    console.log(c.dim('    npx @electron/asar extract app.asar ./unpacked'));
    console.log('');
  }

  process.exit(findings.some((f) => f.severity === 'ERROR') ? 1 : 0);
}

main();
