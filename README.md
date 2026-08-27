# App-Vibe-Security

**Deterministic security guardrails for AI-generated mobile and desktop applications.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-React%20Native%20%C2%B7%20Flutter%20%C2%B7%20iOS%20%C2%B7%20Android%20%C2%B7%20Electron-informational)](#the-four-modules)
[![Rules](https://img.shields.io/badge/semgrep%20rules-47-brightgreen)](skills/semgrep-rules.yml)

Drop-in rule files, security specifications, and audit tooling that stop a coding agent from
writing the four vulnerabilities that dominate AI-generated native applications — **before** the
code is written, not after it ships.

Author: **Hadi Hajibagheri** · [@HajibagheriLabs](https://github.com/HajibagheriLabs) · MIT licensed

---

## The problem this solves

Generating a working app from natural language is now routine. Generating a *secure* one is not.

Empirical security evaluations put **40–62% of AI-generated code** as containing at least one
exploitable vulnerability, and **45% of AI-synthesized applications** fail a standard OWASP audit.
This is not a model defect that better prompting alone removes. It is structural:

> A language model optimizes for **functional completion**. It produces the shortest path from the
> prompt to running code, drawn from a training corpus full of tutorials, prototypes, and
> Stack Overflow answers where security was not the point. Non-functional requirements —
> context-aware validation, execution-boundary correctness, least privilege, threat-model
> awareness — are omitted unless something in the context window demands them explicitly.

For **native applications** the consequences are worse than on the web, for one reason the model
does not internalize: **you ship a file to a device the attacker owns.**

A web app keeps its code on your server and hands the browser a copy that is thrown away. A mobile
or desktop app hands the user an APK, an IPA, or an installer that they keep, copy, decompile, and
read at leisure — on a device they can root, image, and instrument. Assumptions that are merely
sloppy in a web context become fatal here:

| The model assumes | Reality on a shipped app |
|---|---|
| "The app sandbox protects this file." | It does not survive root, jailbreak, `adb backup`, or a forensic image. |
| "The API key is inside the binary, so it is hidden." | `unzip` and `strings` recover it in seconds. |
| "This check runs in my app, so it is trustworthy." | The binary is patchable and the API is callable with `curl`. |
| "This link came from our own email." | Anything can originate a deep link: a web page, an SMS, a QR code, a malicious app. |
| "Enabling this flag just fixes the error." | `nodeIntegration: true` converts every rendering bug into host code execution. |

**App-Vibe-Security supplies the missing context.** It puts explicit, non-negotiable, native-specific
constraints into the agent's system prompt — where benchmarks show language-specific security
prompting cuts insecure generation by around **37%**, and self-review at generation time cuts
vulnerability rates by **48–50%** — and then it verifies the result deterministically with a
Semgrep ruleset, two dependency-free audit scripts, and a multi-pass adversarial review.

Guardrails at generation. Verification at commit. Proof against the artifact you actually ship.

> Building web applications instead? The web-specific counterpart — secret boundaries, zero-trust
> authorization, injection defense, supply chain — is a separate project. This repository covers
> native mobile and desktop only.

---

## Threat model — what actually goes wrong

Four empirically observed failure classes drive everything in this repository. Each has a module,
a rule set, machine-checkable detections, and a worked remediation.

### 1. Desktop RCE escapes through Electron misconfiguration

**Severity: Critical — CVSS 9.6 to 10.0.**

Electron fuses a Chromium renderer with a Node.js runtime. Security depends entirely on keeping
them apart. Agents dismantle that boundary as a debugging step: the model writes renderer code
calling `require('fs')`, the renderer throws `require is not defined`, and the fix it reaches for
is `nodeIntegration: true, contextIsolation: false`.

The application then has no security boundary. **Any** rendering-layer injection — a markdown
preview, a chat message, a synced document title, a filename, output from a retrieval pipeline —
becomes remote code execution on the host, as the logged-in user.

Observed in the wild:

| CVE | Application | CVSS | Mechanism |
|---|---|---|---|
| **CVE-2026-32626** | AnythingLLM Desktop | **9.6** | Insecure Electron flags turned a web-layer rendering flaw into full RCE |
| **CVE-2026-33336** | Vikunja Desktop | **8.8** | Same class — process isolation disabled in the window configuration |
| **CVE-2026-34765** | Framework-level | — | Improper target-window isolation: `window.open` child inherits elevated opener permissions |

A second failure survives correct flags: the preload script exposes the capability wholesale.
`contextBridge.exposeInMainWorld('api', { exec, fs, invoke: (ch, ...a) => ipcRenderer.invoke(ch, ...a) })`
is `nodeIntegration: true` with one extra indirection — and the generic `invoke` passthrough
re-exposes every IPC handler any contributor adds later.

→ **[Module 02 — Desktop Process Isolation](modules/02-desktop-process-isolation.md)**

### 2. Cleartext local storage on mobile

**Severity: High.** The dominant data-at-rest failure in generated React Native and Flutter code.

Asked to "keep the user logged in", a model writes `AsyncStorage.setItem('authToken', token)` or
`SharedPreferences.setString('refreshToken', t)`. Both write **plaintext files inside the app
sandbox**. `MODE_PRIVATE` is process isolation, not encryption.

On a rooted or jailbroken device — or through `adb backup`, `run-as` on a debuggable build, an MDM
backup channel, or a desktop sync tool — those files are read directly. The prize is usually the
**refresh** token, which outlives the access token by weeks.

```bash
adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/RKStorage "SELECT key, value FROM catalystLocalStorage;"
```

The desktop equivalent is identical: an Electron app writing a token into `electron-store` or
`localStorage` under `userData`. Infostealer malware enumerates those paths by default.

→ **[Module 01 — Hardware-Backed Secure Storage](modules/01-hardware-secure-storage.md)**

### 3. Static credentials harvested from distributed binaries

**Severity: High.** Every string in your artifact is public the day you release.

Models place vendor keys next to the call site, exactly as they would in a server. `.env` files
feel like a fix and are not: `flutter_dotenv` bundles the file as an **asset**,
`react-native-config` writes values into `BuildConfig` and `Info.plist`, and `EXPO_PUBLIC_*` is a
compile-time string substitution by design.

| Artifact | Extraction | Time |
|---|---|---|
| React Native bundle | `unzip app.apk` → `strings assets/index.android.bundle` | seconds |
| Hermes bytecode | `hermes-dec` / `hbctool` — string table intact by design | minutes |
| Flutter release | `strings libapp.so`, or Blutter for Dart reconstruction | minutes |
| Android resources | `apktool d app.apk` → `strings.xml`, manifest, `BuildConfig` | seconds |
| iOS IPA | `unzip app.ipa` → `strings Payload/App.app/App` | seconds |
| Electron | `npx @electron/asar extract app.asar` — plain JavaScript | seconds |

Obfuscation does not change this. If the app can recover a value at runtime without a server, so
can an attacker. The fix is architectural: the credential moves to a backend gateway and the app
never holds it.

→ **[Module 03 — Binary Trust and Backend Gateways](modules/03-binary-trust-and-gateways.md)**

### 4. Deep link parameter tampering and open redirects

**Severity: Medium-High.** Low exploitation cost, and it frequently reaches authentication.

A deep link is an **unauthenticated RPC from an unknown caller**. Agents treat it as internal
navigation and write `navigation.navigate(path, queryParams)` — handing an attacker the route name
*and* every parameter.

```
myapp://settings?isPremium=true          → paid features unlocked
myapp://pay/confirm?amount=0&orderId=88  → state mutation from a URL
myapp://webview?url=https://evil.tld     → attacker page inside the trusted app chrome
myapp://auth?token=X&returnTo=evil.tld   → session from a link, then an open redirect
```

Switching to a verified App Link does not fix it. Verification proves the *domain* is yours; it
says nothing about who wrote the query string. On desktop it is sharper still: a registered
protocol arrives as `process.argv`, so a web page can inject `--gpu-launcher`, `--inspect`, or
`--no-sandbox` **into the trusted main process**, bypassing every renderer control.

→ **[Module 04 — Deep Link Verification](modules/04-deep-link-verification.md)**

### Extension: supply chain and build integrity

Beyond the original four, one more surface compromises every user at once. **19.7%** of
model-suggested dependencies do not exist in any registry — and **43% of the hallucinated names
recur** across identical prompts, which makes them predictable enough for attackers to
pre-register ("slopsquatting"). Native projects multiply the surface: a React Native app pulls npm
*and* CocoaPods *and* Gradle. Add unsigned artifacts and hijackable update feeds, and one bad
release reaches the entire install base.

→ **[Module 05 — Supply Chain and Build Integrity](modules/05-build-integrity-and-updates.md)**

---

## 30-second quickstart

**What you are doing:** copying one rules file into your app project, so your coding assistant reads
it automatically and refuses to write the vulnerabilities above.

First, get the files:

```bash
git clone https://github.com/HajibagheriLabs/App-Vibe-Security.git
```

Then find your tool in the table and run the one command in the last column, **from inside your own
app project directory**. Replace `~/App-Vibe-Security` with wherever you cloned it.

| Tool | What it reads | Where the file goes | Command to run |
|---|---|---|---|
| **Claude Code** | `CLAUDE.md` at the project root, loaded automatically every session | `./CLAUDE.md` | `cp ~/App-Vibe-Security/configs/CLAUDE.md ./CLAUDE.md` |
| **Cursor** | `.cursorrules` at the project root | `./.cursorrules` | `cp ~/App-Vibe-Security/configs/.cursorrules ./.cursorrules` |
| **Windsurf** | `.windsurfrules` at the project root | `./.windsurfrules` | `cp ~/App-Vibe-Security/configs/.windsurfrules ./.windsurfrules` |
| **Aider** | `.aider.conf.yml` plus a read-only context file | `./.aider.conf.yml` + `./AGENT_RULES.md` | `cp ~/App-Vibe-Security/configs/.aider.conf.yml ./ && cp ~/App-Vibe-Security/configs/AGENT_RULES.md ./` |
| **GitHub Copilot** | `.github/copilot-instructions.md` | `./.github/copilot-instructions.md` | `mkdir -p .github && cp ~/App-Vibe-Security/configs/copilot-instructions.md .github/copilot-instructions.md` |
| **Hermes agent** | `AGENTS.md` at the project root (open AGENTS.md convention) | `./AGENTS.md` | `cp ~/App-Vibe-Security/configs/AGENTS.md ./AGENTS.md` |
| **Codex CLI / Amp / Jules** | `AGENTS.md` at the project root | `./AGENTS.md` | `cp ~/App-Vibe-Security/configs/AGENTS.md ./AGENTS.md` |
| **Any other CLI or custom prompt** | Whatever you paste into the system prompt | — | `cat ~/App-Vibe-Security/configs/AGENT_RULES.md` — paste the output into your system prompt |
| **Web UI (chat window)** | Nothing automatically — paste it yourself | — | Paste `configs/AGENT_RULES.md` as your first message, before describing the app |

That is the whole setup. From the next prompt onward, the assistant carries the constraints.

**Using more than one tool?** Copy more than one file — they do not conflict. All of them are
compressed views of the same source of truth,
[`configs/AGENT_RULES.md`](configs/AGENT_RULES.md).

<details>
<summary><b>Not sure it worked? Test it in one prompt.</b></summary>

Ask your assistant, in the project where you placed the file:

> Store the user's auth token so they stay logged in between app launches.

**Without the rules**, you get `AsyncStorage.setItem('authToken', token)` or
`SharedPreferences.setString(...)`.

**With the rules**, you get `react-native-keychain` / `expo-secure-store` /
`flutter_secure_storage` with device-only accessibility, the access token kept in memory, and a
one-line note saying why.

If you still get `AsyncStorage`, the file is not being read: check the filename and that it sits at
the project root, then start a fresh session.

</details>

---

## Static code auditing

Guardrails reduce what gets written. These commands prove what actually exists. Run them from the
`App-Vibe-Security` directory, pointing at your app — or copy `skills/` and `scripts/` into your
project and run them there.

### The one-command sweep

```bash
node scripts/audit-native.mjs /path/to/your-app --check-deps
```

Deterministic, zero dependencies, Node 18+. Covers what a language-agnostic scanner cannot reach:
`AndroidManifest.xml`, `Info.plist`, `network_security_config.xml`, Gradle release configuration,
Electron packaging and fuses, lockfile presence, version pinning, committed signing material — and
with `--check-deps`, it queries npm and pub.dev live to confirm **every declared dependency
actually exists**. Exits non-zero on any ERROR finding, so it drops straight into CI.

### The Semgrep ruleset

```bash
semgrep --config skills/semgrep-rules.yml /path/to/your-app
```

47 AST rules across JavaScript, TypeScript, Dart, Kotlin, Java, Swift, and XML/plist — mapped to
CWE, OWASP Mobile Top 10, and MASVS, each carrying the module rule that explains the fix. Gate a
build with:

```bash
semgrep --config skills/semgrep-rules.yml --error --severity ERROR /path/to/your-app
```

### Scan what you actually ship

Source scanning misses anything the bundler injects at build time. This reads the artifact:

```bash
node scripts/scan-artifacts.mjs ./android/app/build/outputs/apk/release/app-release.apk
```

Accepts `.apk`, `.aab`, `.ipa`, `.asar`, native binaries, or a build directory. Inflates ZIP
entries in memory, extracts printable strings from native code, and reports credentials, JWTs,
private keys, cleartext endpoints, non-production hosts, shipped source maps, and unsafe Electron
flags **in the packaged application**. Matched values are redacted in the output.

### Electron-specific analysis

```bash
npx @doyensec/electronegativity -i /path/to/your-app -l 2
```

### Continuous enforcement

```bash
cp .pre-commit-config.yaml /path/to/your-app/ && cd /path/to/your-app && pre-commit install
```

```bash
cp .github/workflows/security-audit.yml /path/to/your-app/.github/workflows/
```

The workflow runs static analysis, live dependency verification, a gitleaks sweep across the full
git history, and the artifact scan. Actions are pinned by commit SHA.

---

## The native Ralph Loop audit

Deterministic tools find known patterns. They do not find design errors — a control in the wrong
place, an authorization check that trusts the wrong identity, a boundary that was never drawn. For
that, run an adversarial review with a **second** model auditing the first model's output.

**The prompt:** [`skills/audit-prompt.md`](skills/audit-prompt.md)

Run the deterministic tools first — they are faster and they never hallucinate:

```bash
semgrep --config skills/semgrep-rules.yml . && node scripts/audit-native.mjs . --check-deps
```

Then start a **fresh session with no memory of the build conversation** and paste the prompt. An
auditor that remembers why the code was written that way will rationalize the same blind spots.

```
┌── BUILDER ────────────┐        ┌── AUDITOR ─────────────────┐
│ generates / patches   │───────▶│ fresh context, no memory   │
│ code                  │        │ of the build rationale     │
│                       │◀───────│ emits structured findings  │
└───────────────────────┘  diff  └────────────────────────────┘
        ▲                                     │
        └────── repeat until PASS 1–5 all clean, max 5 iterations ──┘
```

Five passes, run separately and never summarized together:

| Pass | Covers |
|---|---|
| **1** | Local storage and data at rest — every persistence call, classified |
| **2** | Desktop process isolation — window flags, preload surface, IPC handlers, navigation |
| **3** | Binary secrets and backend gateways — artifact contents, client-side authority, TLS |
| **4** | Deep links, intents, and external input — the full entry-point surface |
| **5** | Dependencies and build integrity — existence, provenance, pinning, signing, updates |

The auditor emits `file:line`, a reproduction, an impact statement, and a **rotate-first** flag for
any credential that has ever shipped. `VERDICT: PASS` requires zero CRITICAL and zero HIGH.

**Loop exit conditions:** all five passes clean → PASS. The same finding surviving three repair
attempts → HALT and escalate to a human. A repair introducing a new CRITICAL → revert and escalate.

A repair prompt to feed findings back to the builder is included at the end of the file.

---

## The four modules

Each module is a complete specification: root cause, numbered non-negotiable rules, a reference
architecture, detection commands, an agent-constraints block to paste into a system prompt, and a
worked example.

| Module | Target | Key rules |
|---|---|---|
| **[01 — Hardware-Backed Secure Storage](modules/01-hardware-secure-storage.md)** | Cleartext credentials and PII on device | Ban `AsyncStorage` / `SharedPreferences` / `UserDefaults` / `electron-store` for sensitive values; mandate Keychain, Keystore via `EncryptedSharedPreferences`, `SecureStore`, `safeStorage`; device-only accessibility; biometric invalidation on enrolment change; access tokens in memory only |
| **[02 — Desktop Process Isolation](modules/02-desktop-process-isolation.md)** | Electron isolation bypass and unsafe IPC | `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` everywhere; no Node module over `contextBridge`; IPC handlers verify sender, parse schema, authorize, confine paths, `execFile` only; navigation and window creation denied by default; main-process CSP |
| **[03 — Binary Trust and Gateways](modules/03-binary-trust-and-gateways.md)** | Decompilation and credential harvesting | Zero static secrets in any shipped artifact; all privileged operations behind an authenticated backend gateway; server-side price, entitlement, and receipt validation; R8 / Hermes / Dart obfuscation; no cleartext HTTP; certificate pinning with backup pins |
| **[04 — Deep Link Verification](modules/04-deep-link-verification.md)** | Parameter tampering and open redirects | One resolver, `https:` only, exact hostname allowlist, closed route map, typed schema parse, reject-never-repair; a link may navigate but never authorize or mutate; redirect allowlist; desktop `argv` switch filtering; PKCE for OAuth |
| **[05 — Build Integrity](modules/05-build-integrity-and-updates.md)** *(extension)* | Slopsquatting, unsigned artifacts, hijackable updates | Live registry verification before install; never guess a near-miss name; exact pinning and committed lockfiles; signing material out of the repository; HTTPS signature-verified update feeds |

---

## Repository layout

```
App-Vibe-Security/
├── README.md                          you are here
├── LICENSE                            MIT
├── SECURITY.md                        reporting policy for this repository
├── .pre-commit-config.yaml            gitleaks + Semgrep + native audit, pinned
├── .github/workflows/
│   └── security-audit.yml             CI gate, actions pinned by commit SHA
├── configs/                           drop-in agent rule files
│   ├── AGENT_RULES.md                 ← source of truth, all modules compressed
│   ├── CLAUDE.md                      Claude Code
│   ├── .cursorrules                   Cursor
│   ├── .windsurfrules                 Windsurf (within its size budget)
│   ├── AGENTS.md                      Hermes, Codex CLI, Amp, Jules, custom CLIs
│   ├── copilot-instructions.md        GitHub Copilot
│   └── .aider.conf.yml                Aider
├── modules/                           full specifications
│   ├── 01-hardware-secure-storage.md
│   ├── 02-desktop-process-isolation.md
│   ├── 03-binary-trust-and-gateways.md
│   ├── 04-deep-link-verification.md
│   └── 05-build-integrity-and-updates.md
├── skills/
│   ├── audit-prompt.md                the five-pass adversarial Ralph Loop
│   └── semgrep-rules.yml              47 AST rules, CWE/OWASP/MASVS mapped
├── scripts/
│   ├── audit-native.mjs               manifests, plists, build config, live dep check
│   └── scan-artifacts.mjs             APK / AAB / IPA / asar / binary scanner
└── examples/                          side-by-side vulnerable vs. remediated
    ├── electron-ipc-remediation.md
    ├── mobile-storage-remediation.md
    └── deep-link-remediation.md
```

---

## Design principles

**Guardrails beat review.** A rule in the context window prevents the vulnerability. A finding in a
report asks someone to go back and fix it, which frequently does not happen.

**Deterministic beats probabilistic.** A model can be argued out of a security position. A Semgrep
rule and a non-zero exit code cannot. Every module ships machine-checkable detections.

**The floor is not the ceiling.** Static analysis finds known patterns. The adversarial audit finds
design errors. Human review stays mandatory for authentication, payments, key management, native
interfaces, and the build pipeline.

**Decouple boundaries from generated code.** Never rely on AI-synthesized application logic to
enforce a security boundary. The controls that matter — hardware key stores, backend authorization,
API gateways, process sandboxes — sit in platform infrastructure, outside what the model writes.

**Refuse, then substitute.** A rules file that only lists prohibitions gets worked around. Every
rule here pairs the prohibition with the correct alternative, so the agent has somewhere to go.
"It is only for development" is not an exception — development configurations ship.

---

## Contributing

Corrections to the guidance are the most valuable contribution. If a rule is wrong, outdated, or
produces a false positive that would push a developer to disable the check, open an issue with the
sample and the reasoning. New rules need a real-world failure mode, a detection, and a remediation.

See [SECURITY.md](SECURITY.md) for how to report a defect in this repository.

---

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Hadi Hajibagheri.

Use it, fork it, vendor the rule files into your own repositories, ship it inside a commercial
product. Attribution appreciated, not required.

---

## Author

**Hadi Hajibagheri** — [@HajibagheriLabs](https://github.com/HajibagheriLabs)
