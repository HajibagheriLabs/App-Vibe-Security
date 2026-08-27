# Module 05 — Supply Chain and Build Integrity

> **Status:** Extension module — added beyond the original four because the shipping channel is the one attack surface that compromises every user at once.
> **Target vulnerability class:** Dependency hallucination (slopsquatting), unsigned artifacts, hijackable update channels
> **Empirical risk profile:** **19.7%** of model-suggested package dependencies do not exist in public registries; **43%** of hallucinated names recur across identical prompts
> **CWE mapping:** CWE-1357 (Reliance on Insufficiently Trustworthy Component), CWE-494 (Download of Code Without Integrity Check), CWE-347 (Improper Verification of Cryptographic Signature), CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere)

---

## 1. Root Cause

Two distinct failures share one blast radius: code the developer did not write ends up executing
on the user's machine with full application privileges.

**Slopsquatting.** Language models fabricate package names. Across large-scale evaluation, 19.7% of
suggested dependencies do not exist; open-weight model families average 21.7% and commercial models
5.2%. The fabrications are not random — 38% are semantic conflations of two real packages, 13% are
typographical variants, 49% are contextual inventions from naming convention. Critically, **43% of
hallucinated names recur across repeated runs of the same prompt**, which makes them predictable
enough to pre-register.

An attacker watching model output registers the recurring name on npm, PyPI, pub.dev, or Maven
Central. The next developer or autonomous agent that runs the install command downloads the
attacker's package. Install-time lifecycle scripts then run with developer privileges and lift
environment variables, cloud tokens, signing keys, and SSH keys off the build host.

Mobile and desktop projects widen this surface considerably. A React Native app pulls npm packages
*and* CocoaPods *and* Gradle artifacts. A Flutter app pulls pub.dev *and* both native ecosystems.
An Electron app pulls npm *and* prebuilt native binaries fetched over the network at install time
by `node-gyp` and postinstall scripts.

**The update channel.** Desktop applications ship an auto-updater. An updater that fetches over
plain HTTP, or that installs a package without verifying a signature, converts any network position
into code execution on every installation — silently, with the application's own privileges, and
with the user's trust in a signed binary already established. This is the highest-leverage bug a
desktop app can have, and generated updater configuration frequently omits the signature check
because the tutorial it was learned from used a local test server.

---

## 2. Non-Negotiable Rules

### R5.1 — Verify every package against the live registry before installing it

Run this **before** the install command, never after:

```bash
npm view <package> versions time.created repository
```

```bash
curl -s "https://pub.dev/api/packages/<package>" | head -20
```

- If the registry returns 404, the package **does not exist**. Report that. **Never guess a similar name** — near-miss names are exactly what attackers pre-register.
- Reject packages under 90 days old, with no working repository link, with negligible download history, or with a maintainer account created recently.
- Reject packages carrying install scripts they have no functional reason to need.
- Prefer, in order: platform standard library → framework built-in → an existing direct dependency → an established package with a long history → ten lines written locally. No micro-packages.

### R5.2 — Pin exactly, lock, and install from the lockfile

- No `^`, `~`, `*`, `latest`, `+`, or open ranges in `package.json`, `pubspec.yaml`, `Podfile`, or Gradle dependency declarations. Set `save-exact=true`.
- Commit every lockfile: `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`, `pubspec.lock`, `Podfile.lock`, Gradle verification metadata.
- CI installs with `npm ci`, `--frozen-lockfile`, or `--immutable`. A CI job that can resolve a new version is a CI job that can install a compromised one.
- Enable Gradle dependency verification (`gradle/verification-metadata.xml`) with checksums for native Android dependencies.
- Set `ignore-scripts=true` and allowlist lifecycle scripts individually for the few packages that genuinely require them.
- Scope internal packages (`@org/name`) and bind the scope to a private registry, so a public package of the same name cannot shadow it.

### R5.3 — Generate and retain an SBOM per release

Produce a CycloneDX or SPDX bill of materials for every published build, covering the JavaScript,
Dart, Gradle, and CocoaPods graphs plus any bundled native binaries. Store it with the release
artifact. When a dependency is disclosed as malicious, the SBOM is what answers "which shipped
versions contain it" in minutes rather than days.

### R5.4 — Sign every artifact, and verify signatures on the way in

| Platform | Requirement |
|---|---|
| Android | Play App Signing or an offline-held upload key; keystore never in the repository; `key.properties` git-ignored |
| iOS / macOS | Distribution certificate held in a secure store, notarization mandatory for macOS, hardened runtime enabled |
| Windows | Authenticode signature from a certificate in an HSM or a cloud signing service; timestamped so it survives certificate expiry |
| Linux | Detached GPG signature or a signed repository for `.deb` / `.rpm`; checksums published for AppImage |
| Electron | ASAR integrity validation enabled, plus platform signing above |

Signing keys live in the CI secret store or an HSM — never in the repository, never on a developer
laptop, never in an environment variable printed by a build log.

### R5.5 — The update channel is HTTPS, signed, and version-monotonic

- The update feed URL is **HTTPS with a pinned or verified certificate**. Never `http:`. Never a URL that is configurable by a deep link, config file, or command-line argument (see [Module 04](04-deep-link-verification.md)).
- The downloaded package is **signature-verified before execution**, against a public key compiled into the application. A checksum served from the same host as the artifact verifies nothing — an attacker who controls the artifact controls the checksum.
- Reject downgrades. An updater that accepts a lower version number can be forced back onto a build with a known vulnerability.
- Never disable the updater's own verification to make a staging build work. Use a separate staging channel with its own key.
- Support a kill switch: the ability to require a minimum client version server-side, so a compromised release can be forced out of circulation.

### R5.6 — Build hosts and CI are part of the trust boundary

- CI secrets are scoped per job, never exposed to workflows triggered by forks or untrusted pull requests.
- Pin CI actions by commit SHA, not by tag. A moving tag is a supply chain vulnerability with a friendly name.
- Builds run in ephemeral, isolated environments with no ambient cloud credentials.
- Never echo environment variables, run `env`, or print resolved configuration in a build log. Build logs are frequently public.
- Enforce two-person review on anything touching the build pipeline, signing configuration, or dependency manifests.

### R5.7 — Human review is mandatory for high-impact modules

Automation catches patterns. It does not catch design errors. Manual expert review remains
mandatory for:

- Authentication and session flows
- Payment and entitlement logic
- Key management and cryptographic code
- Native system interfaces, IPC handlers, and preload scripts
- The build, signing, and update pipeline itself

---

## 3. Detection

```bash
npm audit --audit-level=high
```

```bash
npx osv-scanner --recursive .
```

**Confirm every declared dependency actually exists** — this is the slopsquatting gate:

```bash
node scripts/audit-native.mjs . --check-deps
```

**Confirm the lockfile is authoritative** — a diff here means CI can resolve versions that were never reviewed:

```bash
npm ci --dry-run
```

**Confirm the update channel:**

```bash
grep -rEn "setFeedURL|feedURL|autoUpdater|http://" --include=*.js --include=*.ts --include=*.yml . | grep -v node_modules
```

Any `http://` in an update path, or an `autoUpdater` configuration without signature verification,
is a **P0**.

---

## 4. Agent Constraints

```text
SUPPLY CHAIN AND BUILD INTEGRITY — HARD CONSTRAINTS
1. VERIFY EVERY PACKAGE AGAINST THE LIVE REGISTRY BEFORE RUNNING ANY INSTALL COMMAND.
   Roughly 1 in 5 model-suggested packages does not exist, and attackers pre-register the
   recurring names.
2. If the registry returns 404: report it. NEVER guess a similar name.
3. Reject packages under 90 days old, without a working repository, with negligible downloads,
   or with unnecessary install scripts.
4. Pin exact versions everywhere: package.json, pubspec.yaml, Podfile, Gradle. No ^ ~ * latest.
5. Commit every lockfile. CI uses npm ci / --frozen-lockfile / --immutable.
6. Set ignore-scripts=true; allowlist lifecycle scripts individually.
7. Never place a signing key, keystore, or certificate in the repository. key.properties and
   *.jks / *.p12 / *.p8 are git-ignored before they are created.
8. Update feeds are HTTPS only, signature-verified against a key compiled into the app, and
   downgrade-resistant. Never make the feed URL configurable from outside the binary.
9. Pin CI actions by commit SHA. Never print env or resolved config in a build log.
10. State the source repository for every dependency you introduce.
```

---

Related: [Module 03](03-binary-trust-and-gateways.md) governs what is inside the artifact;
this module governs how the artifact is assembled and delivered.
