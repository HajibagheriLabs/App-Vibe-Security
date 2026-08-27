# Security Policy

## Scope

This repository contains **security guidance, agent configuration, and audit tooling**. It ships no
runtime library and processes no user data. The security surface is therefore:

1. **Correctness of the guidance.** A rule that is wrong, outdated, or misleading is a defect with
   real downstream impact — people ship code based on it.
2. **The audit scripts** in [`scripts/`](scripts/), which read files in a repository or an artifact
   and, with `--check-deps`, make outbound registry requests.
3. **Detection gaps.** A pattern that should be caught and is not.

## Reporting

Report through **GitHub Security Advisories** on this repository
(`Security` → `Report a vulnerability`), or open a public issue if the finding is a guidance
correction rather than an exploitable flaw.

Please include:

- Which file and rule identifier the report concerns (e.g. `modules/02` R2.4, `AVS-205`)
- For a guidance defect: why the current rule is wrong, and what the correct rule is
- For a detection gap: a minimal code sample that should be flagged and is not
- For a false positive: the sample, and why it is safe

Expect an initial response within seven days.

## What counts as a vulnerability here

| Report | Treated as |
|---|---|
| A rule that recommends an insecure pattern | **Critical** — fixed and a correction noted in the module |
| An audit script that executes untrusted input, writes outside its output path, or transmits scanned content anywhere | **Critical** |
| A detection gap for a pattern the module explicitly bans | **High** |
| A false positive that would push a developer to disable the check | **Medium** |
| A missing rule for a class not yet covered | **Enhancement** — open an issue |

## Handling secrets in reports

The audit scripts **redact** matched values in their output by design, and this project asks that
you do the same. Do not paste a live credential into an issue, an advisory, or a test fixture. Use
an obviously synthetic value (`sk_live_EXAMPLE...`) when demonstrating a detection gap.

If you discover a real credential exposed in a third-party application while using these tools:
report it to that application's vendor, not here. **Rotation is the remediation** — a credential
inside a published build cannot be recalled.

## Using this repository safely

- `scripts/audit-native.mjs` and `scripts/scan-artifacts.mjs` have **no dependencies** and make no
  network requests unless you pass `--check-deps`. Read them before running them on a sensitive
  codebase — they are short and deliberately dependency-free so that reading them is practical.
- Scan output can contain fragments of matched values. Do not commit it; `/audit-out/`, `/loot/`,
  and `*.sarif` are git-ignored for that reason.
- The rules in [`configs/`](configs/) constrain a coding agent. They are not a sandbox. An agent
  with shell access can still be told to do something harmful by a user, or by content it reads.
  Combine these rules with a permission model on the agent itself.

## Supported versions

The `main` branch is the supported version. Security corrections land there.
