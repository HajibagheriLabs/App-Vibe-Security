#!/usr/bin/env python3
"""
check-ruleset.py — prove the Semgrep ruleset still works.

A security ruleset fails silently. A rule whose pattern stops parsing, or stops matching
after a Semgrep upgrade, produces a green build and zero protection. This asserts both
directions against committed fixtures:

  tests/fixtures/vulnerable/   MUST produce findings from many distinct rules
  tests/fixtures/remediated/   MUST produce none

Run:      python3 tests/check-ruleset.py
Exit:     0 = ruleset healthy   1 = regression   2 = could not run

Requires semgrep on PATH. No other dependencies.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "skills" / "semgrep-rules.yml"
VULNERABLE = ROOT / "tests" / "fixtures" / "vulnerable"
REMEDIATED = ROOT / "tests" / "fixtures" / "remediated"

# Floor, not a target. Raise it when rules are added; never lower it to make CI pass.
MIN_DISTINCT_RULES = 15


def run_semgrep(target: Path) -> dict:
    cmd = [
        "semgrep",
        "--config", str(CONFIG),
        "--severity", "ERROR",
        "--metrics", "off",
        "--no-git-ignore",
        "--json",
        "--quiet",
        str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Semgrep exits 1 when it has findings, which is expected for the vulnerable set.
    # Anything else means the ruleset itself did not load.
    if proc.returncode not in (0, 1):
        print(f"THE RULESET FAILED TO LOAD (semgrep exit {proc.returncode} on {target}).",
              file=sys.stderr)
        print("A rule is malformed — usually a pattern that does not parse in one of the",
              file=sys.stderr)
        print("languages the rule declares. Semgrep reported:", file=sys.stderr)
        for stream in (proc.stderr, proc.stdout):
            text = (stream or "").strip()
            if text:
                print(text[-4000:], file=sys.stderr)
        sys.exit(2)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"semgrep produced no parseable JSON for {target}", file=sys.stderr)
        print(proc.stdout[-2000:], file=sys.stderr)
        print(proc.stderr[-2000:], file=sys.stderr)
        sys.exit(2)


def rule_errors(payload: dict) -> list:
    out = []
    for err in payload.get("errors", []):
        text = f"{err.get('type', '')} {err.get('message', '')}"
        if "parse" in text.lower() and "rule" in text.lower():
            out.append(text.strip())
    return out


def short(check_id: str) -> str:
    return check_id.split(".")[-1]


def main() -> int:
    for path in (CONFIG, VULNERABLE, REMEDIATED):
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 2

    failures = []

    # --- The rules must fire ------------------------------------------------
    vuln = run_semgrep(VULNERABLE)
    errs = rule_errors(vuln)
    for e in errs:
        print(f"RULE PARSE ERROR: {e}")
    if errs:
        failures.append(f"{len(errs)} rule(s) failed to parse")

    results = vuln.get("results", [])
    fired = sorted({short(r["check_id"]) for r in results})
    print(f"vulnerable fixtures: {len(results)} findings from {len(fired)} distinct rules")
    for name in fired:
        print(f"  fired  {name}")
    if len(fired) < MIN_DISTINCT_RULES:
        failures.append(
            f"only {len(fired)} distinct rules fired, expected at least {MIN_DISTINCT_RULES}"
        )

    # --- The rules must not over-fire --------------------------------------
    clean = run_semgrep(REMEDIATED)
    false_positives = clean.get("results", [])
    print(f"remediated fixtures: {len(false_positives)} findings (expected 0)")
    for r in false_positives:
        print(f"  FALSE POSITIVE  {short(r['check_id'])}  {r['path']}:{r['start']['line']}")
    if false_positives:
        failures.append(
            f"{len(false_positives)} false positive(s) on remediated code — a rule that "
            f"fires on correct code is a rule developers will disable"
        )

    print()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("ruleset healthy: rules fire on vulnerable code and stay quiet on remediated code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
