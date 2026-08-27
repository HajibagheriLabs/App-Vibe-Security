# Ruleset fixtures

Deliberately vulnerable samples that the Semgrep ruleset **must** flag, paired with
remediated versions it **must not** flag. CI asserts both directions, so a rule that
stops matching — or one that starts over-matching — fails the build instead of
silently going quiet.

`vulnerable/` is excluded from the repository's own scan via `.semgrepignore` and is
scanned explicitly by the self-test step in `.github/workflows/security-audit.yml`.

**Nothing here is real.** Every credential-shaped string is synthetic.
