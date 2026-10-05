# ADR-002: Finding model details that refine SPEC §5

- Status: accepted (M0) — open to change, please review
- Date: 2026-10-05

## Decisions

1. **`source_tools: list[str]` instead of `source_tool: str`.** SPEC §5 says dedup keeps
   a list of reporting tools and raises confidence when two independent tools agree;
   a list field makes that representable without a side channel. Minimum length 1.
2. **Fingerprint (`id`)** = `sha256(json([rule_id, location_key, normalised_evidence]))`.
   - Code locations use the *path only*; line/column are excluded because they drift
     whenever code above changes, which would make every edit look like "fixed + new"
     in diffs. The whitespace-normalised evidence snippet disambiguates within a file.
     Two byte-identical snippets in one file would share an id; dedup keeps both and gives
     later occurrences (in line order) a derived id `sha256(id + "#n")` (M3, found by tests).
   - HTTP locations use method + origin + path + sorted query **parameter names** +
     tested parameter. Query values (cache busters, ids) do not change the identity.
   - A stored id is never recomputed on load, so changes to masking rules cannot break
     diffs/suppressions against older scans.
3. **`description`, `impact`, `remediation`, `references` are optional on the model.**
   Modules may emit lean findings; the remediation KB fills them by `rule_id`. The
   M8 CI rule ("every `rule_id` has `remediation/<rule_id>.yaml`") guarantees that the
   report is always explainable.
4. **Secrets are masked at construction time** (`Evidence`, `HttpMessage`, `HttpLocation.url`
   validators call `secscope.core.redact`). It is impossible to build a finding that
   carries an unmasked known-format secret, so storage, logs and reports are safe by
   construction. Bodies are capped at 16 000 chars, snippets at 4 000.
5. Models are frozen and reject unknown fields (`extra="forbid"`).
