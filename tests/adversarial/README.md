# Adversarial Conformance

This directory is reserved for RFC-0016 adversarial harness assets.

Current coverage lives in `tests/adversarial_case_manifest.rs` and validates:

- RFC-0015 escape taxonomy coverage
- RFC-0016 case and result shape
- public-safe adversarial result output
- severity and capability-promotion gates
- minimal Tier 0 runner setup, inspection, cleanup, and result emission

Harness assets added here must stay platform-neutral and public-safe. Backend
private paths, account names, rule names, handles, local usernames, secrets,
credentials, and raw OS sandbox details must not appear in cases, fixtures,
results, or reports.

Tier 0 runner coverage should stay minimal and grow one observable lifecycle
step at a time.
