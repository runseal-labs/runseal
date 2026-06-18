# Vendor

This directory is reserved for upstream code that RunSeal vendors instead of
rewriting.

The Windows sandbox enforcement baseline should come from the upstream Windows
sandbox crate. Keep RunSeal-specific code in `src/` focused on protocol, policy
mapping, audit output, capability reporting, and conformance tests.

Do not paste new low-level Windows ACL, restricted-token, WFP, setup-helper, or
command-runner implementations into the main crate. Add them here only as a
tracked upstream vendor import with a small RunSeal adapter.
