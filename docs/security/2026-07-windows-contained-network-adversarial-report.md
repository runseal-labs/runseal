# Windows contained and network adversarial report

- Status: evidence snapshot
- Report date: 2026-07-23
- Release under test: `v0.1.7`
- Release source: `7baba8695d906f1256895e86c4e44fa0273acb7a`
- Platform: Windows reference backend with Windows sandbox setup complete

## Scope

This report records a reproducible Tier 0 adversarial-conformance run against
the consumer Windows release binary. It covers the public `workspace-contained`
filesystem boundary and the `network.disabled` and `network.proxy` policy
boundaries. It does not claim to be an independent penetration test.

`7 test groups passed` is the Rust test-entrypoint count, not the case count.
The manifest has 63 Windows local-baseline cases. The current harness names
and executes 61 of them; two require dedicated Windows handle-lifecycle
coverage. Of the 21 cases directly in scope here, this run executes 20: all
12 contained-filesystem cases and 8 of the 9 contained-network cases. The
omitted network case is tracked explicitly below; it requires a real inherited
socket handle rather than the standard stdio RPC transport used by this
harness.

## Reproduction

From a source checkout with Rust and Python available, point the harness at the
downloaded release binary and run:

```powershell
$env:RUNSEAL_BIN = '<release-directory>\runseal.exe'
cargo test --test adversarial_harness -- --nocapture
```

The Windows sandbox setup must report `requires_setup: false` before running
the harness. Set `RUNSEAL_TEST_PYTHON` when Python is not discoverable through
the normal Windows command search path.

## Coverage accounting

| Population | Manifest cases | Executed against `v0.1.7` | Status |
| --- | ---: | ---: | --- |
| All Windows local-baseline cases | 63 | 61 | Two handle-lifecycle cases need dedicated Windows coverage |
| `workspace-contained` filesystem boundary | 12 | 12 | Covered |
| `workspace-contained` network boundary | 9 | 8 | One inherited-socket case pending dedicated transport harness |
| This report's contained/proxy scope | 21 | 20 | 95.2% case coverage |

The 12 filesystem cases include parent and absolute-path traversal, relative
cwd confusion, symbolic-link and junction traversal, link swap, case folding,
path normalization, reserved device names, UNC paths, a pre-existing runtime
link, and reading an external file. Each runs with `workspace-contained` and
must be denied or fail closed.

## Cases and expected outcome

| Boundary | Adversarial probes | Required outcome |
| --- | --- | --- |
| Contained filesystem | Read an external file from `workspace-contained` | Denied or fail closed; no external file access |
| Disabled network | Direct socket and HTTP egress, including a local listener | Denied or fail closed; no connection reaches the listener |
| Managed proxy | Direct socket bypass, proxy environment override, direct DNS fallback, localhost tunnel, and route bypass | Denied or fail closed; direct egress remains unavailable |
| Audit safety | Proxy credentials and policy-denial output | Structured audit evidence without credential or backend-private details |

The cases are defined in
[`adversarial/cases/rfc0016-initial.json`](../../adversarial/cases/rfc0016-initial.json)
and executed by [`tests/adversarial_harness.rs`](../../tests/adversarial_harness.rs).

## Observed result

The command above completed successfully against the `v0.1.7` Windows release
binary:

```text
7 test groups passed; 0 failed; 0 ignored
```

The network group covered eight directly executable network escape probes; the
filesystem group covered all twelve contained-filesystem probes. Each
policy-escape case requires `deny_or_fail_closed`; the harness also checks the
required public-safe audit and event behavior.

The one unexecuted case within this report's scope is
`adv.network.pre-opened-socket-inheritance.v1`. It is not reported as passed:
the normal `rpc --stdio` launcher cannot inject a pre-opened Windows socket
handle into the sandboxed child without a dedicated handle-transfer transport.
That transport test is a release gate follow-up, not an inferred pass.

Outside this report's scope, `adv.process.helper-process-reuse.v1` is likewise
not selected by the current harness. It does not change the contained/proxy
result, but prevents calling the 63-case manifest fully executed.

## Limits and follow-up

The harness uses disposable workspaces, local listeners, and reserved invalid
hostnames. It establishes deterministic behavior at the public execution
boundary, not resilience against every kernel, driver, or third-party tool
exploit. Re-run this report's command for every Windows release candidate and
when changing filesystem, process, runtime, or network enforcement. Do not
promote this report beyond Tier 0 until the inherited-socket case has its own
Windows handle-transfer harness.
