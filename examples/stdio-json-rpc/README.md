# RunSeal stdio JSON-RPC integration example

This example shows how a third-party local integration process can call RunSeal through
stdio JSON-RPC.

It demonstrates:

- launching `runseal service --stdio`
- calling `getVersion`, `getCapabilities`, `getServiceStatus`, and `getSetupStatus`
- failing closed when the requested sandbox policy, network mode, or setup state is unavailable
- executing a command with `execute`
- reading interleaved `event` notifications before the final JSON-RPC response
- replaying events with `subscribeEvents`
- retrieving audit events with `getAuditEvents`
- releasing service session state with `disposeSession`

The example uses newline-delimited JSON-RPC messages. It does not use
`Content-Length` framing.

## Run

Build RunSeal first:

```bash
cargo build
```

Then run the example:

```bash
python3 examples/stdio-json-rpc/runseal_stdio_example.py \
  --runseal ./target/debug/runseal \
  --cwd .
```

On Windows:

```powershell
python examples\stdio-json-rpc\runseal_stdio_example.py `
  --runseal .\target\debug\runseal.exe `
  --cwd .
```

The example defaults to:

- policy: `workspace-write`
- network: `disabled`

RunSeal requires `params.command[0]` to be path-qualified. The example uses a
platform system command path (`cmd.exe` on Windows, `/bin/sh` on POSIX) rather
than a bare program name.

## Fail-closed behavior

The example checks `getCapabilities` and `getSetupStatus` before `execute`.

It does not silently downgrade sandboxed execution to `danger-full-access`.
If the requested sandbox policy, network mode, or setup state is unavailable,
the example exits with an error.

Experimental capabilities are rejected by default. To explicitly allow
capabilities reported as `experimental`, pass this on Linux or macOS:

```bash
python3 examples/stdio-json-rpc/runseal_stdio_example.py \
  --runseal ./target/debug/runseal \
  --cwd . \
  --allow-experimental
```

For explicit unsandboxed local execution, pass a policy intentionally:

```bash
python3 examples/stdio-json-rpc/runseal_stdio_example.py \
  --runseal ./target/debug/runseal \
  --cwd . \
  --policy danger-full-access
```

Do not use `danger-full-access` as an automatic fallback for failed sandbox setup.
