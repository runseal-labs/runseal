# RunSeal stdio JSON-RPC integration example

These standard-library Python and Node.js examples show how a third-party local
integration process can call RunSeal through stdio JSON-RPC.

It demonstrates:

- launching `runseal service --stdio`
- calling `getVersion`, `getCapabilities`, `getServiceStatus`, and `getSetupStatus`
- failing closed when the requested sandbox policy, network mode, or setup state is unavailable
- executing a command with `execute`
- receiving the v2 `preparing` receipt before any Execution events, then reading
  notifications until the unique terminal event carries the final result
- replaying events with `subscribeEvents`
- retrieving audit events with `getAuditEvents`
- releasing service session state with `disposeSession`

The Node.js example keeps one service process alive for several executions. It
queries and exchanges three binary stdin rounds with a live child, exercises a
resizable PTY, performs three duplex fd 3 control-channel rounds with separate
stdout/stderr, and cancels a running child after observing live output. Each path
checks the admission receipt, event sequence/offsets, terminal result, and cleanup;
the client fails closed when the requested profile or feature is unavailable.

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

For Node.js, use the same policy and network options:

```powershell
node examples/stdio-json-rpc/runseal_stdio_example.mjs --runseal ./target/debug/runseal.exe --cwd .
```

Run the Node.js example on a prepared Windows reference host to exercise the
sandboxed PTY and control channel. Linux and macOS currently report those
Windows-only combinations as unavailable and the example exits before starting
them.

The Node.js client uses `process.execPath` for its pipe, control, and cancellation
child commands and keeps the protocol reader active during requests and execution
output. Its PTY resize probe uses Python's standard-library `os.get_terminal_size`
to read the live pseudo-console dimensions; Python must be on `PATH`, or
`RUNSEAL_PYTHON` can name its absolute executable path.

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

The Windows CLI control example creates a local duplex endpoint with public Windows
APIs, passes only stdio and fixed CRT fd 3 to RunSeal, and consumes the public CLI.
It verifies three binary rounds, input half-close with a final reverse reply,
separate stdout/stderr markers, and exit 7. It defaults to workspace-write:

```powershell
python examples/stdio-json-rpc/runseal_control_cli_example.py --runseal target/debug/runseal.exe
```

The caller must provide a connected local duplex endpoint. Windows currently accepts
an AF_UNIX stream; missing, unsupported, or stdio-aliased endpoints fail before the
command starts. The example owns its temporary workspace and endpoint namespace.
