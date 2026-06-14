# RunSeal conformance tests

These Rust integration tests define the initial public behavior expected from a RunSeal implementation.

They are intentionally written before the runtime exists. The missing-binary tests document the current RED state. Once an implementation is present, run the suite with:

```bash
RUNSEAL_BIN=/path/to/runseal cargo test --test cli_contract --test protocol_contract
```

The tests are black-box by design:

- CLI behavior through `runseal exec`.
- JSON-RPC behavior through `runseal rpc --stdio`.
- Protocol vocabulary uses `Execution`, not raw process objects.
- Policy denials use stable error codes.
- Events are structured and align with the RFC event model.
