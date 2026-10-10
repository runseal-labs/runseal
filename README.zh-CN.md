# RunSeal

[English](README.md)

RunSeal 是一个 OS-native、受策略约束的本地命令执行环境。`SandboxPolicy`
为每个 `Execution` 定义文件系统、进程、资源和网络控制；RunSeal 生成结构化
事件与 JSONL 审计记录。

RunSeal 专注于本地执行边界，不是 AI governance 平台、工具注册中心、云端 VM
或容器管理器。各类集成应作为同一执行契约之上的轻量客户端。

## 当前状态

RunSeal 目前处于技术预览阶段。Windows 是 reference backend；macOS 和 Linux
的沙箱 enforcement 为 `experimental`，不支持的请求会 fail closed。
`danger-full-access` 是显式的本地执行，**不提供沙箱保证**。

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access`（非沙箱） | supported | supported | supported |
| `read-only` | supported | experimental | experimental |
| `workspace-write` | supported | experimental | experimental |
| `workspace-contained` | supported | experimental | experimental |
| `network.unmanaged` | supported | supported | supported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | experimental | experimental |

`experimental` 不代表稳定支持。依赖特定能力前，请在目标主机上检查
`runseal capabilities` 或 `getCapabilities`。通用 Windows CI 会跳过依赖预置
sandbox identity 的测试；跳过不算 conformance 通过。

## 快速开始

查看当前主机支持的能力：

```sh
runseal capabilities
```

按策略运行命令（选项放在 `--` 之前）：

```sh
runseal exec --policy workspace-write --cwd /path/to/workspace -- python3 -c "print('hello')"
```

网络默认行为取决于所选策略。主机支持时，可显式请求 managed proxy 出口或禁用网络：

```sh
runseal exec --policy workspace-write --network proxy --cwd /path/to/workspace -- python3 -c "print('hello')"
runseal exec --policy workspace-write --network disabled --cwd /path/to/workspace -- python3 -c "print('hello')"
```

确实需要不受沙箱限制的本地执行时，必须显式选择 `danger-full-access`：

```sh
runseal exec --policy danger-full-access --cwd /path/to/workspace -- python3 -c "print('hello')"
```

运行前可用 `runseal explain-policy --policy workspace-write` 查看策略解析结果。

### Windows setup

Windows sandbox 要求 Windows 10 1809（build 17763）或更新版本。请将
`runseal.exe`、`runseal-windows-sandbox-setup.exe` 和
`runseal-command-runner.exe` 放在同一目录；也可以从源码构建：

```powershell
.\scripts\build-windows.ps1
```

初始化或修复 setup（需要时用 `--elevate` 请求 UAC），然后检查 readiness：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\work --elevate
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\work --status
```

setup 完成后，broker 可为后续执行修复过期的 setup state。若 host 在未确认
cleanup 时退出，sandbox admission 会保持关闭。管理员可通过
`runseal repair execution-gates --json` 请求基于证明的恢复；若无法验证进程或
runtime root 已清理，RunSeal 会拒绝修复并保持绑定关闭。

## CLI 与集成

`runseal exec` 支持 plain、`--json` 和 `--events` 输出。plain 模式分别转发子命令的
stdout 和 stderr，并保留子命令退出码。RunSeal 自身失败的外层退出码为 125，超时
为 124，取消为 130。JSON/events 会区分子命令退出状态与 RunSeal 自身状态；适用时，
流式输出使用 base64 表示。

本地集成入口：

- **CLI：** `runseal exec`、`runseal explain-policy`、`runseal capabilities`。
- **JSON-RPC：** 使用 `runseal rpc --stdio` 接入协议客户端。
- **Service：** 使用 `runseal service --stdio` 跨请求保留已完成的 Execution 状态。
- **MCP：** `runseal mcp --stdio --policy <policy> [--network <mode>]` 只暴露一个
  窄范围的 `exec` tool。服务启动时固定 policy 和 network，模型不能自行放宽。

使用 `--network proxy` 时，命令通过 RunSeal 注入的代理环境变量连接；不要硬编码代理
端点或凭据。可运行的客户端和示例位于 [`examples/`](examples/)。公开协议与策略契约见
[RFC 仓库](https://github.com/runseal-labs/rfcs)。

## 运行时限额

下列启动设置在进程启动时冻结，并通过 `getCapabilities.limits` 报告。字节值以
十进制整数配置；表格为便于阅读使用二进制 KiB/MiB 单位。

| 环境变量 | 默认值 | 范围 | 用途 |
| --- | ---: | ---: | --- |
| `RUNSEAL_MAX_ACTIVE_EXECUTIONS` | 8 | 1–64 | 每连接的活动 Execution 数量 |
| `RUNSEAL_CLEANUP_TIMEOUT_MS` | 10,000 ms | 100–60,000 ms | host cleanup 截止时间 |
| `RUNSEAL_REPLAY_EXECUTION_BYTES` | 1 MiB | 64 KiB–64 MiB | 单个 Execution 的 replay 保留量 |
| `RUNSEAL_REPLAY_CONNECTION_BYTES` | 8 MiB | 64 KiB–256 MiB | 单个连接的 replay 保留量 |
| `RUNSEAL_COMPLETED_EXECUTIONS` | 1,024 | 1–65,536 | 保留的 Execution 摘要数量 |
| `RUNSEAL_COMPLETED_EXECUTION_BYTES` | 8 MiB | 64 KiB–256 MiB | 摘要保留预算 |
| `RUNSEAL_AUDIT_CACHE_BYTES` | 8 MiB | 64 KiB–256 MiB | 脱敏审计查询缓存 |
| `RUNSEAL_STREAM_CHUNK_BYTES` | 64 KiB | 8 KiB–64 KiB | 解码后的 stream chunk 上限 |
| `RUNSEAL_INPUT_PENDING_BYTES` | 256 KiB | 8 KiB–16 MiB | 待发送的 stdin/control 数据 |
| `RUNSEAL_RPC_FRAME_BYTES` | 1 MiB | 128 KiB–1 MiB | JSON-RPC 行长度上限 |
| `RUNSEAL_MAX_OUTPUT_BYTES` | 16 MiB | 1–16,777,216 字节 | 单次 Execution 的总输出上限 |
| `RUNSEAL_SENDER_BYTES` | 8 MiB | 5–64 MiB | 每连接的协议发送预算 |
| `RUNSEAL_BACKPRESSURE_MS` | 5,000 ms | 100–60,000 ms | 无输出进展宽限 |

连接级 replay 预算不得小于单次 Execution 的预算；待处理输入预算不得小于一个
stream chunk。有效输出上限属于归一化策略的一部分，会影响策略哈希；其他设置约束
运行时或传输行为，不改变策略哈希。具体协议语义以 RFC 为准。

## 开发与 conformance

```sh
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

在已准备好的 Windows reference host 上，运行包含 sandbox-only cases 的完整测试：

```powershell
cargo test --all-targets -- --include-ignored
```

Windows smoke 需要 elevated shell；验证文档所述的 UAC 流程时可添加
`-AllowElevation`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
```

Linux 和 macOS 上，构建 RunSeal 后运行 portable probe smoke：

```sh
python3 scripts/portable-probe-smoke.py
```

完整 conformance evidence matrix 见 [`tests/ACCEPTANCE.md`](tests/ACCEPTANCE.md)，
测试准备和平台说明见 [`tests/README.md`](tests/README.md)。被忽略的测试是 skipped，
不是通过。

## 延伸阅读

- [稳定执行协议（RFC-0006）](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md)
- [Escape 定义与 adversarial conformance（RFC-0015）](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md)
- [Adversarial conformance harness（RFC-0016）](https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md)
