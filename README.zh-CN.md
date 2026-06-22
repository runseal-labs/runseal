# RunSeal

[English](README.md)

RunSeal 是面向 AI Agent 的 OS-native 本地沙箱层。

它提供稳定的执行协议，把本地命令放进受策略约束的文件系统、进程、资源和网络边界中运行。企业网络访问应通过受控代理出口完成，由代理负责路由控制、边界层认证、敏感信息脱敏和结构化审计。

RunSeal 不是云端 VM 沙箱、Docker Desktop 替代品，也不是 microVM 平台。它是为 agent framework 量身打造的 local-first 执行边界。

## 状态

`0.1.2` 是当前面向第三方集成的技术预览版本。仓库包含可构建的 CLI/RPC shell、标准策略 profile 归一化、canonical policy hash、backend capability 报告、一等公民的 Windows reference backend、`PlatformSandboxPlan` 摘要、JSONL audit 输出和黑盒 conformance 测试。

当前执行能力刻意保持窄边界：`danger-full-access` 以本地非沙箱方式执行。Windows 是当前最完备的支持平台：`read-only`、`workspace-contained`、`workspace-write` 等沙箱策略通过 reference backend 执行。macOS 和 Linux 已有部分 experimental enforcement，覆盖 `read-only` 和 `workspace-write` 搭配 `network.disabled`，但尚未与 Windows backend 对齐；剩余对齐工作预期由社区继续贡献。

Windows 上，沙箱请求会产生一个 `PlatformSandboxPlan`，涵盖 runtime root、synthetic home、profile root、temp root、setup 要求、受保护文件系统类别、进程边界状态、网络 guard 状态和策略路径规划。reference backend 处理 root 创建与清理、环境重定向、进程清理、文件系统 enforcement、进程隔离，以及 direct network deny 或 proxy guard 的强制执行。

底层 OS 强制逻辑位于专用的 Windows sandbox 实现中。RunSeal 自身的代码保持在适配层：策略归一化、`PlatformSandboxPlan` 映射、audit 事件、capability 报告和 conformance 门控。不要将 setup-helper、command-runner 或 OS 边界代码重新实现在 RunSeal 适配层中。

macOS 和 Linux 上，RunSeal 报告 experimental 的 `read-only` 和 `workspace-write` 路径，其他 sandbox level 仍为 unsupported。这些 portable 路径只强制写边界和网络边界，不包含 workspace containment——在 `workspace-contained` 独立实现并报告前，host 文件仍可能可读。portable 的 process cleanup 也是 experimental，不等同于 Windows reference cleanup。

客户端应优先使用 `sandbox_levels`、`network_modes` 和 `feature_statuses` 做状态判断。旧的 `features` 布尔值只是粗粒度的存在标记；portable capability probe 仅用于诊断，不会提升 unsupported capability。

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-write` | supported | experimental with `network.disabled` | experimental with `network.disabled` |
| `workspace-contained` | supported | unsupported | unsupported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | unsupported | unsupported |

协议和策略版本字符串为 `runseal.protocol/v1` 和 `runseal.policy/v1`。Rust package 仍处于 pre-`1.0` 阶段；RFC 变更时，provisional CLI flags、JSON fields 和 audit shapes 仍可能发生 breaking changes。

设计文档在 RFC 仓库：

- https://github.com/runseal-labs/rfcs
- 协议草案：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md

## 快速开始

下载 Windows release archive，把三个可执行文件放在同一目录：

- `runseal.exe`
- `runseal-windows-sandbox-setup.exe`
- `runseal-command-runner.exe`

安装或修复 Windows sandbox。当前 shell 未 elevated 时，使用 `--elevate` 主动请求 UAC：

```powershell
.\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
```

查看 host capabilities：

```powershell
.\runseal.exe capabilities
```

运行沙箱命令：

```powershell
.\runseal.exe exec --json --policy workspace-write --network disabled --cwd C:\path\to\workspace -- whoami.exe
```

显式本地非沙箱执行：

```powershell
.\runseal.exe exec --policy danger-full-access -- python skill.py
```

## 开发原则

测试优先。

测试套件是黑盒的、面向协议的。runtime 实现应在不改变测试行为断言的前提下通过测试——除非 RFC 先行变更。

## 预期 CLI

```bash
runseal exec --policy workspace-write --network proxy --cwd /workspace -- python skill.py
runseal exec --policy workspace-write --network disabled --cwd /workspace --timeout-ms 30000 -- whoami
runseal explain-policy --policy workspace-write --network proxy
runseal capabilities
runseal setup windows-sandbox --cwd C:\path\to\workspace --elevate
runseal rpc --stdio
runseal service --stdio
runseal version
```

可用 `exec` 参数：`--json`、`--events`、`--policy`、`--network`、`--cwd`、`--timeout-ms`。参数必须在 `--` 之前；命令及其参数跟在 `--` 之后。

`runseal exec --json` 失败时，stdout 包含结构化 `error` 对象，进程以非零退出码终止。
`runseal exec --events` 在事件流完成前失败时，stdout 包含一行结构化 `error` 对象，进程以非零退出码终止。

## Windows sandbox setup

构建所有 Windows 二进制，包括 setup helper 和 command runner：

```powershell
.\scripts\build-windows.ps1
```

构建 release artifacts：

```powershell
.\scripts\build-windows.ps1 -Release
```

脚本会把 `runseal.exe`、`runseal-windows-sandbox-setup.exe` 和 `runseal-command-runner.exe` 放到对应的 `target\debug` 或 `target\release` 目录。

推送 `v*` tag 会触发 `.github/workflows/release.yml`，构建原生 release archives 并发布 `.sha256` 校验文件。手动触发 workflow 并传入已有 tag 可以重新打包。

首次 bootstrap 可以用 `--elevate` 请求 UAC：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
```

安装 scheduled setup broker 后，同一命令可以在不再次打开 UAC 的情况下修复 workspace setup state。

使用 `--json` 让 agent 获得结构化的 setup 失败信息。成功时也包含 `setup_status`，便于自动化从同一命令确认 readiness。

只检查 setup readiness，不改变状态：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

状态 payload 包含粗粒度的 setup readiness：`broker`、`elevated`、`can_repair`、`can_run_setup_now`、`requires_setup` 和 `next_action`。Windows 上，同一 `setup_status` 对象也会出现在 setup 缺失或过期时的 `BACKEND_UNAVAILABLE` 错误中、对应的 `execution.failed` audit 事件中、`runseal capabilities` 中，以及 `runseal explain-policy` 中。

`requires_setup` 在 setup marker 和 sandbox user 工件全部完成前保持 true；`broker` 仅报告修复是否无需 elevated shell 即可运行。`can_repair` 在当前进程已 elevated 或 scheduled setup broker 已可用时为 true。

沙箱 `runseal exec` 不会直接拉起 UAC。它使用已安装的 scheduled setup broker；如果 broker 缺失或过期，执行会 fail closed 并返回 `windows sandbox setup unavailable`，直到再次运行 setup 命令。

## 预期协议

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "execute",
  "params": {
    "command": ["python", "skill.py"],
    "cwd": "/workspace",
    "policy": "workspace-write",
    "network": {"mode": "proxy"},
    "timeout_ms": 30000
  }
}
```

完整 JSON-RPC 方法集：

- `getVersion` — 包版本及协议/策略版本字符串
- `getCapabilities` — backend capabilities、sandbox levels、network modes、feature statuses
- `getServiceStatus` — 当前 stdio control plane 是 direct 还是 stateful service 模式
- `explainPolicy` — 按名称或内联定义解析并解释策略
- `getSetupStatus` — 查询 sandbox setup readiness，不改变状态
- `execute` — 在沙箱策略下运行命令
- `getExecution` — 按 ID 检索已完成的 execution（service 模式）
- `listExecutions` — 列出已知 executions（service 模式）
- `cancelExecution` — 取消正在运行的 execution
- `subscribeEvents` — 订阅指定 execution 的事件
- `getAuditEvents` — 获取指定 execution 的审计事件
- `tailAudit` — 流式获取新审计事件
- `disposeSession` — 释放 session 及其关联状态

`execute` 支持的参数：`command`（字符串数组；程序名必须 path-qualified）、`cwd`、`policy`、`network`（字符串或 `{"mode": ...}`）、`stdin`、`timeout_ms`、`metadata`（JSON 对象，最大 4096 字节）、`env`（JSON 键值对对象）。

## 第三方集成

从以下入口之一开始：

- CLI：调用 `runseal exec --json` 或 `runseal exec --events`，处理结构化错误。
- JSON-RPC stdio：启动 `runseal rpc --stdio`，依次调用 `getVersion`、`getCapabilities`、`execute`。
- Service stdio：当一个本地进程需要跨 JSON-RPC 请求持有已完成 execution 状态时，启动 `runseal service --stdio`。
- Conformance：设置 `RUNSEAL_BIN=/path/to/runseal`，运行 `tests/` 下的黑盒测试。

可运行的 stdio JSON-RPC client 示例见 [`examples/stdio-json-rpc`](examples/stdio-json-rpc)。

基于 `getCapabilities` 做沙箱执行的门控，在请求的能力不支持或 setup 不可用时 fail closed。`getSetupStatus` 查询 setup readiness 但不改变状态。`getServiceStatus` 判断当前 stdio control plane 是 direct 模式还是 stateful service 模式。stdio service 记录已完成 execution 用于 `getExecution`、事件回放、通过 `listExecutions` 做摘要列表、通过 `disposeSession` 释放 session，以及为已完成的 execution 提供稳定的不可取消响应。正在运行的 execution 可通过 `cancelExecution` 取消。事件和审计追踪可通过 `subscribeEvents`、`getAuditEvents` 和 `tailAudit` 获取。

## 运行测试

conformance 测试是 Rust 集成测试。`cargo test` 会构建并运行本地 `runseal` 二进制。

```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

Windows 上，重建 helper binaries 后运行 dogfood smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
```

从 elevated shell 运行；如果要验证文档化的交互式 UAC bootstrap 路径，添加 `-AllowElevation`。

Linux 或 macOS 上，构建 `runseal` 后运行 portable probe smoke：

```bash
python3 scripts/portable-probe-smoke.py
```

portable smoke 会检查 diagnostic capability probe、可用的 experimental portable enforcement，以及 unsupported 沙箱策略的结构化 fail-closed 行为。它不会提升 portable capability 为 supported。

Windows reference-backend 的 readiness 要求 smoke check 和上面 Rust 检查都在 Windows 主机上通过。

针对 managed proxy path：

```powershell
cargo test --test filesystem_conformance network_proxy_allows_http_through_managed_proxy_when_supported_or_fails_closed
```

在 Windows smoke 命令中添加 `-IncludeGit` 以验证沙箱内本地的 Git for Windows 安装。

针对其他候选实现运行测试：

```bash
RUNSEAL_BIN=target/debug/runseal cargo test
```

## 非目标

- 不依赖 Docker daemon。
- 企业默认场景不提供非托管直连网络访问。
- 不把真实密钥直接注入沙箱进程。
- 不在 core runtime 内做云端多租户 sandbox control plane。
- 不声称 OS-native sandboxing 能防住所有 kernel-level 逃逸。
