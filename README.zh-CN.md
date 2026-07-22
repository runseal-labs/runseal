# RunSeal

[English](README.md)

RunSeal 是 OS-native、受策略约束的本地命令安全执行环境。

它提供稳定的执行协议，把用户自带的命令放进可强制执行的文件系统、进程、资源和网络边界中运行。企业网络访问应通过受控代理出口完成，由代理负责路由控制、边界层认证、敏感信息脱敏和结构化审计。

RunSeal 不是 AI governance 平台，不是工具生态，不是云端 VM 沙箱、Docker Desktop 替代品，也不是 microVM 平台。它是为 agent framework 量身打造的 local-first 执行边界。

## 状态

RunSeal 是当前面向第三方集成的技术预览版本。仓库包含可构建的 CLI/RPC shell、标准策略 profile 归一化、canonical policy hash、backend capability 报告、一等公民的 Windows reference backend、`PlatformSandboxPlan` 摘要、JSONL audit 输出和黑盒 conformance 测试。

当前执行能力刻意保持窄边界：`danger-full-access` 以本地非沙箱方式执行。`read-only` 和 `workspace-write` 在 Windows、macOS、Linux 三个平台都 supported。Windows 仍是当前最完备的平台，因为它还支持 `network.proxy`；`workspace-contained` 仅作为 Windows-only 的 strict compliance 选项，面向必须做 host-read containment 的部署。macOS 和 Linux 不会追求 `workspace-contained`，因为端侧 agent 需要保留实用的 host 工具和桌面集成能力。

产品边界刻意保持简单。RunSeal 提供的是执行环境：启动命令、应用策略、强制 OS-native 边界、输出事件和审计记录，并在请求的控制能力不可用时 fail closed。它不试图变成 AI governance 平台，也不试图变成工具或应用生态。各种集成应保持为同一命令执行契约之上的薄 adapter。

Windows 上，沙箱请求会产生一个 `PlatformSandboxPlan`，涵盖 runtime root、synthetic home、profile root、temp root、setup 要求、受保护文件系统类别、进程边界状态、网络 guard 状态和策略路径规划。reference backend 处理 root 创建与清理、环境重定向、进程清理、文件系统 enforcement、进程隔离，以及 direct network deny 或 proxy guard 的强制执行。

底层 OS 强制逻辑位于专用的 Windows sandbox 实现中。RunSeal 自身的代码保持在适配层：策略归一化、`PlatformSandboxPlan` 映射、audit 事件、capability 报告和 conformance 门控。不要将 setup-helper、command-runner 或 OS 边界代码重新实现在 RunSeal 适配层中。

macOS 和 Linux 上，RunSeal 支持 `read-only` 和 `workspace-write`，默认网络语义是 unmanaged 直通，其他 sandbox level 仍为 unsupported。这些 portable 路径只强制写边界，不包含 workspace containment；host 文件可能可读是有意的产品取舍。需要拒绝网络时可以显式请求 `network.disabled`；portable `network.proxy` 仍为 unsupported。

macOS 和 Linux 的 backend status 以及底层 feature status 仍为 `experimental`；下面的 `supported` 只针对当前 portable enforcement paths 已执行的公开 sandbox level 和 network mode。客户端应优先使用 `sandbox_levels`、`network_modes` 和 `feature_statuses` 做状态判断。旧的 `features` 布尔值只是粗粒度的存在标记；portable capability probe 仅用于诊断，不会提升 unsupported capability。

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | supported | supported |
| `workspace-write` | supported | supported | supported |
| `workspace-contained` | strict compliance option | not planned | not planned |
| `network.unmanaged` | supported | supported | supported |
| `network.disabled` | supported | supported | supported |
| `network.proxy` | supported | unsupported | unsupported |

### macOS 和 Linux hardening evidence

Windows 是一等公民的 reference backend。下面的 macOS 和 Linux 项追踪它们已声明 capability 的额外 hardening evidence。`workspace-contained` 被明确排除在 portable support 之外。

| Area | Windows reference | macOS portable | Linux portable | Evidence tracked |
| --- | --- | --- | --- | --- |
| Filesystem levels | `read-only` 和 `workspace-write` supported；`workspace-contained` 作为 strict compliance option 提供 | `read-only` 和 `workspace-write` supported；`workspace-contained` not planned | `read-only` 和 `workspace-write` supported；`workspace-contained` not planned | 针对已声明 capability 的共享 filesystem conformance，加上 adversarial external write、parent traversal、symlink 或 junction traversal、protected metadata 和 runtime-root cases。 |
| Network modes | `network.unmanaged`、`network.disabled` 和 `network.proxy` supported | `network.unmanaged` 和 `network.disabled` supported；`network.proxy` unsupported | `network.unmanaged` 和 `network.disabled` supported；`network.proxy` unsupported | `network.unmanaged` 的 direct pass-through 行为；`network.disabled` 的 direct socket 和 HTTP egress denial；`network.proxy` 的 managed proxy routing、environment override resistance、direct egress bypass denial、audit/event coverage，以及 public-safe fail-closed output。 |
| Setup/readiness | Windows setup readiness supported | 无平台 setup；报告 unsupported Windows setup，但不阻塞 portable enforcement paths | 无平台 setup；报告 unsupported Windows setup，但不阻塞 portable enforcement paths | 平台专用 setup contract、结构化 `getSetupStatus`、setup failure audit/events，以及 setup unavailable 时的 fail-closed 行为。 |
| Runtime roots and synthetic home | Supported | Experimental | Experimental | Runtime root creation、environment redirect、cleanup、marker spoofing、symlink replacement、partial setup failure 和 cross-execution contamination conformance。 |
| Process cleanup | Supported | Experimental | Experimental | Timeout、cancellation、child process、shell trampoline、nested process tree 和 helper reuse conformance，且不能终止无关进程。 |
| Audit/events | Supported | 当前 portable paths supported | 当前 portable paths supported | Execution、denial、setup failure 和 network decision events 必须和 JSONL audit records 对齐，并且不暴露 backend-private details。 |
| Adversarial conformance | Reference readiness 必需 | 针对 supported portable claims 持续追踪 | 针对 supported portable claims 持续追踪 | RFC-0016 manifest cases 必须为已声明 capability 产出 public-safe passing results；unsupported gaps 必须保持 explicit fail closed。 |

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

Windows sandbox 支持要求 Windows 10 1809 / build 17763 或更新版本。

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
runseal mcp --stdio --policy workspace-write
runseal rpc --stdio
runseal service --stdio
runseal version
```

可用 `exec` 参数：`--json`、`--events`、`--policy`、`--network`、`--cwd`、`--timeout-ms`。参数必须在 `--` 之前；命令及其参数跟在 `--` 之后。

`runseal exec --json` 失败时，stdout 包含结构化 `error` 对象，进程以非零退出码终止。
`runseal exec --events` 在事件流完成前失败时，stdout 包含一行结构化 `error` 对象，进程以非零退出码终止。

## Windows sandbox setup

Windows sandbox 支持要求 Windows 10 1809 / build 17763 或更新版本。

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
- MCP stdio：只有在需要把 RunSeal 的窄执行 adapter 直接暴露给 AI agent 时，启动 `runseal mcp --stdio --policy <policy> [--network <mode>]`。
- JSON-RPC stdio：启动 `runseal rpc --stdio`，依次调用 `getVersion`、`getCapabilities`、`execute`。
- Service stdio：当一个本地进程需要跨 JSON-RPC 请求持有已完成 execution 状态时，启动 `runseal service --stdio`。
- Conformance：设置 `RUNSEAL_BIN=/path/to/runseal`，运行 `tests/` 下的黑盒测试。

可运行的 stdio JSON-RPC client 示例见 [`examples/stdio-json-rpc`](examples/stdio-json-rpc)。

RunSeal 的 MCP surface 是窄执行 adapter，不是通用 MCP server framework。它只暴露一个 model-controlled tool：`exec`。服务启动者在启动时固定 `policy` 和 `network`；agent 不能通过 MCP 调用 `capabilities`、解释 policy、切换 network mode、切换 sandbox level 或提供 stdin。tool call 只接受 `command`、必填 `cwd`、可选 `timeout_ms` 和可选字符串 `env` 覆盖。`env` 仍受固定 RunSeal policy 的 scrub 规则约束。这样 MCP 面保留 coding agent 所需的执行能力，但不会让模型给自己放宽权限。

最小 MCP host 配置：

```json
{
  "mcpServers": {
    "runseal": {
      "command": "runseal",
      "args": ["mcp", "--stdio", "--policy", "workspace-write"]
    }
  }
}
```

如果 MCP host 不继承你的 shell `PATH`，把 `command` 改成 `runseal` 二进制的绝对路径。修改 MCP 配置后重启 host，然后调用它发现到的 `exec` tool：

```json
{
  "command": ["/usr/bin/python3", "-c", "print('hello from runseal')"],
  "cwd": "/workspace",
  "timeout_ms": 30000,
  "env": {"PYTHONUNBUFFERED": "1"}
}
```

不传 `--network` 时默认是 unmanaged 直通网络；只有需要拒绝网络出口时才传 `--network disabled`。使用 `--network proxy` 时，命令应在当前 execution 内读取 RunSeal 注入的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`GIT_HTTP_PROXY`、`GIT_HTTPS_PROXY` 等代理环境变量；不要硬编码代理主机、端口或凭据，因为 RunSeal 可能把 execution 挂到共享的本机 managed proxy broker。`RUNSEAL_NETWORK_PROXY_AUTHORIZATION` 是每次 execution 独立生成的凭据，仅供必须显式传 `Proxy-Authorization` header 的工具使用。

基于 `getCapabilities` 做沙箱执行的门控，在请求的能力不支持或 setup 不可用时 fail closed。`getSetupStatus` 查询 setup readiness 但不改变状态。`getServiceStatus` 判断当前 stdio control plane 是 direct 模式还是 stateful service 模式。stdio service 记录已完成 execution 用于 `getExecution`、事件回放、通过 `listExecutions` 做摘要列表、通过 `disposeSession` 释放 session，以及为已完成的 execution 提供稳定的不可取消响应。正在运行的 execution 可通过 `cancelExecution` 取消。事件和审计追踪可通过 `subscribeEvents`、`getAuditEvents` 和 `tailAudit` 获取。

每个沙箱 execution 都绑定到由 canonical policy 和 workspace path 派生的 policy epoch。相同 epoch 的 execution 可以并发运行。stateful client 和未来 daemon transport 在存在运行中沙箱 execution 时，不得切换 active workspace 或全局 policy。并发请求如果落到不同 policy epoch，必须显式失败并返回 `POLICY_TRANSITION_BUSY`；不能静默接受、降级，也不能影响已经运行的 execution。filesystem policy、network mode、workspace、identity、setup state 等会改变边界的字段都属于 epoch input；运行中的 execution 只能接受 cancellation、event/audit read 这类不改变边界的操作。未来如果要支持不同 workspace 并发，必须为每个 epoch 使用隔离的 sandbox worker、identity 和 setup state，而不是原地修改共享 sandbox。

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
该 smoke 也会检查 Windows helper binaries 是否齐全，并确认最终 sandbox runner token 能在允许的 workspace root 内创建和写入文件。

Linux 或 macOS 上，构建 `runseal` 后运行 portable probe smoke：

```bash
python3 scripts/portable-probe-smoke.py
```

portable smoke 会检查 diagnostic capability probe、supported portable enforcement，以及 unsupported 沙箱策略的结构化 fail-closed 行为。

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

- 不在 core runtime 内做 AI governance 平台、组织级审批流、policy dashboard、SIEM 产品或合规报表系统。
- 不实现通用 MCP server，也不承诺理解任意 MCP tool 的语义。
- 不在 core runtime 内做 universal MCP gateway、tool registry 或 adapter 生态。
- 不依赖 Docker daemon。
- 企业默认场景不提供非托管直连网络访问。
- 不把真实密钥直接注入沙箱进程。
- 不在 core runtime 内做云端多租户 sandbox control plane。
- 不声称 OS-native sandboxing 能防住所有 kernel-level 逃逸。
