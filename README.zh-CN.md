# RunSeal

[English](README.md)

RunSeal 是面向 AI Agent 的 OS-native 本地沙箱层。

它提供稳定的执行协议，把本地命令放进受策略约束的文件系统、进程、资源和网络边界中运行。企业网络访问应通过受控代理出口完成，由代理负责路由控制、边界层认证、敏感信息脱敏和结构化审计。

RunSeal 不是云端 VM 沙箱、Docker Desktop 替代品，也不是 microVM 平台。它是 agent framework 可嵌入的 local-first 执行边界。

## 状态

`0.1.0` 是面向第三方集成的第一个技术预览版本。当前仓库包含可构建的 CLI/RPC shell、标准策略 profile 归一化、canonical policy hash、backend capability reporting、Windows reference backend、`PlatformSandboxPlan` 摘要、JSONL audit 输出和黑盒 conformance tests。

当前执行能力刻意保持窄边界：显式 `danger-full-access` 会作为本地非沙箱执行运行。Windows 上，`read-only`、`workspace-contained`、`workspace-write` 等沙箱策略通过 reference backend 执行。Linux 上，`read-only` 搭配 `network.disabled` 处于 experimental 状态，并在 runtime guard 可用时通过 portable backend 执行。其他 portable sandbox 策略在能强制执行前仍 fail closed。

macOS 当前报告 explicit experimental skeleton backend，并对 sandbox 策略 fail closed。Linux 当前报告 experimental `read-only` 路径，其他 sandbox level 仍 unsupported。Portable capability probe 仅用于诊断，不会提升 unsupported capability。

Windows 沙箱请求会包含 `PlatformSandboxPlan`，用于描述 runtime root、synthetic home、profile root、temp root、setup requirements、受保护文件系统类别、进程边界状态、网络 guard 状态和策略路径规划。Windows reference path 已覆盖 runtime root 创建/清理、runtime 环境重定向、进程清理、文件系统 enforcement、进程隔离，以及 direct network deny/proxy guard enforcement。

协议和策略版本字符串是 `runseal.protocol/v1` 和 `runseal.policy/v1`。Rust package 仍处于 pre-`1.0`；当 RFC 变更时，provisional CLI flags、JSON fields 和 audit shapes 仍可能发生 breaking changes。

设计文档在 RFC 仓库：

- https://github.com/runseal-labs/rfcs
- 协议草案：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md

## 快速开始

下载 Windows release archive，并把三个可执行文件放在同一目录：

- `runseal.exe`
- `runseal-windows-sandbox-setup.exe`
- `runseal-command-runner.exe`

在 elevated PowerShell 中安装或修复 Windows sandbox：

```powershell
.\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace
```

查看 host capabilities：

```powershell
.\runseal.exe capabilities
```

运行一个沙箱命令：

```powershell
.\runseal.exe exec --json --policy workspace-write --network disabled --cwd C:\path\to\workspace -- whoami.exe
```

显式本地非沙箱执行：

```powershell
.\runseal.exe exec --policy danger-full-access -- python skill.py
```

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

首次 bootstrap 需要 elevated PowerShell：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace
```

安装 scheduled setup broker 后，同一命令可以在不再次打开 UAC 的情况下修复 workspace setup state。

只检查 setup readiness：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

`runseal exec` 不会直接拉起 UAC。sandbox setup 缺失或过期时，执行会 fail closed，并返回结构化的 `BACKEND_UNAVAILABLE` / setup status 信息。

## 第三方集成

集成方优先使用这些入口：

- CLI：调用 `runseal exec --json` 或 `runseal exec --events`，处理结构化错误。
- JSON-RPC stdio：启动 `runseal rpc --stdio`，依次调用 `getVersion`、`getCapabilities`、`execute`。
- Service stdio：当一个本地进程需要跨 JSON-RPC 请求持有已完成 execution 状态时，启动 `runseal service --stdio`。
- Conformance：设置 `RUNSEAL_BIN=/path/to/runseal`，运行 `tests/` 下的黑盒测试。

客户端应基于 `getCapabilities` 判断沙箱能力，并在请求能力不支持或 setup 不可用时 fail closed。`getSetupStatus` 可查询 setup readiness，且不会改变 setup state。`getServiceStatus` 可判断当前 stdio control plane 是 direct 还是 stateful service mode。`listExecutions` 可在 service mode 返回已知 execution 的公开摘要列表。

敏感文件应通过 policy 的 `filesystem.deny` 显式保护，例如 SSH keys、cloud credentials、package-manager credentials 和 agent/runtime 配置目录。RunSeal 会把这些路径纳入有效策略和 policy hash；实现应在公开输出里使用逻辑类别，避免泄露 resolved host paths。

企业凭据不应注入到沙箱进程环境变量中；应由 managed proxy 在边界层注入 header 或完成上游认证。

## 本地测试

```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

Windows 上，重建 helper binaries 后运行 dogfood smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1
```

Linux 或 macOS 上，构建 `runseal` 后运行 portable probe smoke：

```bash
python3 scripts/portable-probe-smoke.py
```

portable smoke 只检查 diagnostic capability probe 和沙箱策略的结构化
fail-closed 行为，不提升 macOS 或 Linux 的 sandbox 支持声明。

针对 managed proxy path：

```powershell
cargo test --test filesystem_conformance network_proxy_allows_http_through_managed_proxy_when_supported_or_fails_closed
```

## 非目标

- 不依赖 Docker daemon。
- 企业默认场景不提供 unmanaged direct network access。
- 不把真实密钥直接注入沙箱进程。
- 不在 core runtime 内做云端多租户 sandbox control plane。
- 不声称 OS-native sandboxing 可以防住所有 kernel-level escape。
