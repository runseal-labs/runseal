# RunSeal

[English](README.md)

启动环境 `RUNSEAL_MAX_ACTIVE_EXECUTIONS` 配置每个 RPC/service 连接的活动执行上限，允许十进制整数 1..64，默认 8；启动后冻结，`getCapabilities.limits.max_active_executions` 回报实际值。连接达到上限时，新执行在目标启动前以 `EXECUTION_LIMIT_EXCEEDED` 拒绝，查询和取消仍可使用。待接纳请求和等待清理的执行线程计入同一容量；接纳校验和资源准备独立于连接控制请求推进，目标须等待 preparing 回执交付。无效配置会被拒绝且不回显配置值。

启动环境 `RUNSEAL_CLEANUP_TIMEOUT_MS` 配置 host 全范围清理等待，允许十进制毫秒 100..60000，默认 10000；`limits.cleanup_timeout_ms` 回报冻结值。host 各阶段沿用最早绝对截止时间，后续阶段或 Drop 不得重新计时；backend 可施加更早期限。此等待不延长命令的执行超时。

`RUNSEAL_REPLAY_EXECUTION_BYTES`（默认 1 MiB，允许 64 KiB..64 MiB）和 `RUNSEAL_REPLAY_CONNECTION_BYTES`（默认 8 MiB，允许 64 KiB..256 MiB）以十进制字节数配置 replay 驻留预算；连接预算不得小于单执行预算。启动时冻结，分别由 `limits.replay_execution_bytes` 和 `limits.replay_connection_bytes` 回报。淘汰推进可用历史范围，不改变实时输出或策略哈希。

终态摘要和脱敏审计查询缓存支持以下启动配置：

| 环境变量 | 默认值 | 允许范围 |
|---|---:|---:|
| `RUNSEAL_COMPLETED_EXECUTIONS` | 1,024 | 1..65,536 |
| `RUNSEAL_COMPLETED_EXECUTION_BYTES` | 8 MiB | 64 KiB..256 MiB |
| `RUNSEAL_AUDIT_CACHE_BYTES` | 8 MiB | 64 KiB..256 MiB |

字节设置使用十进制字节数。`getCapabilities.limits` 以 `completed_executions`、`completed_execution_bytes`、`audit_cache_bytes` 回报实际值。摘要数量和字节预算同时生效，活动执行仍可查询。审计缓存淘汰会报告历史不完整，落盘审计文件保留；这些设置不改变执行策略哈希。

`RUNSEAL_STREAM_CHUNK_BYTES` 配置 stream/input/control 解码后 chunk 上限，默认 64 KiB，允许 8 KiB..64 KiB。`RUNSEAL_INPUT_PENDING_BYTES` 配置 stdin/control 各自待写预算，默认 256 KiB，允许 8 KiB..16 MiB，计入已取出但尚未确认写完的数据，且不得小于一个 chunk。两者使用十进制字节数，启动时冻结，由 `limits.stream_chunk_bytes` 和 `limits.input_pending_bytes` 回报。RPC 超限 chunk 在写入目标前拒绝；输出和 plain CLI 原始输入按上限分片，字节、offset 和策略哈希不变。其他部署资源限制也可配置，具体项见下文。

`RUNSEAL_RPC_FRAME_BYTES` 限制 JSON-RPC 输入和输出行的字节数（包含换行），默认 1 MiB，允许 128 KiB..1 MiB。`limits.rpc_frame_bytes` 回报冻结后的启动值；`limits.query_response_bytes` 回报快照响应预算 `min(256 KiB, rpc_frame_bytes)`。超长输入排空至换行后拒绝，目标不启动，后续请求仍可处理。快照保留最新完整记录并明确报告截断；输出帧无法容纳时关闭连接并清理活动执行。此传输设置不改变策略哈希。

`RUNSEAL_MAX_OUTPUT_BYTES` 配置每个执行的 stdout/stderr/terminal/control 合计输出上限，默认 16 MiB，允许 1..16,777,216 的十进制字节数。`limits.max_output_bytes` 回报启动时冻结的部署值。归一化将有效 `resources.max_output_bytes` 明确写入 canonical policy JSON：未指定时采用部署上限，指定时取请求与部署值中更小的一个；请求明确设置为零时仍为零。解释结果、策略哈希、回执、逐事件和审计使用同一有效策略。有效输出上限变化会改变哈希，纯传输参数不会。恰好达到预算可正常完成，超限返回 `OUTPUT_LIMIT_EXCEEDED` 并清理执行范围；引擎拒绝未归一化的上限，不再叠加未进入哈希的隐藏 fallback。

`runseal exec` 的 plain、JSON、events 对 RunSeal 自身失败统一返回外层 125，timeout 为 124，主动取消为 130。plain 在 stderr 写 `[runseal:<CODE>]`；启动前 JSON/events 失败写一份结构化 error，events 运行失败保留唯一终态，不追加第二份错误。正常取得子进程结果时，plain 保留子进程退出码，JSON/events 外层为 0，包括 child exit 125。子进程可以自行输出相同前缀，需用结构化结果分类。未知选项、无效 timeout/network 值和 policy 拒绝不回显任意被拒绝的参数值。

最终 JSON 开始交付后，写入或输出清理失败返回非零外层状态，不重试结果，也不追加另一份 error。持久化终态记录执行完成，不代表调用方已收到完整结果；需同时检查外层状态和完整 JSON。

Windows `exec` 收到控制台 Ctrl-C/Ctrl-Break 时，通过 Execution owner 请求取消；三种输出模式在确认清理后返回外层 130，并保留真实退出事实和唯一审计终态。测试覆盖独立控制台中的真实事件、后代清理及独立 peer 继续运行，当前证据使用 `danger-full-access`。控制台 shutdown 事件、portable 宿主信号及 sandboxed 信号矩阵仍待验证。

`RUNSEAL_SENDER_BYTES` 配置每连接协议发送预算，默认 8 MiB，允许 5 MiB..64 MiB，启动时冻结并由 `limits.sender_bytes` 回报。其中 2 MiB 保留给 controller staging，剩余 writer 预算再保留 1 MiB 给控制帧。已编码帧、节点计费和尚未写完的帧同时受 enqueue/poll 限制；出队不提前释放计费。此参数改变传输 backpressure，不改变策略哈希或执行输出上限。完整常驻内存上界仍需这些队列计费之外的证据。

`RUNSEAL_BACKPRESSURE_MS` 配置无输出进展宽限，默认 5,000 毫秒，允许 100..60,000，启动时冻结，由 `limits.backpressure_ms` 回报。RPC、CLI 输出/control 及有界 backend 交付使用同一值；实际写出才重置传输 writer 进展，没有待发送输出的空闲连接不超时。backend 队列等待也受原清理截止时间约束。此参数不改变策略哈希，不替代 execution timeout。

stdin/control 的待发送字节合并到有界内部缓冲区，请求边界不形成永久队列节点。队列不保留调用方 Vec 的多余容量；in-flight bytes 在实际写入 ACK 后释放计费，超预算请求在复制前整体拒绝，EOF 等待已接纳数据交付。容量测试覆盖单字节填满和调用方超额预分配；真实 stdin/control 测试覆盖二进制顺序、拒绝、EOF 和仅 metadata 的审计。这些证据限制该队列的缓冲区/节点容量，完整连接的常驻内存上界仍待验证。

RunSeal 是 OS-native、受策略约束的本地命令安全执行环境。

它提供稳定的执行协议，把用户自带的命令放进可强制执行的文件系统、进程、资源和网络边界中运行。企业网络访问应通过受控代理出口完成，由代理负责路由控制、边界层认证、敏感信息脱敏和结构化审计。

RunSeal 不是 AI governance 平台，不是工具生态，不是云端 VM 沙箱、Docker Desktop 替代品，也不是 microVM 平台。它是为 agent framework 量身打造的 local-first 执行边界。

## 状态

RunSeal 是当前面向第三方集成的技术预览版本。仓库包含可构建的 CLI/RPC shell、标准策略 profile 归一化、canonical policy hash、backend capability 报告、一等公民的 Windows reference backend、`PlatformSandboxPlan` 摘要、JSONL audit 输出和黑盒 conformance 测试。

当前执行能力刻意保持窄边界：`danger-full-access` 以本地非沙箱方式执行。Windows 是 `read-only`、`workspace-write`、`workspace-contained` 和沙箱网络模式的 reference backend。macOS 和 Linux 将这些 portable enforcement paths 报告为 `experimental`；backend 状态不代表每台主机都支持每种 profile。portable 实现通过默认拒绝的平台视图约束 host read，并在所需机制不可用时 fail closed。

产品边界刻意保持简单。RunSeal 提供的是执行环境：启动命令、应用策略、强制 OS-native 边界、输出事件和审计记录，并在请求的控制能力不可用时 fail closed。它不试图变成 AI governance 平台，也不试图变成工具或应用生态。各种集成应保持为同一命令执行契约之上的薄 adapter。

Windows 上，沙箱请求会产生一个 `PlatformSandboxPlan`，涵盖 runtime root、synthetic home、profile root、temp root、setup 要求、受保护文件系统类别、进程边界状态、网络 guard 状态和策略路径规划。reference backend 处理 root 创建与清理、环境重定向、进程清理、文件系统 enforcement、进程隔离，以及 direct network deny 或 proxy guard 的强制执行。

底层 OS 强制逻辑位于专用的 Windows sandbox 实现中。RunSeal 自身的代码保持在适配层：策略归一化、`PlatformSandboxPlan` 映射、audit 事件、capability 报告和 conformance 门控。不要将 setup-helper、command-runner 或 OS 边界代码重新实现在 RunSeal 适配层中。

macOS 和 Linux 的 `read-only`、`workspace-write`、`workspace-contained`、`network.disabled` 和 `network.proxy` 均报告为 `experimental`。当前实现使用默认拒绝的平台视图；`workspace-contained` 只暴露 workspace、私有 runtime roots、显式 policy read roots 和最小只读系统执行基线。macOS 只允许连接当前 execution 的 managed proxy endpoint；Linux 使用隔离 network namespace 和 execution-local relay。已执行的 portable paths 会拒绝 direct external、无关 loopback 和未授权 host IPC 连接；在平台 conformance evidence 被接受前，`experimental` 状态仍是权威状态。

macOS 和 Linux 的 backend status、公开 sandbox level、沙箱网络模式以及底层 feature status 均为 `experimental`。`network.unmanaged` 和 `danger-full-access` 描述普通本地执行，状态为 `supported`。客户端应优先使用 `sandbox_levels`、`network_modes` 和 `feature_statuses` 做状态判断。旧的 `features` 布尔值只是粗粒度的存在标记；portable capability probe 仅用于诊断，不会提升 unsupported capability。

| Capability | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `danger-full-access` | supported | supported | supported |
| `read-only` | supported | experimental | experimental |
| `workspace-write` | supported | experimental | experimental |
| `workspace-contained` | strict compliance option | experimental | experimental |
| `network.unmanaged` | supported | supported | supported |
| `network.disabled` | supported | experimental | experimental |
| `network.proxy` | supported | experimental | experimental |

### macOS 和 Linux hardening evidence

Windows 是一等公民的 reference backend。下面的 macOS 和 Linux 项追踪它们已声明 capability 的额外 hardening evidence，包括默认拒绝宿主读取的 contained 边界。

| Area | Windows reference | macOS portable | Linux portable | Evidence tracked |
| --- | --- | --- | --- | --- |
| Filesystem levels | `read-only` 和 `workspace-write` supported；`workspace-contained` 作为 strict compliance option 提供 | `read-only`、`workspace-write` 和 `workspace-contained` 为 experimental paths | `read-only`、`workspace-write` 和 `workspace-contained` 为 experimental paths | 针对已声明 capability 的共享 filesystem conformance，加上 adversarial external read/write、parent traversal、symlink 或 junction traversal、protected metadata 和 runtime-root cases。 |
| Network modes | `network.unmanaged`、`network.disabled` 和 `network.proxy` supported | `network.unmanaged` supported；沙箱网络模式为 experimental | `network.unmanaged` supported；沙箱网络模式为 experimental | `network.unmanaged` 的 direct pass-through 行为；`network.disabled` 的 direct socket 和 HTTP egress denial；`network.proxy` 的 managed proxy routing 和 `CONNECT` tunneling、environment override resistance、direct TCP/UDP、无关 loopback、host-IPC 和 inherited-socket bypass denial、credential redaction、audit/event coverage，以及 public-safe fail-closed output。 |
| Setup/readiness | Windows setup readiness supported | 无平台 setup；报告 unsupported Windows setup，但不阻塞 portable enforcement paths | 无平台 setup；报告 unsupported Windows setup，但不阻塞 portable enforcement paths | 平台专用 setup contract、结构化 `getSetupStatus`、setup failure audit/events，以及 setup unavailable 时的 fail-closed 行为。 |
| Runtime roots and synthetic home | Supported | Experimental | Experimental | Runtime root creation、environment redirect、cleanup、marker spoofing、symlink replacement、partial setup failure 和 cross-execution contamination conformance。 |
| Process cleanup | Supported | Experimental | Experimental | Timeout、cancellation、child process、shell trampoline、nested process tree 和 helper reuse conformance，且不能终止无关进程。 |
| Audit/events | Supported | 当前 portable paths supported | 当前 portable paths supported | Execution、denial、setup failure 和 network decision events 必须和 JSONL audit records 对齐，并且不暴露 backend-private details。 |
| Adversarial conformance | Reference readiness 必需 | 持续追踪 experimental portable paths | 持续追踪 experimental portable paths | 每个 capability 在提升状态前，RFC-0016 manifest cases 都必须产出 public-safe passing results；unsupported gaps 必须保持 explicit fail closed。 |

协议和策略版本字符串为 `runseal.protocol/v2` 和 `runseal.policy/v1`。源码包候选版本 `0.2.0-rc.1` 已实现 v2 生命周期、流式 stdin/output、取消、PTY、control channel、可配置 transport 限制、审计和 session 清理。跨平台 CI 与已运行的 portable/local conformance 对应路径通过。仍需在 prepared Windows reference host 上完成 sandboxed pipe/stdin/cancel/PTY/control、filesystem/network enforcement、跨进程 policy gate 和 capability profile 矩阵。通用 Windows CI 会忽略依赖预置身份的用例；这些 skip 不计为 conformance 通过。`danger-full-access` 本地测试和示例明确不属于 sandbox 证据。停滞 Console 路径由拥有的 helper process 转发；本地 Console 回归通过，sandboxed 对应项仍待预置主机验证。Linux/macOS CI 已覆盖当前声明的 portable 路径，包括 Unix 非阻塞协议 writer。完整 Windows 矩阵通过前，此候选版本不得作为可发布版本。

标准 `read-only` profile 允许广泛读取、禁止 workspace 写入，执行私有 runtime root 仍可写。
自定义策略显式声明的读取范围保持不变。Windows 内部权限 profile 在选择隔离模式前包含 runtime root。

Windows sandboxed pipe 已验证自然退出、取消、超时和输出超限时的进程范围与
runtime root 清理，完成后才报告 `cleanup_complete:true`。Windows 显式本地 pipe
执行也拥有独立进程范围，已验证自然退出、取消、宿主异常退出以及其他连接的隔离。
本地执行在证明所属进程范围为空后排空输出，输入和输出线程共用清理截止时间。
真实测试让无关进程持有复制的 stdout/stdin 句柄，验证完整输出、及时完成和无关进程存活。
sandboxed runner 现在等待 I/O 线程结束后才确认清理成功，超时后读取实际进程退出码。
已确认的退出事实在 runner 清理失败或后续 parent 输入清理失败时仍会保留。缺少退出确认时保持未知，已知退出码不能使未完成的执行范围清理变为成功。
capture 输入来源失败使用 `EXECUTION_INPUT_FAILED` / `input_failed`，保留已确认退出事实。runner、parent 和 runtime roots 清理已完成时仍报告 `cleanup_complete:true`；清理失败优先报告，并保留最先接受的终止原因。native I/O 与真实本地 engine 的故障回归覆盖了报告路径，完整沙箱故障矩阵仍待完成。
其他运行管理故障首先被接受时，原因是 `execution_failed`，保留适用的结构化错误码。已启动 backend 缺少可信清理事实时返回 `EXECUTION_CLEANUP_FAILED`，退出保持未知，不能误报为命令启动失败。真实本地进程故障测试覆盖范围终止、先前取消和唯一持久终态。
清理失败标记写入失败时，owner 仍保留 reservation 和受保护的原生隔离信号；另一进程不能在该信号存活期间重新接纳绑定。
完整 I/O 故障矩阵和 portable 清理证据仍待完成。宿主死亡留下的绑定不会被自动清除：死占用、原生隔离信号和清理失败标记只能由下文的显式 `runseal repair execution-gates` 证明式修复释放。

Windows 共享执行状态现在依赖原生机器目录和 OS 进程边界，不再依赖调用方环境路径或 runtime home 的拼写。真实进程测试验证了环境路径覆盖时在 admission 阶段拒绝、原执行 heartbeat 继续推进，以及完全清理后接纳新策略。共享状态保持为 protected subpath：位于其中的 workspace 在启动前拒绝，其上级目录可写也不能修改受保护记录。协调锁等待有界，活动记录绑定宿主 PID 和原生创建时间。宿主死亡或身份无法验证均不能证明 cleanup 完成：同策略和不同策略都拒绝准入，健康同伴只释放自己的记录。跨全部 backend 组合的完整共享状态故障矩阵仍待完成；死绑定只能通过显式 `runseal repair execution-gates` 证明恢复。

Windows capture parent 通过轮询读取 IPC 分片，不再等待保持管道打开的对端补齐帧。取消、执行超时或输入线程失败后，parent 响应等待与输入线程 join 共用有界清理期限；Drop 不续期，未结束的 I/O 仍由 owner 持有，不能报告清理成功。真实管道和跨进程回归覆盖了这些路径。preparing、runner 和 frontend 全阶段的统一清理期限仍需继续实现和验证。

设计文档在 RFC 仓库：

- https://github.com/runseal-labs/rfcs
- 协议草案：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0006-stable-execution-protocol.md
- Escape model：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0015-escape-definition-and-adversarial-conformance.md
- Adversarial conformance：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0016-adversarial-conformance-harness-and-case-format.md
- macOS managed proxy：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0019-macos-managed-proxy-network-boundary.md
- Linux managed proxy：https://github.com/runseal-labs/rfcs/blob/main/rfcs/0020-linux-managed-proxy-network-boundary.md

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
plain `exec` 实时分流转发子命令 stdout/stderr 的原始 bytes，并保留子命令退出码。stdin 默认 empty；`--stdin inherit` 转发调用方输入与 EOF，且只允许 plain 模式。`--json` 返回一份最终结果，`output.stdout` 和 `output.stderr` 包含 `encoding: "base64"`、`data`、`bytes`、`truncated`；RunSeal 正常完成时外层退出码为 0，子命令的非零退出码仍放在 `exit_code` 中。
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

沙箱状态存放在机器级 home（`%LOCALAPPDATA%\RunSeal\windows-sandbox`，可用
`RUNSEAL_WINDOWS_SANDBOX_HOME` 覆盖），对所有 workspace 共享。因此一次
bootstrap 即可覆盖当前及未来的所有 workspace；切换 workspace 后无需再次 setup。

首次 bootstrap 可以用 `--elevate` 请求 UAC：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --elevate
```

bootstrap 会注册 scheduled setup broker。
之后同一命令可以在任何 workspace 下修复或重建 setup state 而不再打开 UAC；
沙箱 `runseal exec` 在 setup 缺失或过期时也会自动通过 broker 修复，而不是直接失败。

使用 `--json` 让 agent 获得结构化的 setup 失败信息。成功时也包含 `setup_status`，便于自动化从同一命令确认 readiness。

只检查 setup readiness，不改变状态：

```powershell
.\target\debug\runseal.exe setup windows-sandbox --cwd C:\path\to\workspace --status
```

状态 payload 包含粗粒度的 setup readiness：`broker`、`elevated`、`can_repair`、`can_run_setup_now`、`requires_setup` 和 `next_action`。Windows 上，同一 `setup_status` 对象也会出现在 setup 缺失或过期时的 `BACKEND_UNAVAILABLE` 错误中、对应的 `execution.failed` audit 事件中、`runseal capabilities` 中，以及 `runseal explain-policy` 中。

`requires_setup` 在 setup marker 和 sandbox user 工件全部完成前保持 true；`broker` 仅报告修复是否无需 elevated shell 即可运行。`can_repair` 在当前进程已 elevated 或 scheduled setup broker 已可用时为 true。

沙箱 `runseal exec` 不会直接拉起 UAC。它使用已安装的 scheduled setup broker：setup 缺失或过期时会在执行前自动通过 broker 修复。只有 broker 本身缺失时，执行才会 fail closed 并返回 `windows sandbox setup unavailable`，直到再次运行 setup 命令。

宿主在未确认 cleanup 的情况下死亡时，它的执行绑定会保持关闭，之后所有沙箱准入都返回 `EXECUTION_CLEANUP_FAILED`。只有显式修复才会恢复：

```powershell
.\target\debug\runseal.exe repair execution-gates --json
```

修复只有在同时满足以下条件时才继续：所有被记录的接纳 owner 均已消失；沙箱身份下没有进程在运行；每条被记录的 runtime root 均已不存在或可安全删除。随后它清除当前机器绑定的占用、清理失败标记和原生隔离信号。无法检查的进程 token 或早于 runtime root 记录的占用属于未验证证据，默认 fail closed；`--accept-unverified-release` 会继续并在 JSON 报告中标明未验证项。普通准入、`setup --status` 读取和重启都不构成修复。

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
- `getCapabilities` — backend capabilities、sandbox levels、network modes、粗粒度 feature statuses，以及细粒度 `execution_capabilities` 与按 sandbox level、network mode、io mode 展开的 `execution_profiles`
- `getServiceStatus` — 当前 stdio control plane 是 direct 还是 stateful service 模式
- `explainPolicy` — 按名称或内联定义解析并解释策略
- `getSetupStatus` — 查询 sandbox setup readiness，不改变状态
- `execute` — 在沙箱策略下运行命令
- `getExecution` — 按 ID 查询活动状态或保留的最终结果
- `listExecutions` — 列出已知 executions（service 模式）
- `cancelExecution` — 取消正在运行的 execution
- `subscribeEvents` — 订阅指定 execution 的事件
- `getAuditEvents` — 获取指定 execution 的审计事件
- `tailAudit` — 流式获取新审计事件
- `disposeSession` — 释放 session 及其关联状态

`execute` 支持的参数：`command`（字符串数组；程序名必须 path-qualified）、`cwd`、`policy`、`network`（字符串或 `{"mode": ...}`）、`stdin`、`timeout_ms`、`metadata`（JSON 对象，最大 4096 字节）、`env`（JSON 键值对对象）。

Windows 本地与 sandboxed PTY 使用 `io:{"mode":"pty","rows":24,"cols":80}` 和 `stdin:{"mode":"stream"}`。输出为 `execution.terminal`，终态包含 `terminal_bytes` 和 `stderr_merged:true`。`resizeExecution` 接受 execution ID 与 1..1000 的行列尺寸，返回入队回执。PTY 拒绝 pipe EOF 请求。`signalExecution` 接受活动 PTY 的 `signal:"interrupt"`，将终端 Ctrl+C 入队，保留 Execution 生命周期。danger-full-access 和 workspace-write 测试证明前台任务退出、同一个 Shell 继续执行和并行 Execution 存活。本地 profile 仍是显式无沙箱执行。Windows plain CLI 支持 `--pty --stdin inherit`：将终端输出转发到 stdout、跟踪控制台尺寸、退出前恢复控制台模式，并在继承输入结束时取消和清理所属 Execution。stdout 被重定向时初始尺寸为 80 列、24 行。真实终端测试覆盖 Unicode 输入、Ctrl+C、resize、原生退出码 7 和模式恢复；输入 pipe EOF 测试证明范围清理和并行 Execution 存活。完整故障/平台矩阵仍待完成。

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

conformance 测试是 Rust 集成测试。`cargo test` 会构建并运行本地 `runseal` 二进制。`tests/ACCEPTANCE.md` 把 RFC-0021 的每一条验收条件（AC01–28）映射到测试位置、命令、平台/模式、预期行为与实际结果。

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

portable smoke 会检查 diagnostic capability probe、报告为 experimental 的 portable enforcement 实际文件/网络行为，以及所需沙箱机制不可用时的结构化 fail-closed 行为。

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

Windows RPC control 已有四种标准 profile 的针对性证据：固定 child fd 3、三轮二进制交互、输入半关闭后反向回传、stdout/stderr 分离及独立 offset、清理后 peer 继续运行、仅保存元数据的审计。本地与 workspace-write 还验证了 stdin 阻塞时 control 仍推进、有界 control 输入、取消及共享输出限额。完整 control 故障/profile 矩阵仍待完成。

Windows plain CLI 支持 --control-fd 3，显式转发调用方已有的本地双向端点。二进制 control 与 stdout/stderr 分离，输入半关闭后仍能反向回传，保留子命令退出码，并限制 control 输出停滞。本地和 workspace-write 测试覆盖三轮交互、EOF 后最终回传、缺失端点/无效组合的启动前拒绝，以及调用方暂停读取时的清理与 peer 存活。公开 Windows API 示例位于 examples/stdio-json-rpc/runseal_control_cli_example.py。Windows CLI 的重定向 stdout/stderr 和 events 输出已接入非阻塞 pipe 写入。本地与 workspace-write 测试覆盖停读、关闭读端、所属进程清理、持久终态、peer 存活，以及超时先于 writer 停滞发生时保留超时原因。完整 Console/文件输出及 control 故障/profile 矩阵仍待完成。

Windows plain CLI 继承 Console 输入已有本地与 workspace-write 验收证据：Unicode、原生退格编辑、raw 输入、Ctrl+Z EOF，以及未提交换行时子命令提前退出。测试确认原生退出码 7、Console 模式保持一致，半行内容仍留在调用方缓冲区。完整 frontend 清理故障矩阵仍待完成。

Windows Console/文件输出现在通过持有独立句柄的有界、可取消写入转发。真实测试覆盖 Console 停读后的进程/runtime root 清理及 peer 存活、二进制文件输出，以及逐字节闸门控制的 Unicode 分块与调用方 code page 保持不变。Console 连续解码 UTF-8，非法或最终不完整序列显示为替换字符；pipe/文件保留原始 bytes。

本地 CLI Console 慢读测试在输出期间保持 child 活动，以实际消费解除退出闸门，确认完整审计字节计数、原生退出码 7 和所有不同的 supplementary 字符，CP437 保持不变。停滞计时跟随实际原生写入完成；关闭进展刷新后，同一用例被误判为 backpressure。

已知限制：plain 模式下，若 sandboxed 执行的 stdout/stderr 是一个句柄保持打开但停止读取的 Console，原生 console 写 worker 无法被取消。目标仍被终止，执行范围、runtime roots 与策略绑定仍被释放，但终态可能以 EXECUTION_CLEANUP_FAILED 报告并保留原始 requested_termination_reason（例如 backpressure），清理也可能耗满部署清理期限。会关闭的 pipe 不受影响；这是 Console 特有的限制，等待后续输出策略改造。

CLI frontend 的输入线程、终端模式、control 端点和输出 worker 现在由生命周期 owner 在提交审计终态前清理。未完成的 frontend 清理会报告 cleanup_failed，并保留原终止原因和真实退出事实。本地进程范围和 frontend 清理回调接收同一宿主截止时间，各 frontend 阶段与 Drop 不续期，未完成 I/O worker 保留 owner。CLI stdout/stderr 和 control 交付在清理期限到达时也停止，持续进展不能续期；本地 Console 慢读用例保留原生退出码 7、报告 frontend 清理未完成，wrapper 退出 125。preparing、通用 observer 交付、helper 和 capture parent 的期限协调、终端模式恢复及完整故障矩阵仍待完成。

Windows runner 的连接、请求写入和增量启动确认现在共享准备预算，并在等待期间检查取消和超时。原生测试验证未 join 的连接 owner 会被保留，安全设置失败后 suspended 进程被终止而目标未执行。capture parent 的 I/O 清理复用宿主绝对截止时间。启动失败仍报告清理未验证，不能以一个 runner 退出推定整个执行边界已释放。原生启动调用现在由 worker 持有，caller 按同一准备预算等待；到期后保留 worker，迟到的挂起进程会被终止而不会恢复执行。原生 setup、迟到启动的恢复、helper 完整期限及完整沙箱启动故障矩阵仍待完成。
