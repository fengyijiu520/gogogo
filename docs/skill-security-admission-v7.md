# 技能安全准入核心评估表 V7

## 适用范围

V7 聚焦“技能进入公司内部仓库前”的准入审查。网关输入输出审查、项目组组合使用多个技能时的链路风险审查，不作为本表的主要判定对象；本表只在必要处输出可供后续场景复用的证据，例如权限清单、外联清单、数据处理清单和残余风险。

## 准入结论

| 准入结论 | 含义 | 触发条件 |
| --- | --- | --- |
| 不通过 | 当前技能不得入库 | 存在恶意能力、真实凭证泄露、数据外发、沙箱逃逸、验证失败仍放行等高风险问题，或高风险问题无法由平台侧可靠隔离 |
| 需人工复核 | 自动检测证据不足，必须由安全人员确认 | 存在中风险组合、闭源或混淆内容、声明与行为不一致证据不足、外部服务信任边界不清 |
| 可整改后通过 | 风险真实但可由作者在入库前修复 | 发现中低风险配置缺陷、缺少声明、校验不完整、日志或审计不足等问题，并且修复后可复扫确认 |
| 通过 | 本次准入检查未发现需要阻断、复核或整改的风险 | 所有适用项均未命中风险，或仅存在已记录且已有充分补偿的残余低风险 |

“通过”不表示绝对没有风险，只表示在本次准入检查范围内没有发现影响入库的风险。

## V7 评估项

| ID | 评估项 | 危害等级 | 适用场景 | 检测目标 | 检测步骤 | 证据要求 | 准入判定 | 可接受补偿 | 平台侧防御 | 信息来源 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| V7-001 | 恶意代码与破坏性行为 | 高风险 | 准入 | 检测系统破坏、勒索、挖矿、反弹 Shell、任意命令执行等主动恶意能力 | 1. 扫描源码和脚本中的危险命令、反弹连接、挖矿关键字、批量删除逻辑。2. 对命中位置做上下文复核，排除文档示例和测试夹具。3. 沙箱执行可疑入口，观察进程、网络、文件写入和系统调用。 | 命中文件、行号、代码片段、沙箱行为日志 | 命中真实恶意能力则不通过 | 不接受补偿 | 沙箱隔离和出口限制只能降低运行期影响，不能替代准入修复 | OWASP AI Agent Security Cheat Sheet；CWE-94；CWE-78 |
| V7-002 | 后门与条件触发逻辑 | 高风险 | 准入 | 检测特定口令、时间、环境变量、隐藏参数触发的未声明能力 | 1. 扫描条件分支中的 magic string、debug secret、隐藏路由和时间触发。2. 比对 SKILL.md 与实际行为。3. 对可疑触发条件做动态验证。 | 触发条件、代码位置、触发后的实际行为 | 存在隐藏高风险能力则不通过 | 不接受补偿 | 运行时审计可作为辅助发现手段 | OWASP AI Agent Security Cheat Sheet；CWE-912 |
| V7-003 | 敏感数据外发与隐蔽通道 | 高风险 | 准入 | 检测环境变量、密钥、文件、上下文、用户数据被发送到未声明目标或隐蔽通道 | 1. 提取网络目标、DNS 查询、HTTP 请求、Webhook 和 socket 调用。2. 建立数据流，从敏感源到网络 sink 做污点分析。3. 沙箱中阻断外联并记录目的地。 | 敏感源、外联目标、数据流路径、请求证据 | 未声明敏感数据外发则不通过 | 不接受补偿；仅声明不充分但用途合理时可整改后复扫 | 出口白名单、DLP、请求审计 | OWASP AI Agent Security Cheat Sheet；OWASP LLM Top 10 LLM06；CWE-200 |
| V7-004 | 硬编码真实凭证 | 高风险 | 准入 | 检测代码和配置中的真实密码、Token、API Key、AK/SK、私钥等敏感凭证 | 1. 扫描凭证关键字、私钥头、云厂商 Key 格式和高熵字符串。2. 排除空值、占位符、环境变量引用和示例文档。3. 对疑似真实凭证做人工确认，不在报告中明文展示完整值。 | 脱敏后的凭证片段、文件位置、凭证类型 | 真实凭证泄露则不通过 | 不接受补偿，必须移除并轮换 | Secret 扫描、密钥托管、凭证轮换 | CWE-798；CWE-259；CWE-321；OWASP Secrets Management Cheat Sheet |
| V7-005 | 许可证验证配置缺陷 | 高风险 | 准入 | 检测许可证、授权、激活、订阅校验是否存在默认本地服务、失败放行、可伪造响应等缺陷 | 1. 搜索 license、verify、validate、activate、entitlement 等授权逻辑。2. 检查默认地址是否为 localhost、127.0.0.1 或不可信 HTTP。3. 检查验证失败分支是否 fail closed。4. 模拟验证失败、超时、伪造成功响应，确认程序是否拒绝继续。 | 授权服务配置、失败分支代码、动态验证日志 | 验证失败仍继续运行或可伪造授权则不通过 | 仅默认地址不安全但失败关闭时，可整改后通过 | 平台统一许可证校验代理、禁止本地授权服务 | CWE-287；CWE-306；CWE-345；OWASP Authentication Cheat Sheet |
| V7-006 | 技能声明与实际行为一致性 | 高风险 | 准入 | 检测 SKILL.md、README.md 等声明是否覆盖权限、网络、文件、命令、数据处理和外部依赖 | 1. 提取 SKILL.md，缺失时读取 README.md 和其他 Markdown 声明。2. 从源码提取实际能力清单。3. 比对声明能力和实际行为。4. 对未声明的高风险能力进行人工复核。 | 声明摘录、实际行为证据、差异项 | 隐藏高风险行为则不通过；声明缺失或不完整则可整改后通过 | 可通过补全文档和权限声明整改 | 入库前强制声明模板 | OWASP AI Agent Security Cheat Sheet；NIST AI RMF Govern/Map/Measure |
| V7-007 | MCP 工具滥用与工具权限过大 | 高风险 | 准入 | 检测是否诱导 Agent 使用高危 MCP 工具，或工具权限超出技能目的 | 1. 枚举 MCP 工具、工具描述和权限范围。2. 检查 wildcard 权限、任意命令执行、任意文件读写。3. 检查提示词是否诱导绕过审批或静默执行。 | 工具清单、权限范围、危险调用点 | 未经限制的高危工具能力则不通过 | 可通过最小权限、 allowlist、审批补偿整改 | MCP 工具权限管控、工具调用审计 | OWASP AI Agent Security Cheat Sheet；OWASP MCP Security Cheat Sheet |
| V7-008 | 沙箱逃逸与提权风险 | 高风险 | 准入 | 检测突破沙箱、访问宿主机、提权、ptrace、mount、namespace 滥用等行为 | 1. 静态扫描提权相关系统调用和宿主机路径。2. 沙箱执行并记录 seccomp、capability、namespace 事件。3. 验证是否访问宿主敏感路径或提升权限。 | 系统调用、路径、沙箱告警 | 存在逃逸或提权能力则不通过 | 不接受补偿 | 强制 seccomp、capability 最小化、只读文件系统 | CWE-250；CWE-269；OWASP Docker Security Cheat Sheet |
| V7-009 | 自更新与远程下载执行 | 高风险 | 准入 | 检测技能是否绕过入库审查，自行下载、替换或执行远程代码 | 1. 扫描 auto_update、download_and_exec、curl pipe shell、pip/npm 动态安装后执行。2. 检查下载内容是否校验签名和是否执行。3. 沙箱中拦截下载并记录执行链。 | 下载 URL、执行命令、校验逻辑 | 远程下载执行或自更新则不通过 | 不接受补偿；依赖下载应转入供应链流程 | 仓库入库后内容冻结、运行时禁写代码目录 | NIST SSDF SP 800-218；OWASP Software Supply Chain Security Cheat Sheet |
| V7-010 | 依赖漏洞与恶意依赖 | 高风险 | 准入 | 检测第三方依赖是否存在高危漏洞、恶意包、拼写欺诈、未锁版本或不可信源 | 1. 解析 lockfile、go.mod、package.json、requirements。2. 匹配 OSV、NVD、GitHub Advisory 等漏洞库。3. 检查包名相似度、维护状态和下载源。4. 验证是否锁定版本和校验哈希。 | 依赖名、版本、漏洞编号、来源 URL、修复版本 | 可利用高危漏洞或恶意依赖则不通过；可升级漏洞则可整改后通过 | 临时虚拟补丁只适合作为短期例外 | 私有源代理、依赖准入、漏洞告警 | OWASP LLM Top 10 LLM05；NIST SSDF SP 800-218；OpenSSF Scorecard |
| V7-011 | 动态指令注入与可执行上下文拼接 | 高风险 | 准入 | 检测用户输入、外部文档或工具响应是否进入 Prompt、Shell、SQL、eval、模板等可执行上下文 | 1. 标记不可信输入源。2. 追踪到 LLM prompt、exec、eval、SQL、shell、模板渲染等 sink。3. 检查是否使用参数化、边界分隔、转义和白名单。4. 用对抗样本验证绕过。 | 源点、sink 点、拼接路径、防护证据 | 无防护进入高危执行上下文则不通过 | 参数化、安全 API、隔离上下文可整改 | 网关输入校验、Prompt 注入护栏 | OWASP LLM Top 10 LLM01；OWASP LLM Prompt Injection Prevention Cheat Sheet；CWE-94；CWE-89；CWE-78 |
| V7-012 | 权限声明与最小权限 | 高风险 | 准入 | 检测声明权限是否超过功能所需，读写、网络、命令、文件权限是否可细粒度约束 | 1. 解析权限声明。2. 从源码提取实际权限使用。3. 对比“声明权限、实际使用、功能需要”。4. 标记未使用的敏感权限和过宽路径。 | 权限差异清单、调用证据 | 过度申请敏感权限且无合理理由则不通过 | 可通过缩小权限范围整改 | 运行时强制最小权限 | OWASP AI Agent Security Cheat Sheet；NIST SP 800-53 Rev.5 AC-6 |
| V7-013 | 路径遍历与文件越权 | 高风险 | 准入 | 检测文件读写是否可通过路径拼接越权访问工作区外文件或敏感路径 | 1. 追踪用户输入到文件路径 API。2. 检查 filepath clean、realpath、根目录边界校验。3. 使用 ../、绝对路径、编码路径测试。 | 输入样本、目标路径、越权证据 | 可越权读写敏感文件则不通过 | 可通过路径规范化和边界校验整改 | 文件系统沙箱 | CWE-22；OWASP Path Traversal；OWASP File System Security guidance |
| V7-014 | SSRF 与内网探测 | 高风险 | 准入 | 检测外部 URL 请求是否可访问内网、metadata、localhost 或绕过 DNS/IP 校验 | 1. 查找 HTTP client、URL fetch、Webhook、代理转发。2. 检查 allowlist、私网 IP、重定向、DNS rebinding 防护。3. 使用 127.0.0.1、169.254.169.254、私网网段和重定向样本测试。 | 请求点、目标地址、绕过样本 | 可访问内网或 metadata 服务则不通过 | 严格 allowlist 可整改 | 出口代理、私网地址拦截 | CWE-918；OWASP Server Side Request Forgery Prevention Cheat Sheet |
| V7-015 | 工具响应投毒与间接提示注入 | 中风险 | 准入 | 检测 MCP/API/网页/文档返回内容是否被当作指令注入 Agent 上下文 | 1. 查找外部响应进入 prompt 或 memory 的路径。2. 检查是否标记为不可信数据并做隔离。3. 用恶意响应样本验证是否改变工具调用或系统指令。 | 外部响应样本、上下文拼接点、绕过结果 | 可诱导高危工具调用则不通过；普通污染风险需人工复核 | 隔离上下文、摘要前置、响应清洗可整改 | 上下文注入防护、工具响应网关 | OWASP AI Agent Security Cheat Sheet；OWASP LLM Top 10 LLM01 |
| V7-016 | 凭据缓存与跨任务隔离 | 中风险 | 准入 | 检测是否明文缓存用户凭据、复用跨用户会话、长期保存 token 或共享全局状态 | 1. 搜索 credential、token、session、cache、global state。2. 检查加密、TTL、作用域、用户隔离。3. 构造两个会话验证是否串数据。 | 缓存位置、TTL、隔离机制、复现实验 | 跨用户泄露或明文长期保存敏感凭据则不通过 | 加密、TTL、按用户命名空间可整改 | 会话隔离、凭据托管 | OWASP AI Agent Security Cheat Sheet；CWE-522；CWE-613 |
| V7-017 | 敏感上下文与错误信息泄露 | 中风险 | 准入 | 检测系统提示词、密钥、内部路径、堆栈、环境变量是否输出给用户或日志 | 1. 扫描 print、logger、错误处理、响应构造。2. 触发异常路径并观察输出。3. 检查脱敏和错误模板。 | 输出样本、日志样本、泄露字段 | 直接泄露密钥或系统提示词则不通过；泄露路径或堆栈可整改 | 脱敏和统一错误处理可整改 | 日志脱敏、响应过滤 | OWASP LLM Top 10 LLM06；CWE-209；CWE-532 |
| V7-018 | 外部软依赖完整性 | 中风险 | 准入 | 检测外部 Prompt 模板、规则库、知识库、MCP 工具描述、远程配置是否可被替换或投毒 | 1. 枚举运行时加载的远程资源。2. 检查来源 allowlist、签名、哈希、版本固定。3. 模拟资源被篡改后的行为。 | 远程资源清单、完整性校验证据 | 可被替换并改变安全行为则不通过；缺少校验可整改 | 签名、哈希、版本锁定 | 平台托管模板和工具描述 | OWASP AI Agent Security Cheat Sheet；NIST SSDF SP 800-218；SLSA Framework |
| V7-019 | 不可逆或高影响操作审批 | 中风险 | 准入 | 检测删除、支付、发信、提交代码、修改权限等高影响操作是否有人审、预览和取消机制 | 1. 枚举高影响工具调用。2. 检查执行前是否生成预览。3. 检查是否需要明确确认。4. 验证拒绝或超时后不会执行。 | 操作类型、审批流程、失败分支证据 | 高影响操作无审批且可直接执行则不通过 | 增加 HITL、预览和回滚说明可整改 | 平台统一审批网关 | OWASP AI Agent Security Cheat Sheet；NIST AI RMF Govern/Manage |
| V7-020 | 输入 Schema 与边界校验 | 中风险 | 准入 | 检测工具接口是否定义类型、长度、格式、枚举、范围和必填约束 | 1. 枚举工具入口和 API handler。2. 检查 JSON Schema、Pydantic、Zod、validator 等。3. 使用空值、超长、非法类型、边界值测试。 | 接口清单、Schema、边界测试结果 | 高危工具缺少输入校验则需人工复核或整改 | 补充 Schema 和服务端校验可整改 | 网关输入校验 | OWASP Input Validation Cheat Sheet；CWE-20 |
| V7-021 | 日志审计与敏感信息脱敏 | 低风险 | 准入 | 检测是否记录关键安全事件，且日志不会明文写入凭据、个人信息和系统提示词 | 1. 查找安全相关操作的日志点。2. 检查敏感字段脱敏。3. 触发失败、拒绝、审批、外联等路径验证日志。 | 日志字段、脱敏样本、覆盖路径 | 明文记录凭据则不通过；审计不足可整改 | 补充审计和脱敏可整改 | 平台统一日志采集和脱敏 | OWASP Logging Cheat Sheet；CWE-532；NIST SP 800-92 |
| V7-022 | SBOM、版本锁定与来源可信 | 中风险 | 准入 | 检测是否提供依赖清单、锁文件、来源和可复现安装依据 | 1. 检查 SBOM、lockfile、go.sum、package-lock、requirements hash。2. 核对依赖是否覆盖实际使用。3. 检查依赖源是否可信且版本固定。 | SBOM 或 lockfile、依赖差异、来源 URL | 高权限技能缺少依赖清单需人工复核；普通缺失可整改 | 补交 SBOM 和锁文件可整改 | 私有源代理、依赖缓存 | NTIA SBOM Minimum Elements；OWASP Dependency Graph SBOM Cheat Sheet；NIST SSDF SP 800-218 |
| V7-023 | TLS 证书和传输保护 | 高风险 | 准入 | 检测网络请求是否关闭 TLS 校验、使用明文传输敏感数据或接受任意证书 | 1. 扫描 verify=false、InsecureSkipVerify、rejectUnauthorized=false。2. 检查敏感数据请求是否使用 HTTPS。3. 验证证书错误时是否失败关闭。 | 代码位置、请求目标、TLS 配置 | 生产路径关闭证书校验或明文传敏感数据则不通过 | 测试环境例外必须隔离且有声明 | 网关强制 TLS 和证书校验 | CWE-295；OWASP Transport Layer Security Cheat Sheet |
| V7-024 | 文件上传和文件解析安全 | 高风险 | 准入 | 检测上传、解压、解析文件是否存在类型绕过、Zip Slip、恶意脚本或越权写入 | 1. 检查文件类型、大小、后缀和 MIME 校验。2. 测试 Zip Slip、双后缀、超大文件、恶意内容。3. 检查解压路径边界和解析沙箱。 | 上传入口、测试样本、越权路径 | 可写出工作区或执行上传内容则不通过 | 类型白名单、大小限制、沙箱解析可整改 | 文件扫描沙箱、配额限制 | OWASP File Upload Cheat Sheet；CWE-434；CWE-22 |
| V7-025 | 隐私合规与数据最小化 | 高风险 | 准入 | 检测个人信息、敏感数据收集是否有声明、最小化、用途限制和保留策略 | 1. 提取声明中的数据类型和用途。2. 从代码中提取实际收集和外发的数据类型。3. 比对是否超范围收集。4. 检查保留、删除和脱敏策略。 | 数据类型清单、声明摘录、处理路径 | 过度收集敏感个人信息且无合理用途则不通过 | 补充最小化、脱敏、删除策略可整改 | 数据分类、DLP、审计 | NIST AI RMF；OWASP AI Agent Security Cheat Sheet；《个人信息保护法》 |
| V7-026 | 资源耗尽与级联失败 | 中风险 | 准入 | 检测无限循环、递归、无超时网络请求、无配额模型调用、错误级联传播 | 1. 扫描循环、递归、重试、网络请求和模型调用。2. 检查 timeout、retry cap、circuit breaker、quota。3. 故障注入模拟超时和下游失败。 | 超时配置、配额、故障注入日志 | 可造成不可控资源耗尽则不通过；缺少局部限流可整改 | 超时、限流、熔断可整改 | 平台配额、限流、熔断 | OWASP AI Agent Security Cheat Sheet；CWE-400 |
| V7-027 | 记忆与上下文污染 | 中风险 | 准入 | 检测是否将不可信输入写入长期记忆、向量库或跨会话上下文，且缺少来源标记和隔离 | 1. 查找 memory、vector store、cache、conversation history 写入点。2. 检查用户隔离、TTL、来源标记和敏感内容扫描。3. 用恶意记忆验证后续会话是否被影响。 | 写入点、隔离策略、污染复现 | 跨用户污染或恶意记忆可影响高危操作则不通过 | 命名空间、TTL、来源标记、写入审核可整改 | 记忆隔离和污染扫描 | OWASP AI Agent Security Cheat Sheet |
| V7-028 | 不安全反序列化和模型文件加载 | 高风险 | 准入 | 检测 pickle、torch.load、joblib、yaml.load 等不可信模型或数据文件加载 | 1. 扫描危险反序列化 API。2. 检查模型文件来源、签名和格式。3. 使用恶意样本验证是否执行代码。 | API 位置、文件来源、签名证据 | 不可信反序列化可执行代码则不通过 | 使用安全格式和签名校验可整改 | 模型文件扫描沙箱 | CWE-502；OWASP Deserialization Cheat Sheet；OWASP Secure AI Model Ops Cheat Sheet |
| V7-029 | 隐藏内容、混淆与诱导性描述 | 低风险 | 准入 | 检测 Unicode 方向覆盖、高熵混淆、Base64 隐藏指令、破解版/0day 等诱导性描述 | 1. 扫描 Unicode 控制字符、高熵块、Base64/压缩字符串。2. 解码后复核是否含恶意指令。3. 检查技能名称和描述是否含诱导性高危词。 | 命中内容、解码结果、描述片段 | 隐藏恶意指令按对应高风险项处理；仅诱导性描述可整改 | 清理混淆和修改描述可整改 | 入库描述审核 | OWASP AI Agent Security Cheat Sheet；CWE-451；CWE-506 |
| V7-030 | 调试接口与测试后门残留 | 中风险 | 准入 | 检测未鉴权调试路由、测试开关、开发模式和诊断接口是否可在生产路径触发 | 1. 扫描 debug、test_backdoor、diagnostic、/debug、dev mode。2. 检查是否仅测试环境可达。3. 动态访问调试入口验证鉴权。 | 路由或开关位置、触发方式、鉴权证据 | 未鉴权调试入口或特权接口则不通过 | 移除或仅测试环境编译可整改 | 网关禁止调试路径 | CWE-489；CWE-306 |

## 被移出准入核心表的项目

| 原 V6 项目 | 处理方式 | 原因 |
| --- | --- | --- |
| 内容安全与输出审核检测 | 移到网关场景 | 主要属于生成内容输出审核，不是技能入库前静态准入的核心能力 |
| 红队对抗测试评估 | 改为高风险技能附加流程 | 不是所有技能的常规准入项，适合作为人工复核或专项测试条件 |
| Hook Point覆盖度评估 | 移到平台能力评估 | Hook 覆盖度主要评价平台可治理性，不应作为单个技能入库必备项 |
| 跨技能安全通信检测 | 移到使用场景 | 多技能组合风险需要项目组使用多个技能时按链路评估 |
| 依赖安全更新订阅检测 | 移到运营阶段 | 订阅更新是持续运营要求，准入阶段只要求依赖清单、锁定版本和漏洞处置 |

## 信息来源清单

| 来源编号 | 来源 | URL | 适用说明 |
| --- | --- | --- | --- |
| SRC-OWASP-AGENT | OWASP AI Agent Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html | Agent 工具权限、记忆隔离、HITL、监控、多 Agent、安全数据处理 |
| SRC-OWASP-LLM | OWASP Top 10 for Large Language Model Applications / GenAI Security Project | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Prompt Injection、敏感信息泄露、供应链、过度代理等 LLM 应用风险 |
| SRC-OWASP-MCP | OWASP MCP Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html | MCP 工具、工具描述、权限与信任边界 |
| SRC-OWASP-PROMPT | OWASP LLM Prompt Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html | Prompt 注入与间接提示注入防护 |
| SRC-CWE | MITRE CWE | https://cwe.mitre.org/data/index.html | 通用软件弱点，包括硬编码凭证、路径遍历、SSRF、反序列化、资源耗尽等 |
| SRC-NIST-AI-RMF | NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework | AI 风险治理、映射、度量和管理 |
| SRC-NIST-SSDF | NIST SP 800-218 Secure Software Development Framework | https://csrc.nist.gov/publications/detail/sp/800-218/final | 安全开发、供应链、发布完整性 |
| SRC-NIST-800-53 | NIST SP 800-53 Rev.5 | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final | 访问控制、最小权限、审计控制 |
| SRC-NTIA-SBOM | NTIA Minimum Elements for a Software Bill of Materials | https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom | SBOM 最小元素 |
| SRC-OWASP-FILE | OWASP File Upload Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | 文件上传和文件解析安全 |
| SRC-OWASP-SSRF | OWASP SSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html | SSRF 防护 |
| SRC-OWASP-LOGGING | OWASP Logging Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | 安全日志和敏感日志脱敏 |
| SRC-OWASP-TLS | OWASP Transport Layer Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html | TLS 配置与证书校验 |
| SRC-OWASP-DESER | OWASP Deserialization Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html | 不安全反序列化 |
| SRC-PIPL | 中华人民共和国个人信息保护法 | https://www.gov.cn/xinwen/2021-08/20/content_5632486.htm | 个人信息处理、最小必要、告知同意和合规要求 |
