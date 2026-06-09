package handler

import (
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBatchSkillStructuredFindingMatrix(t *testing.T) {
	tests := []struct {
		name                   string
		findings               []plugins.Finding
		refined                review.Result
		want                   structuredExpectation
	}{
		{
			name: "真实风险-未声明远程诊断控制",
			findings: []plugins.Finding{batchFinding("SecurityEngine", "V7-006", "高风险", "破坏性操作需复核", "声明仅提及读取车辆状态，但代码包含 ECU 写入和例程控制。", "ecu_control.py:2", "ecu.write_data_by_identifier('0xF190', firmware)")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "undeclared"},
		},
		{
			name: "策略风险-禁用第三方车联网平台",
			findings: []plugins.Finding{batchFinding("ThreatIntel", "V7-003", "中风险", "命中黑名单目标（域名/IP）", "目标命中策略黑名单，需按平台准入策略处理。", "config.json:12", "目标证据: blacklisted-telematics.example.com\n判定依据: policy blacklist")},
			refined: review.Result{TIReputations: []review.TIReputation{{Target: "blacklisted-telematics.example.com", Reputation: "policy"}}},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "policy", declarationVerdict: "declared"},
		},
		{
			name: "边界待复核-交付提示下沉",
			findings: []plugins.Finding{batchFinding("SecurityEngine", "V7-006", "中风险", "声明与提供代码严重不一致", "声明承诺经销商诊断助手，但当前交付只有 README。", "README.md:1", "# Dealer Diagnostic Bot")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared", secondary: true},
		},
		{
			name: "环境构建风险-未锁依赖与bootstrap",
			findings: []plugins.Finding{batchFinding("Static", "V7-022", "中风险", "依赖来源未经验证", "售后诊断仪表板通过 requirements.txt 安装未锁依赖，存在供应链风险。", "bootstrap.sh:1", "pip3 install -r requirements.txt --break-system-packages")},
			want: structuredExpectation{category: "环境与构建风险", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "正常业务-车辆诊断读取结果",
			findings: []plugins.Finding{batchFinding("Static", "V7-006", "低风险", "网络访问需复核", "声明已覆盖诊断数据同步能力，代码仅访问厂内诊断接口，属于已声明网络访问。", "obd_reader.py:3", "requests.get('https://dealer-api.example.com/vehicles/status')")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "partially_declared"},
		},
		{
			name: "待复核-车机日志回传",
			findings: []plugins.Finding{batchFinding("Static", "V7-003", "中风险", "外联回传需复核", "车机日志通过 webhook 回传到售后平台，需要确认字段范围和授权边界。", "log_sync.py:2", "requests.post(webhook, json={'vin': vin, 'log_bundle': bundle_path})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "declared"},
		},
		{
			name: "正常业务-固定售后地址日志回传",
			findings: []plugins.Finding{batchFinding("Static", "V7-003", "低风险", "已声明外联回传", "日志仅回传到固定售后平台地址，当前证据落在已声明业务外联。", "log_sync.py:2", "requests.post('https://after-sales.example.com/logs', json={'vin': vin, 'log_bundle': bundle_path})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "partially_declared"},
		},
		{
			name: "待复核-用户可控日志上报目标",
			findings: []plugins.Finding{batchFinding("Static", "V7-003", "中风险", "用户可控外联目标", "上传目标来自请求体，需确认 allowlist、鉴权和字段范围。", "log_forward.py:2", "requests.post(target, json={'vin': vin, 'bundle': bundle_path})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "declared"},
		},
		{
			name: "策略风险-外联集成命中黑名单 webhook",
			findings: []plugins.Finding{batchFinding("ThreatIntel", "V7-003", "中风险", "命中黑名单目标（域名/IP）", "webhook 目标命中策略黑名单，需按平台准入策略处理。", "sync.py:2", "目标证据: blacklisted-ops-webhook.example.com\n判定依据: policy blacklist")},
			refined: review.Result{TIReputations: []review.TIReputation{{Target: "blacklisted-ops-webhook.example.com", Reputation: "policy"}}},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "policy", declarationVerdict: "declared"},
		},
		{
			name: "真实风险-产线刷写工具未声明高影响控制",
			findings: []plugins.Finding{batchFinding("SecurityEngine", "V7-006", "高风险", "破坏性操作需复核", "声明仅提及工位报表，但代码包含 ECU 下载、传输和例程控制。", "flash_ecu.py:1", "ecu.request_download('firmware.bin')")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "undeclared"},
		},
		{
			name: "真实风险-未鉴权诊断仪表板暴露",
			findings: []plugins.Finding{batchFinding("Static", "V7-021", "高风险", "缺乏身份验证的Web仪表盘", "经销商诊断仪表板绑定公网地址且缺少身份验证。", "dashboard.py:5", "app.run(host='0.0.0.0', port=8080)")},
			want: structuredExpectation{category: "暴露面与未鉴权服务", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "真实风险-通用管理后台公网暴露",
			findings: []plugins.Finding{batchFinding("Static", "V7-021", "高风险", "缺乏身份验证的Web仪表盘", "任务管理后台绑定公网地址且缺少身份验证。", "dashboard.py:5", "app.run(host='0.0.0.0', port=9000)")},
			want: structuredExpectation{category: "暴露面与未鉴权服务", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "正常业务-本地管理面",
			findings: []plugins.Finding{batchFinding("Static", "V7-021", "低风险", "本地管理面", "管理面仅绑定本地回环地址，当前证据落在本地运维入口。", "dashboard.py:5", "app.run(host='127.0.0.1', port=9000)")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "环境构建风险-远程安装脚本执行",
			findings: []plugins.Finding{batchFinding("Static", "V7-022", "中风险", "依赖来源未经验证", "bootstrap 脚本通过远程安装脚本拉取并执行依赖，存在供应链风险。", "bootstrap.sh:1", "curl -fsSL https://packages.example.com/install.sh | sh")},
			want: structuredExpectation{category: "环境与构建风险", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "正常业务-锁版本依赖构建链",
			findings: []plugins.Finding{batchFinding("Static", "V7-022", "低风险", "锁版本依赖", "requirements.txt 使用锁版本依赖，当前证据落在正常构建链。", "requirements.txt:1", "requests==2.32.3")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "正常业务-Agent 摘要工作流",
			findings: []plugins.Finding{batchFinding("Static", "V7-006", "低风险", "已声明摘要工作流", "技能声明已覆盖工单读取和摘要生成，当前证据落在普通 Agent 工作流。", "agent.py:2", "summary = llm.summarize(ticket)")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "真实风险-Agent 未声明命令执行",
			findings: []plugins.Finding{batchFinding("SecurityEngine", "V7-006", "高风险", "命令执行需复核", "声明仅提及摘要生成，但代码包含 shell 子进程执行。", "agent.py:3", "subprocess.run(cmd, shell=True)")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "undeclared"},
		},
		{
			name: "正常业务-已声明受控脚本执行",
			findings: []plugins.Finding{batchFinding("Static", "V7-006", "低风险", "已声明维护脚本执行", "技能声明已覆盖固定白名单脚本和命令执行，当前证据落在受控维护流程。", "runner.py:3", "subprocess.run(ALLOWED[name], check=True)")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "真实风险-系统工具未声明破坏性删除",
			findings: []plugins.Finding{batchFinding("SecurityEngine", "V7-006", "高风险", "破坏性操作需复核", "声明仅提及报告导出，但代码包含删除目录能力。", "cleanup.py:3", "shutil.rmtree(target)")},
			want: structuredExpectation{category: "声明与行为差异", securityVerdict: "review", declarationVerdict: "undeclared"},
		},
		{
			name: "正常业务-固定目标数据同步",
			findings: []plugins.Finding{batchFinding("Static", "V7-003", "低风险", "已声明业务同步", "工单摘要仅同步到固定 CRM API，当前证据落在已声明业务外联。", "sync.py:2", "requests.post(CRM_ENDPOINT, json={'ticket_id': ticket_id, 'summary': summary})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "declared"},
		},
		{
			name: "待复核-用户可控数据同步目标",
			findings: []plugins.Finding{batchFinding("Static", "V7-003", "中风险", "用户可控外联目标", "同步目标来自请求体，需确认 allowlist、鉴权和字段范围。", "sync.py:2", "requests.post(target, json={'ticket_id': ticket_id, 'summary': summary})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "declared"},
		},
		{
			name: "待复核-会话字段同步到固定目标",
			findings: []plugins.Finding{batchFinding("Static", "V7-019", "中风险", "数据最小化与收集边界", "检测到 session 字段随请求同步到固定审计 API，需确认字段必要性与会话保护边界。", "sync.py:2", "requests.post('https://audit.example.com/sessions', json={'session': session})")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "策略风险-数据同步命中黑名单 API",
			findings: []plugins.Finding{batchFinding("ThreatIntel", "V7-003", "中风险", "命中黑名单目标（域名/IP）", "审计同步 API 命中策略黑名单，需按平台准入策略处理。", "sync.py:2", "目标证据: blacklisted-sync.example.com\n判定依据: policy blacklist")},
			refined: review.Result{TIReputations: []review.TIReputation{{Target: "blacklisted-sync.example.com", Reputation: "policy"}}},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "policy", declarationVerdict: "declared"},
		},
		{
			name: "真实风险-凭据字段外发到日志服务",
			findings: []plugins.Finding{batchFinding("Static", "V7-019", "高风险", "数据最小化与收集边界", "检测到 api_key 被发送到日志服务，需立即移除凭据外发路径。", "sync.py:2", "requests.post('https://logs.example.com/ingest', json={'api_key': api_key})")},
			want: structuredExpectation{category: "外联与情报", securityVerdict: "confirmed", declarationVerdict: "declared"},
		},
		{
			name: "数据边界-车主手机号持久化",
			findings: []plugins.Finding{batchFinding("Static", "V7-019", "中风险", "数据最小化与收集边界", "检测到 owner_phone 被写入工单表，需确认保留周期与用途边界。", "work_order.py:4", "db.execute('insert into work_orders(owner_phone) values (?)', [owner_phone])")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "数据边界-经销商会话外发",
			findings: []plugins.Finding{batchFinding("Static", "V7-019", "中风险", "数据最小化与收集边界", "检测到 dealer_session 随请求同步到售后系统，需确认字段必要性与会话保护边界。", "sync.py:6", "requests.post('https://after-sales.example.com/sync', json={'dealer_session': dealer_session})")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
		{
			name: "数据边界-车主邮箱写日志",
			findings: []plugins.Finding{batchFinding("Static", "V7-019", "中风险", "数据最小化与收集边界", "检测到 owner email 被输出到日志，需确认脱敏与最小化策略。", "contact.py:3", "logger.info('owner email=%s', email)")},
			want: structuredExpectation{category: "静态规则发现", securityVerdict: "review", declarationVerdict: "declared"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			structured := buildStructuredFindings(tc.findings, tc.refined, nil, "", nil)
			assertStructuredFindingMatrix(t, tc.refined, structured, tc.want)
		})
	}
}
