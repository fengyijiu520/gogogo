package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type paragraphKind string

const (
	kindTitle   paragraphKind = "title"
	kindHeading paragraphKind = "heading"
	kindText    paragraphKind = "text"
	kindBullet  paragraphKind = "bullet"
	kindCode    paragraphKind = "code"
)

type paragraph struct {
	Kind paragraphKind
	Text string
}

func main() {
	out := filepath.Join(".", "SkillScanner_新服务器从零部署教程.docx")
	if err := writeDocx(out, deploymentGuide()); err != nil {
		fmt.Fprintf(os.Stderr, "生成 Word 文档失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func deploymentGuide() []paragraph {
	return []paragraph{
		{kindTitle, "Skill Scanner 新服务器从零部署教程"},
		{kindText, "适用对象：国内云服务器用户、Ubuntu 服务器、需要离线放置 ONNX Runtime、runsc/gVisor 与 BGE 模型文件的部署场景。"},
		{kindText, "生成日期：" + time.Now().Format("2006-01-02")},
		{kindHeading, "一、目标与最终效果"},
		{kindText, "本教程从一台全新的 Ubuntu 云服务器开始，指导完成 Skill Scanner 的运行环境准备、项目部署、离线工具文件安装、Docker gVisor 沙箱配置、ONNX Runtime 配置、BGE 模型放置、管理员初始密码设置、systemd 常驻服务配置和上线验证。"},
		{kindBullet, "最终 Web 服务监听 8880 端口。"},
		{kindBullet, "沙箱运行时使用 runsc/gVisor，而不是普通 runc。"},
		{kindBullet, "ONNX Runtime 动态库可被程序正常加载。"},
		{kindBullet, "BGE 模型文件 model.onnx 能被语义引擎加载。"},
		{kindBullet, "首次启动必须设置强管理员密码，不再使用 admin/admin。"},
		{kindBullet, "服务可通过 systemd 后台运行并开机自启。"},

		{kindHeading, "二、推荐服务器配置"},
		{kindText, "如果你已经迁移到新服务器，建议不要再使用 2 核 2G。完整能力包含 ONNX 语义引擎、Docker 沙箱、LLM 调用、报告生成，建议配置如下。"},
		{kindBullet, "最低建议：2 核 4G 内存，8G swap，并发 1。"},
		{kindBullet, "推荐稳定：4 核 8G 内存，8G swap。"},
		{kindBullet, "体验更好：4 核 16G 内存或以上。"},
		{kindBullet, "系统建议：Ubuntu 22.04 LTS 或 Ubuntu 24.04 LTS。"},
		{kindBullet, "磁盘建议：至少 40G，推荐 80G 以上。"},

		{kindHeading, "三、目录规划"},
		{kindText, "本教程假设你的项目源码保留在一个目录中，并在项目同级或项目内新建 tools 文件夹，存放离线文件。推荐目录如下。"},
		{kindCode, "/opt/skill-scanner/                 # 项目根目录\n/opt/skill-scanner/skill-scanner   # 编译后的主程序\n/opt/skill-scanner/models/          # 模型目录\n/opt/skill-scanner/data/            # 运行数据目录\n/opt/skill-scanner/tools/           # 离线工具文件目录"},
		{kindText, "tools 目录中需要放置这些文件。"},
		{kindCode, "tools/libonnxruntime.so\ntools/libonnxruntime.so.1\ntools/libonnxruntime.so.1.21.0\ntools/libonnxruntime.so.1.22.0\ntools/runsc\ntools/model.onnx"},
		{kindText, "如果 tokenizer.json 不在项目模型目录中，也需要一并准备。通常模型目录需要至少包含 model.onnx 和 tokenizer.json。"},

		{kindHeading, "四、服务器基础准备"},
		{kindText, "以下命令在新服务器上执行。国内云服务器建议优先使用云厂商默认 Ubuntu 镜像源或已配置好的国内镜像源。"},
		{kindCode, "apt-get update\nDEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl unzip tar git docker.io"},
		{kindText, "启动 Docker，并确认 Docker 可用。"},
		{kindCode, "systemctl start docker\nsystemctl status docker\ndocker version"},
		{kindText, "如果服务器没有 swap，建议添加 8G swap，避免模型加载期间内存峰值导致 OOM。"},
		{kindCode, "fallocate -l 8G /swapfile\nchmod 600 /swapfile\nmkswap /swapfile\nswapon /swapfile\ngrep -q '^/swapfile ' /etc/fstab || printf '\n/swapfile none swap sw 0 0\n' >> /etc/fstab\nfree -h"},

		{kindHeading, "五、上传项目源码和 tools 文件"},
		{kindText, "将当前项目源码上传到新服务器，例如 /opt/skill-scanner。然后在项目根目录新建 tools 文件夹，并把离线文件放入 tools。"},
		{kindCode, "mkdir -p /opt/skill-scanner/tools\ncd /opt/skill-scanner\nls -lh tools"},
		{kindText, "确认至少能看到以下文件。"},
		{kindCode, "libonnxruntime.so\nlibonnxruntime.so.1\nlibonnxruntime.so.1.21.0\nlibonnxruntime.so.1.22.0\nrunsc\nmodel.onnx"},

		{kindHeading, "六、安装 ONNX Runtime 动态库"},
		{kindText, "程序默认从 /usr/local/lib/libonnxruntime.so 加载 ONNX Runtime。将 tools 中的动态库复制到 /usr/local/lib，并刷新动态链接缓存。"},
		{kindCode, "cp /opt/skill-scanner/tools/libonnxruntime.so* /usr/local/lib/\nldconfig\nls -l /usr/local/lib/libonnxruntime.so*"},
		{kindText, "如果你不想复制到 /usr/local/lib，也可以用环境变量指定路径。"},
		{kindCode, "export SKILL_SCANNER_ONNX_RUNTIME_LIB=/opt/skill-scanner/tools/libonnxruntime.so"},

		{kindHeading, "七、安装 runsc 并配置 Docker gVisor 运行时"},
		{kindText, "runsc 是 gVisor 的运行时。生产部署建议使用 runsc，而不是普通 runc，以降低被扫描技能影响宿主机的风险。"},
		{kindCode, "cp /opt/skill-scanner/tools/runsc /usr/local/bin/runsc\nchmod 0755 /usr/local/bin/runsc\nrunsc --version"},
		{kindText, "配置 Docker runtime。编辑 /etc/docker/daemon.json，如果文件不存在就创建。"},
		{kindCode, "mkdir -p /etc/docker\ncat > /etc/docker/daemon.json <<'EOF'\n{\n  \"runtimes\": {\n    \"runsc\": {\n      \"path\": \"/usr/local/bin/runsc\",\n      \"runtimeArgs\": []\n    }\n  }\n}\nEOF\nsystemctl restart docker"},
		{kindText, "验证 Docker 已识别 runsc。"},
		{kindCode, "docker info --format '{{range $name, $_ := .Runtimes}}{{$name}}{{\"\\n\"}}{{end}}'"},
		{kindText, "输出中应包含 runsc。"},

		{kindHeading, "八、准备沙箱镜像"},
		{kindText, "程序使用 ZeroClaw 沙箱，镜像名为 zeroclaw-sandbox。进入 zeroclaw 目录构建镜像。"},
		{kindCode, "cd /opt/skill-scanner/zeroclaw\ndocker build -t zeroclaw-sandbox .\ndocker images | grep zeroclaw-sandbox"},
		{kindText, "验证沙箱能启动。"},
		{kindCode, "docker run --rm zeroclaw-sandbox echo ok"},

		{kindHeading, "九、准备 BGE 模型目录"},
		{kindText, "默认模型目录为 models/bge-large-zh-v1.5。将 tools/model.onnx 放到该目录，并确认 tokenizer.json 存在。"},
		{kindCode, "mkdir -p /opt/skill-scanner/models/bge-large-zh-v1.5\ncp /opt/skill-scanner/tools/model.onnx /opt/skill-scanner/models/bge-large-zh-v1.5/model.onnx\nls -lh /opt/skill-scanner/models/bge-large-zh-v1.5/model.onnx\nls -lh /opt/skill-scanner/models/bge-large-zh-v1.5/tokenizer.json"},
		{kindText, "如果 tokenizer.json 不存在，需要从旧服务器同名模型目录复制。没有 tokenizer.json 时，模型通常无法正常分词和推理。"},
		{kindText, "也可以使用环境变量指定模型目录。"},
		{kindCode, "export SKILL_SCANNER_BGE_MODEL_DIR=/opt/skill-scanner/models/bge-large-zh-v1.5"},

		{kindHeading, "十、编译或放置主程序"},
		{kindText, "如果新服务器有 Go 环境，可以在项目根目录编译。"},
		{kindCode, "cd /opt/skill-scanner\ngo build -o skill-scanner ./cmd/server"},
		{kindText, "如果你已经从旧服务器复制了编译好的 skill-scanner，可直接放到 /opt/skill-scanner/skill-scanner，并赋予执行权限。"},
		{kindCode, "chmod 0755 /opt/skill-scanner/skill-scanner\n/opt/skill-scanner/skill-scanner"},
		{kindText, "只运行程序不带 web 参数时，应输出用法提示。正式启动需要加 web。"},

		{kindHeading, "十一、首次启动必须设置管理员密码"},
		{kindText, "为了防止公网部署后被 admin/admin 弱口令登录，当前版本首次创建 admin 用户时必须设置环境变量 SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD，且长度至少 12 位。"},
		{kindCode, "cd /opt/skill-scanner\nSKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD='请替换为至少12位强密码' \\\nSKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER=1 \\\nSKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL=1 \\\n./skill-scanner web"},
		{kindText, "启动成功后应看到 Web 服务启动日志，例如：http://:8880。实际访问时使用服务器公网 IP 或域名加端口。"},
		{kindCode, "http://服务器公网IP:8880"},
		{kindText, "如果 data/users.json 已存在，SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD 不会覆盖已有 admin 密码。忘记密码时使用 devreset，并设置 SKILL_SCANNER_RESET_ADMIN_PASSWORD。"},

		{kindHeading, "十二、systemd 后台运行配置"},
		{kindText, "建议使用 systemd 管理服务，避免 SSH 断开后进程退出。创建 /etc/systemd/system/skill-scanner.service。"},
		{kindCode, "cat > /etc/systemd/system/skill-scanner.service <<'EOF'\n[Unit]\nDescription=Skill Scanner\nAfter=docker.service\nRequires=docker.service\n\n[Service]\nType=simple\nWorkingDirectory=/opt/skill-scanner\nExecStart=/opt/skill-scanner/skill-scanner web\nRestart=always\nRestartSec=5\nProtectKernelModules=yes\nProtectKernelLogs=yes\nMemoryDenyWriteExecute=yes\n\nEnvironment=SKILL_SCANNER_LISTEN_ADDR=:8880\nEnvironment=SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD=请替换为至少12位强密码\nEnvironment=SKILL_SCANNER_ONNX_RUNTIME_LIB=/usr/local/lib/libonnxruntime.so\nEnvironment=SKILL_SCANNER_BGE_MODEL_DIR=/opt/skill-scanner/models/bge-large-zh-v1.5\nEnvironment=REVIEW_ENABLE_SANDBOX=true\nEnvironment=REVIEW_SANDBOX_IMAGE=zeroclaw-sandbox\nEnvironment=SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER=1\nEnvironment=SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL=1\n\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl enable skill-scanner\nsystemctl start skill-scanner\nsystemctl status skill-scanner"},
		{kindText, "查看服务日志。"},
		{kindCode, "journalctl -u skill-scanner -n 100 --no-pager"},

		{kindHeading, "十三、上线验证清单"},
		{kindText, "启动后按以下顺序验证。"},
		{kindCode, "ss -lntp | grep 8880\nfree -h\ndocker run --rm zeroclaw-sandbox echo ok\nls -lh /usr/local/lib/libonnxruntime.so\nls -lh /opt/skill-scanner/models/bge-large-zh-v1.5/model.onnx"},
		{kindText, "登录 Web 页面后，系统启动自检应显示：规则配置正常、沙箱正常、语义引擎正常、LLM 正常或按用户配置校验。"},

		{kindHeading, "十四、国内环境注意事项"},
		{kindBullet, "不要依赖服务器直接访问 storage.googleapis.com 下载 runsc，国内网络通常较慢或不稳定。"},
		{kindBullet, "推荐把 ONNX Runtime、model.onnx、tokenizer.json、zeroclaw-sandbox 镜像包从旧服务器复制到新服务器。"},
		{kindBullet, "Docker 镜像建议使用离线 tar 包导入，避免拉取失败。"},
		{kindBullet, "如果使用云服务器安全组，只开放必要端口，例如 22 和 8880。生产环境建议只允许固定办公 IP 访问 8880。"},
		{kindBullet, "如果使用域名和 HTTPS，建议通过 Nginx 反代到 127.0.0.1:8880，并设置 X-Forwarded-Proto: https。"},

		{kindHeading, "十五、Nginx HTTPS 反代示例"},
		{kindText, "如果你使用 Nginx 反代，建议让 Skill Scanner 只监听本地地址。systemd 中设置：SKILL_SCANNER_LISTEN_ADDR=127.0.0.1:8880。Nginx 示例配置如下。"},
		{kindCode, "server {\n    listen 443 ssl http2;\n    server_name scanner.example.com;\n\n    ssl_certificate /path/to/fullchain.pem;\n    ssl_certificate_key /path/to/privkey.pem;\n\n    client_max_body_size 120m;\n\n    location / {\n        proxy_pass http://127.0.0.1:8880;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n    }\n}"},

		{kindHeading, "十六、常见问题排查"},
		{kindText, "问题 1：启动报 libonnxruntime.so not found。"},
		{kindCode, "cp /opt/skill-scanner/tools/libonnxruntime.so* /usr/local/lib/\nldconfig\nls -l /usr/local/lib/libonnxruntime.so"},
		{kindText, "问题 2：沙箱提示 runsc 不可用。"},
		{kindCode, "command -v runsc\nrunsc --version\ndocker info --format '{{range $name, $_ := .Runtimes}}{{$name}}{{\"\\n\"}}{{end}}'"},
		{kindText, "问题 3：docker run --runtime=runsc 失败。"},
		{kindCode, "systemctl restart docker\ndocker run --rm zeroclaw-sandbox echo ok"},
		{kindText, "问题 4：启动时被 Killed。通常是内存不足或 swap 不足。"},
		{kindCode, "free -h\ndmesg -T | grep -i -E 'killed process|out of memory|oom' | tail -20"},
		{kindText, "问题 5：浏览器打不开 8880。检查服务监听、安全组、防火墙。"},
		{kindCode, "ss -lntp | grep 8880\nsystemctl status skill-scanner\njournalctl -u skill-scanner -n 100 --no-pager"},
		{kindText, "问题 6：登录失败。确认首次启动密码来自 SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD；如果 data/users.json 已存在，该变量不会覆盖旧密码。"},
		{kindCode, "SKILL_SCANNER_RESET_ADMIN_PASSWORD='新的至少12位强密码' /opt/skill-scanner/devreset"},

		{kindHeading, "十七、性能建议"},
		{kindBullet, "不要上传 node_modules、.git、dist、build、vendor、venv、__pycache__ 等目录。"},
		{kindBullet, "生产默认并发建议先设置为 1，确认资源充足后再提高。"},
		{kindBullet, "如果扫描很慢，优先观察 CPU、内存、swap 和 Docker 容器运行情况。"},
		{kindBullet, "大模型 model.onnx 会占用较多内存，4G 以下机器不建议完整开启。"},
		{kindBullet, "如果需要更快体验，可准备更小的 BGE ONNX 模型，并通过 SKILL_SCANNER_BGE_MODEL_DIR 指定。"},

		{kindHeading, "十八、安全建议"},
		{kindBullet, "首次启动必须使用强密码，不要使用 admin/admin。"},
		{kindBullet, "公网部署建议限制安全组来源 IP。"},
		{kindBullet, "建议启用 HTTPS 反代，并传递 X-Forwarded-Proto: https，使 Cookie 使用 Secure。"},
		{kindBullet, "保留 runsc/gVisor 沙箱，不要为了省事改回 runc。"},
		{kindBullet, "定期备份 /opt/skill-scanner/data。"},
		{kindBullet, "不要把 LLM API Key 写入 shell 历史或公开文档，优先在 Web 个人中心配置。"},

		{kindHeading, "十九、最终启动命令速查"},
		{kindCode, "cd /opt/skill-scanner\nSKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD='请替换为至少12位强密码' \\\nSKILL_SCANNER_ONNX_RUNTIME_LIB=/usr/local/lib/libonnxruntime.so \\\nSKILL_SCANNER_BGE_MODEL_DIR=/opt/skill-scanner/models/bge-large-zh-v1.5 \\\nREVIEW_ENABLE_SANDBOX=true \\\nREVIEW_SANDBOX_IMAGE=zeroclaw-sandbox \\\nSKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER=1 \\\nSKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL=1 \\\n./skill-scanner web"},
	}
}

func writeDocx(path string, paragraphs []paragraph) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	files := map[string]string{
		"[Content_Types].xml":          contentTypesXML,
		"_rels/.rels":                  relsXML,
		"word/_rels/document.xml.rels": docRelsXML,
		"word/styles.xml":              stylesXML,
		"word/settings.xml":            settingsXML,
		"word/document.xml":            documentXML(paragraphs),
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(body)); err != nil {
			return err
		}
	}
	return nil
}

func documentXML(paragraphs []paragraph) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, p := range paragraphs {
		b.WriteString(paragraphXML(p))
	}
	b.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>`)
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

func paragraphXML(p paragraph) string {
	style := "Normal"
	size := "24"
	bold := ""
	color := "111827"
	indent := ""
	spacing := `<w:spacing w:after="160" w:line="276" w:lineRule="auto"/>`
	splitLines := false
	switch p.Kind {
	case kindTitle:
		style = "Title"
		size = "36"
		bold = `<w:b/>`
		color = "0F172A"
		spacing = `<w:spacing w:after="300"/>`
	case kindHeading:
		style = "Heading1"
		size = "30"
		bold = `<w:b/>`
		color = "1D4ED8"
		spacing = `<w:spacing w:before="360" w:after="180"/>`
	case kindBullet:
		indent = `<w:ind w:left="420" w:hanging="220"/>`
		p.Text = "• " + p.Text
	case kindCode:
		size = "20"
		color = "374151"
		spacing = `<w:spacing w:before="80" w:after="180"/>`
		splitLines = true
	}

	var b strings.Builder
	b.WriteString(`<w:p><w:pPr><w:pStyle w:val="` + style + `"/>` + spacing + indent + `</w:pPr>`)
	if splitLines {
		lines := strings.Split(p.Text, "\n")
		for i, line := range lines {
			if i > 0 {
				b.WriteString(`<w:r><w:br/></w:r>`)
			}
			b.WriteString(runXML(line, size, bold, color, p.Kind == kindCode))
		}
	} else {
		b.WriteString(runXML(p.Text, size, bold, color, false))
	}
	b.WriteString(`</w:p>`)
	return b.String()
}

func runXML(text, size, bold, color string, mono bool) string {
	font := `w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Microsoft YaHei"`
	if mono {
		font = `w:ascii="Courier New" w:hAnsi="Courier New" w:eastAsia="Microsoft YaHei"`
	}
	return `<w:r><w:rPr>` + bold + `<w:rFonts ` + font + `/><w:color w:val="` + color + `"/><w:sz w:val="` + size + `"/><w:szCs w:val="` + size + `"/></w:rPr><w:t xml:space="preserve">` + escape(text) + `</w:t></w:r>`
}

func escape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

const docRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Microsoft YaHei"/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/></w:style>
</w:styles>`

const settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:defaultTabStop w:val="720"/></w:settings>`
