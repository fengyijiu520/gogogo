// Package templates holds all HTML template strings for the skill scanner web UI.
package templates

// LoginHTML is the login page template.
const LoginHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
        h1 { text-align: center; color: #333; margin-bottom: 30px; font-size: 28px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        .error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: 600; cursor: pointer; transition: transform 0.2s; margin-bottom: 10px; }
        button:hover { transform: translateY(-2px); }
        .link-btn { background: none; color: #667eea; font-size: 14px; }
        .info { text-align: center; margin-top: 20px; color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 技能扫描器</h1>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="请输入用户名" required>
            </div>
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="请输入密码" required>
            </div>
            <button type="submit">登 录</button>
        </form>
        <form method="GET" action="/change-password">
            <button type="submit" class="link-btn">修改密码</button>
        </form>
        <div class="info">当前开发环境默认账号: admin / admin</div>
    </div>
</body>
</html>
`

// ChangePasswordHTML is the change password page template.
const ChangePasswordHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>修改密码 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
        h1 { text-align: center; color: #333; margin-bottom: 30px; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        .error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        .success { background: #efe; color: #060; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        .back-btn { display: block; text-align: center; margin-top: 15px; color: #667eea; text-decoration: none; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 修改密码</h1>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        {{if .Success}}<div class="success">{{.Success}}</div>{{end}}
        <form method="POST" action="/change-password">
            <div class="form-group">
                <label for="old_password">当前密码</label>
                <input type="password" id="old_password" name="old_password" placeholder="请输入当前密码" required>
            </div>
            <div class="form-group">
                <label for="new_password">新密码</label>
                <input type="password" id="new_password" name="new_password" placeholder="请输入新密码" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">确认新密码</label>
                <input type="password" id="confirm_password" name="confirm_password" placeholder="请再次输入新密码" required>
            </div>
            <button type="submit">确认修改</button>
        </form>
        <a href="/dashboard" class="back-btn">返回仪表盘</a>
    </div>
</body>
</html>
`

// DashboardHTML is the main dashboard template.
const DashboardHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>仪表盘 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-btn .arrow { font-size: 10px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .welcome { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 30px; }
        .welcome h2 { color: #333; margin-bottom: 10px; }
        .welcome p { color: #666; line-height: 1.6; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); transition: transform 0.2s, box-shadow 0.2s; text-align: center; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .card h3 { color: #333; margin-bottom: 12px; font-size: 18px; }
        .card p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 20px; }
        .card .icon { font-size: 48px; margin-bottom: 14px; }
        .card-btn { display: inline-block; padding: 12px 28px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; transition: transform 0.2s; }
        .card-btn:hover { transform: translateY(-2px); }
        .section-title { color: #333; font-size: 20px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #667eea; margin-top: 40px; }
        .report-list { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .report-item { padding: 16px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }
        .task-item { padding: 14px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #fafcff; }
        .task-item:last-child { border-bottom: 1px solid #eee; }
        .report-item:last-child { border-bottom: none; }
        .report-item .info { flex: 1; }
        .report-item .filename { color: #333; font-weight: 500; }
        .report-item .meta { color: #888; font-size: 13px; margin-top: 4px; font-variant-numeric: tabular-nums; }
        .report-item .badges { display: flex; gap: 8px; margin-top: 6px; flex-wrap: wrap; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.high { background: #fee; color: #c00; }
        .badge.medium { background: #ffc; color: #a60; }
        .badge.low { background: #efe; color: #060; }
        .badge.ok { background: #eef; color: #06c; }
        .report-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .download-btn, .view-btn { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; text-decoration: none; white-space: nowrap; }
        .view-btn { background: linear-gradient(135deg, #1f6feb 0%, #2156d1 100%); color: white; box-shadow: 0 8px 18px rgba(31,111,235,0.18); }
        .view-btn:hover { background: #1558c0; }
        .download-btn { background: #667eea; color: white; }
        .download-btn:hover { background: #5569d9; }
        .empty { text-align: center; padding: 40px; color: #888; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>🎯 技能扫描器</h1></div>
        <div class="header-nav">
            <a href="/dashboard" class="active">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="dashboardUserMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="welcome">
            <h2>欢迎使用技能扫描器</h2>
            <p>上传技能文件或文件夹，检测敏感信息泄露和危险函数调用，生成 Word 风险报告。</p>
        </div>
        <div class="cards">
            <div class="card">
                <div class="icon">🔍</div>
                <h3>技能扫描</h3>
                <p>拖拽或点击上传技能文件（夹），自动扫描并生成风险报告。</p>
                <a href="/scan" class="card-btn">开始扫描</a>
            </div>
            <div class="card">
                <div class="icon">📊</div>
                <h3>风险报告</h3>
                <p>查看历史扫描报告，{{if .IsAdmin}}管理员可查看所有报告{{else}}可查看您及同团队成员的报告{{end}}。</p>
                <a href="/reports" class="card-btn">查看报告</a>
            </div>
            <div class="card">
                <div class="icon">🗂️</div>
                <h3>准入库</h3>
                <p>查看已录入技能资产、风险标签和准入状态，支撑后续人工审查与组合分析。</p>
                <a href="/admission/skills" class="card-btn">进入准入库</a>
            </div>
            <div class="card">
                <div class="icon">🧩</div>
                <h3>组合分析</h3>
                <p>选择多个技能进行聚合风险分析，查看组合能力画像、残余风险与动态链路推理。</p>
                <a href="/combination/overview" class="card-btn">进入组合分析</a>
            </div>
        </div>

        <h3 class="section-title">📋 最近报告</h3>
        <div class="report-list">
            {{if .Reports}}
                {{range .Reports}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
                        <div class="meta">{{.Username}} · {{.CreatedAt}} · {{.StatusLabel}}</div>
                        <div class="badges">
                            {{if .NoRisk}}<span class="badge ok">✅ 无风险</span>{{end}}
                            {{if .HighRisk}}<span class="badge high">🔴 高 {{.HighRisk}}</span>{{end}}
                            {{if .MediumRisk}}<span class="badge medium">🟡 中 {{.MediumRisk}}</span>{{end}}
                            {{if .LowRisk}}<span class="badge low">🟢 低 {{.LowRisk}}</span>{{end}}
                            {{if .Decision}}<span class="badge ok">决策 {{.Decision}}</span>{{end}}
                            <span style="color:#888;font-size:12px;margin-left:4px;">共 {{.FindingCount}} 项</span>
                        </div>
                    </div>
                    <div class="report-actions">
                        {{if .HasHTML}}<a href="/reports/view/{{.ID}}" class="view-btn">直接查看</a>{{end}}
                        <a href="/reports/download/{{.ID}}" class="download-btn">下载 DOCX</a>
                    </div>
                </div>
                {{end}}
            {{else}}
                <div class="empty">暂无报告，请先进行技能扫描</div>
            {{end}}
        </div>
    </div>
    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }
        bindDropdownMenu('dashboardUserMenuButton', 'userDropdown');
    </script>
</body>
</html>
`

// ReportsHTML is the reports listing page template.
const ReportsHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>风险报告 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .nav-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; }
        .nav-btn:hover { background: rgba(255,255,255,0.3); }
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .admin-hint { background: #f0f7ff; color: #667eea; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .team-hint { background: #f0fff0; color: #060; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .report-item { padding: 16px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }
        .report-item:last-child { border-bottom: none; }
        .report-item .info { flex: 1; }
        .report-item .filename { color: #333; font-weight: 500; }
        .report-item .meta { color: #888; font-size: 13px; margin-top: 4px; font-variant-numeric: tabular-nums; }
        .report-item .badges { display: flex; gap: 8px; margin-top: 6px; flex-wrap: wrap; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.high { background: #fee; color: #c00; }
        .badge.medium { background: #ffc; color: #a60; }
        .badge.low { background: #efe; color: #060; }
        .badge.ok { background: #eef; color: #06c; }
        .badge.status { background: #f4f4f5; color: #52525b; }
        .report-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .download-btn, .view-btn, .delete-btn, .admission-btn, .admission-btn-muted { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; text-decoration: none; white-space: nowrap; }
        .view-btn { background: linear-gradient(135deg, #1f6feb 0%, #2156d1 100%); color: white; box-shadow: 0 8px 18px rgba(31,111,235,0.18); }
        .view-btn:hover { background: #1558c0; }
        .download-btn { background: #667eea; color: white; }
        .download-btn:hover { background: #5569d9; }
        .admission-btn { background: #0f766e; color: white; }
        .admission-btn:hover { background: #0d5f59; }
        .admission-btn-muted { background: #ecfdf3; color: #067647; border: 1px solid #a6f4c5; }
        .delete-btn { background: #fff1f0; color: #b42318; border: 1px solid #f0b7bf; }
        .delete-btn:hover { background: #ffe5e2; }
        .delete-form { margin: 0; }
        .flash { padding: 14px 16px; border-radius: 10px; margin-bottom: 16px; font-size: 14px; }
        .flash.success { background: #ecfdf3; color: #067647; border: 1px solid #a6f4c5; }
        .flash.error { background: #fff1f0; color: #b42318; border: 1px solid #f0b7bf; }
        .empty { text-align: center; padding: 60px; color: #888; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>📊 风险报告</h1></div>
		<div class="header-nav">
			<a href="/dashboard">🎯 首页</a>
			<a href="/scan">🔍 扫描</a>
			<a href="/reports" class="active">📊 报告</a>
			<a href="/admission/skills">准入库</a>
			<a href="/combination/overview">组合分析</a>
		</div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="reportsUserMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>报告列表</h2>
                {{if .IsAdmin}}<span class="admin-hint">👑 管理员视图（显示所有报告）</span>{{else}}<span class="team-hint">显示您及同团队成员的报告</span>{{end}}
            </div>
            {{if .Notice}}<div class="flash success">{{.Notice}}</div>{{end}}
            {{if .Error}}<div class="flash error">{{.Error}}</div>{{end}}
            {{if .RunningTasks}}
                {{range .RunningTasks}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
                        <div class="meta">任务 {{.ID}} · 创建 {{.CreatedAt}} · 更新 {{.UpdatedAt}} · {{.StatusLabel}}</div>
                        <div class="badges">
                            <span class="badge status">{{.StatusLabel}}</span>
                            <span style="color:#888;font-size:12px;margin-left:4px;">扫描进行中，报告尚未生成</span>
                        </div>
                        {{if .Message}}<div class="meta">{{.Message}}</div>{{end}}
                    </div>
                    <div class="report-actions">
                        <a href="/scan" class="view-btn">查看扫描进度</a>
                    </div>
                </div>
                {{end}}
            {{end}}
            {{if .Reports}}
                {{range .Reports}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
                        <div class="meta">{{.Username}} · {{.CreatedAt}} · {{.StatusLabel}}</div>
                        <div class="badges">
                            <span class="badge status">{{.StatusLabel}}</span>
                            {{if .NoRisk}}<span class="badge ok">✅ 无风险</span>{{end}}
                            {{if .HighRisk}}<span class="badge high">🔴 高 {{.HighRisk}}</span>{{end}}
                            {{if .MediumRisk}}<span class="badge medium">🟡 中 {{.MediumRisk}}</span>{{end}}
                            {{if .LowRisk}}<span class="badge low">🟢 低 {{.LowRisk}}</span>{{end}}
                            <span style="color:#888;font-size:12px;margin-left:4px;">共 {{.FindingCount}} 项</span>
                            {{if .Decision}}<span class="badge ok">决策 {{.Decision}}</span>{{end}}
                        </div>
                    </div>
                    <div class="report-actions">
                        {{if .HasHTML}}<a href="/reports/view/{{.ID}}" class="view-btn">直接查看</a>{{end}}
                        <a href="/reports/download/{{.ID}}" class="download-btn">DOCX</a>
                        <a href="/reports/download/{{.ID}}?format=html" class="download-btn">HTML</a>
                        <a href="/reports/download/{{.ID}}?format=json" class="download-btn">JSON</a>
                        {{if .HasPDF}}<a href="/reports/download/{{.ID}}?format=pdf" class="download-btn">PDF</a>{{end}}
						{{if .Imported}}
						<a href="/admission/skills/{{.ImportedSkillID}}" class="admission-btn-muted">已录入准入库</a>
						{{else}}
						<a href="/admission/import/{{.ID}}" class="admission-btn">录入准入库</a>
						{{end}}
                        {{if .Imported}}
                        <a href="/combination/overview?skill_id={{.ImportedSkillID}}" class="admission-btn">组合风险分析</a>
                        {{else}}
                        <a href="/combination/overview?report_id={{.ID}}" class="admission-btn">组合风险分析</a>
                        {{end}}
						{{if .CanDelete}}
						<form method="POST" action="/reports/delete/{{.ID}}" class="delete-form report-delete-form" data-confirm="确认删除报告“{{.FileName}}”吗？该操作会同时清理关联的 HTML、JSON、DOCX、PDF 文件且不可恢复。">
                            <button type="submit" class="delete-btn">删除</button>
                        </form>
                        {{end}}
                    </div>
                </div>
                {{end}}
            {{else}}
                <div class="empty">
                    <div style="font-size:40px;margin-bottom:10px;">📭</div>
                    暂无报告，请先进行技能扫描
                </div>
            {{end}}
        </div>
    </div>
    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }

        function bindConfirmForms(selector) {
            document.querySelectorAll(selector).forEach(function(form) {
                form.addEventListener('submit', function(e) {
                    var message = form.getAttribute('data-confirm') || '确认执行当前操作吗？';
                    if (!confirm(message)) {
                        e.preventDefault();
                    }
                });
            });
        }

        bindDropdownMenu('reportsUserMenuButton', 'userDropdown');
        bindConfirmForms('.report-delete-form');
    </script>
</body>
</html>
`

// ScanHTML is the skill scanning page template (fixed folder upload).
const ScanHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>技能扫描 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .panel h2 { color: #333; margin-bottom: 10px; }
        .panel > p { color: #666; margin-bottom: 30px; line-height: 1.6; }
        .upload-mode { display: flex; gap: 15px; margin-bottom: 20px; }
        .mode-btn { flex: 1; padding: 20px; border: 2px solid #e1e1e1; border-radius: 10px; cursor: pointer; text-align: center; transition: all 0.2s; background: white; }
        .mode-btn:hover { border-color: #667eea; }
        .mode-btn.active { border-color: #667eea; background: rgba(102,126,234,0.05); }
        .mode-btn .icon { font-size: 36px; margin-bottom: 8px; }
        .mode-btn .title { font-weight: 600; color: #333; margin-bottom: 4px; }
        .mode-btn .desc { font-size: 13px; color: #888; }
        .upload-area { border: 3px dashed #ddd; border-radius: 12px; padding: 50px 40px; text-align: center; transition: all 0.3s; cursor: pointer; margin-bottom: 20px; }
        .upload-area:hover, .upload-area.dragover { border-color: #667eea; background: rgba(102,126,234,0.05); }
        .upload-area .icon { font-size: 50px; margin-bottom: 15px; }
        .upload-area h3 { color: #333; margin-bottom: 8px; }
        .upload-area p { color: #888; margin-bottom: 0; font-size: 14px; }
        .upload-area .hint { font-size: 12px; color: #aaa; margin-top: 8px; }
        .upload-area input { display: none; }
        .file-list { background: #f5f6fa; padding: 14px 18px; border-radius: 8px; margin-bottom: 15px; display: none; max-height: 200px; overflow-y: auto; }
        .file-list.show { display: block; }
        .file-item { display: flex; align-items: center; padding: 6px 0; border-bottom: 1px solid #e0e0e0; }
        .file-item:last-child { border-bottom: none; }
        .file-item .name { flex: 1; color: #333; font-size: 14px; word-break: break-all; }
        .file-item .size { color: #888; font-size: 12px; margin-left: 10px; }
        .file-summary { margin-bottom: 12px; color: #333; font-weight: 500; }
        .submit-btn { width: 100%; padding: 16px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: 600; cursor: pointer; transition: transform 0.2s; display: none; }
        .submit-btn.show { display: block; }
        .submit-btn:hover { transform: translateY(-2px); }
        .submit-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .loading { display: none; text-align: center; padding: 40px; }
        .loading .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .task-status-panel { display: none; margin: 18px 0 22px; padding: 18px 20px; border-radius: 12px; border: 1px solid #d9e3ff; background: linear-gradient(180deg, #f8fbff 0%, #eef4ff 100%); }
        .task-status-panel.show { display: block; }
        .task-status-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 10px; }
        .task-status-head h3 { margin: 0; font-size: 16px; color: #24324a; }
        .task-status-head .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; background: #dfe9ff; color: #2156d1; }
        .task-status-panel p { margin: 6px 0; color: #4d5b70; line-height: 1.6; }
        .task-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
        .task-link { display: inline-flex; align-items: center; justify-content: center; padding: 9px 14px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 600; border: 1px solid #c7d5fb; background: white; color: #2156d1; }
        .task-link.primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-color: transparent; color: white; }
        .task-progress { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
        .task-progress span { padding: 4px 10px; border-radius: 999px; font-size: 12px; background: #edf2ff; color: #52627c; }
        .task-progress span.done { background: #e7f7ee; color: #067647; }
        .tips { background: #f0f7ff; border-left: 4px solid #667eea; padding: 16px 20px; border-radius: 0 8px 8px 0; margin-top: 30px; }
        .tips h4 { color: #333; margin-bottom: 10px; }
        .tips ul { color: #666; padding-left: 20px; line-height: 1.8; }
        .runtime-status { background: #fff7e6; border-left: 4px solid #f0ad4e; padding: 14px 18px; border-radius: 0 8px 8px 0; margin-bottom: 22px; color: #5a4100; line-height: 1.6; }
        .field-group { margin-bottom: 20px; }
        .field-group label { display: block; margin-bottom: 6px; color: #555; font-weight: 500; }
        .field-group input, .field-group textarea { width: 100%; padding: 12px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 14px; }
        .field-group textarea { resize: vertical; min-height: 80px; }
        .rules-panel { border: 1px solid #e8ebf5; border-radius: 10px; padding: 16px; margin-bottom: 20px; background: #fafbff; }
        .rules-panel h3 { font-size: 15px; color: #333; margin-bottom: 10px; }
        .rules-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; gap: 10px; flex-wrap: wrap; }
        .rules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 14px; max-height: 220px; overflow-y: auto; padding: 8px 2px; }
        .rule-item { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #333; }
        .rule-layer { display: inline-block; min-width: 42px; text-align: center; padding: 1px 6px; border-radius: 10px; font-size: 11px; color: white; }
        .rule-layer.high { background: #d9534f; }
        .rule-layer.medium { background: #f0ad4e; }
        .rule-layer.low { background: #5bc0de; }
        .rule-empty { color: #888; font-size: 13px; }
        .tiny-btn { border: 1px solid #cfd6ea; background: white; border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 12px; color: #445; }
        .tiny-btn:hover { background: #f2f5ff; }
        .custom-rule-row { border: 1px solid #e1e6f4; border-radius: 8px; padding: 12px; margin-top: 10px; background: white; }
        .custom-rule-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }
        .custom-rule-row input, .custom-rule-row select { width: 100%; padding: 8px 10px; border: 1px solid #dbe2f3; border-radius: 6px; font-size: 13px; }
        .custom-rule-row .remove { margin-top: 10px; color: #b00020; border-color: #f0b7bf; }
        .hint-text { margin-top: 6px; font-size: 12px; color: #7a8296; }
        .diff-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
        .diff-checkboxes { display: flex; gap: 12px; flex-wrap: wrap; font-size: 13px; color: #333; }
        .config-toolbar { display: grid; grid-template-columns: 1fr auto auto auto auto; gap: 10px; align-items: end; margin-bottom: 20px; }
        .config-toolbar select, .config-toolbar input { width: 100%; padding: 10px; border: 1px solid #dbe2f3; border-radius: 6px; font-size: 13px; }
        .config-toolbar .tiny-btn { height: 38px; }
        @media (max-width: 720px) {
            .config-toolbar { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>🔍 技能扫描</h1></div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan" class="active">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="scanUserMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <h2>上传技能文件</h2>
            <p>选择文件或整个文件夹，系统将自动扫描并生成风险报告。</p>
            {{if .RuntimeSummary}}
            <div class="runtime-status"><strong>启动自检:</strong> {{.RuntimeSummary}}<br>任一关键能力不可用时，系统会阻断扫描并提示修复，不会降级生成低精度报告。</div>
            {{end}}

            <div class="upload-mode">
                <div class="mode-btn active" id="modeFile">
                    <div class="icon">📄</div>
                    <div class="title">单文件 / 多文件</div>
                    <div class="desc">选择一个或多个文件</div>
                </div>
                <div class="mode-btn" id="modeFolder">
                    <div class="icon">📁</div>
                    <div class="title">文件夹</div>
                    <div class="desc">选择整个文件夹（递归上传所有文件）</div>
                </div>
            </div>

            <div class="config-toolbar">
                <div>
                    <label style="display:block; margin-bottom:6px; color:#555; font-weight:500;">规则配置选择</label>
                    <select id="profileSelector">
                        <option value="preset:default-all">默认全量基线（系统）</option>
                    </select>
                </div>
                <input type="text" id="newProfileName" placeholder="新配置名称">
                <button type="button" class="tiny-btn" id="saveProfileBtn">保存当前配置</button>
                <button type="button" class="tiny-btn" id="renameProfileBtn">重命名已选配置</button>
                <button type="button" class="tiny-btn" id="deleteProfileBtn">删除已选配置</button>
            </div>

            <div class="rules-panel">
                <h3>规则勾选与增补</h3>
                <div class="rules-toolbar">
                    <label class="rule-item"><input type="checkbox" id="selectAllRules" checked> 全选内置规则</label>
                    <button type="button" class="tiny-btn" id="addCustomRuleBtn">新增自定义规则</button>
                </div>
                <div id="rulesCatalog" class="rules-grid">
                    <div class="rule-empty">正在加载规则目录...</div>
                </div>
                <div class="hint-text">可按当前技能风险面裁剪评估项；高风险规则建议保持勾选。</div>
                <div id="customRulesContainer"></div>
            </div>

            <div class="rules-panel">
                <h3>差分执行配置</h3>
                <div class="diff-options">
                    <div>
                        <label style="font-size:13px; color:#555; font-weight:600; margin-bottom:8px; display:block;">环境差分画像</label>
                        <label class="rule-item"><input type="checkbox" id="diffEnabled" checked> 启用后同时执行容器画像、虚拟机画像、基线画像分析</label>
                        <div class="hint-text">三个场景会作为一个整体执行，用于识别反沙箱、反虚拟机和通用反分析差异。</div>
                    </div>
                    <div>
                        <label for="delayThreshold" style="font-size:13px; color:#555; font-weight:600; margin-bottom:8px; display:block;">长延时判定阈值（秒）</label>
                        <input type="number" id="delayThreshold" min="1" step="1" value="300">
                        <div class="hint-text">用于识别 sleep/time.sleep 类反分析延时逻辑。</div>
                    </div>
                </div>
            </div>

            <form id="uploadForm" enctype="multipart/form-data">
                <div class="upload-area" id="dropZone">
                    <div class="icon" id="uploadIcon">📄</div>
                    <h3 id="uploadTitle">选择文件</h3>
                    <p id="uploadHint">点击选择或将文件拖拽到此处</p>
                    <p class="hint" id="uploadHint2">支持任意代码文件，可多选或整个文件夹</p>
                    <input type="file" id="fileInput" name="files" multiple>
                </div>

                <div class="file-list" id="fileListContainer">
                    <div class="file-summary" id="fileSummary"></div>
                    <div id="fileItems"></div>
                </div>

                <button type="submit" class="submit-btn" id="submitBtn">🔍 开始扫描</button>
            </form>

            <div class="task-status-panel" id="taskStatusPanel">
                <div class="task-status-head">
                    <div>
                        <h3 id="taskStatusTitle">当前扫描任务</h3>
                        <p id="taskStatusText">暂无正在跟踪的扫描任务。</p>
                    </div>
                    <span class="badge" id="taskStatusBadge">空闲</span>
                </div>
                <p id="taskStatusMeta"></p>
                <div class="task-progress" id="taskProgress"></div>
                <div class="task-actions">
                    <a href="/reports" class="task-link primary" id="taskViewReportBtn" style="display:none;">查看完整报告</a>
                    <a href="/reports" class="task-link primary">查看报告列表</a>
                    <a href="/admission/skills" class="task-link">进入准入库</a>
                    <a href="/combination/overview" class="task-link">进入组合分析</a>
                    <button type="button" class="tiny-btn" id="clearTaskStatusBtn">清除任务状态</button>
                </div>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>扫描中，请稍候...</p>
            </div>
        </div>

        <div class="tips">
            <h4>💡 使用提示</h4>
            <ul>
                <li><strong>单/多文件：</strong>直接选择一个或多个文件</li>
                <li><strong>文件夹：</strong>直接选择整个文件夹，浏览器会上传其中所有文件（递归）</li>
                <li>系统会自动推断技能行为与权限，不再需要手工填写描述或权限声明</li>
                <li>支持检测：硬编码凭证、危险函数、语义安全分析（需模型支持）</li>
                <li>扫描完成后会在当前页显示结果概要，你可以按需进入完整报告</li>
            </ul>
        </div>
    </div>

    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }

        bindDropdownMenu('scanUserMenuButton', 'userDropdown');

        var currentMode = 'file';
        var selectedFiles = [];
        var builtinRules = [];
        var builtinPresets = [];
        var savedProfiles = [];
        var customRuleCount = 0;

        document.getElementById('modeFile').addEventListener('click', function() {
            setMode('file');
        });
        document.getElementById('modeFolder').addEventListener('click', function() {
            setMode('folder');
        });

        loadRulesCatalog('preset:default-all');

        function loadRulesCatalog(preferredSelection) {
            fetchJSON('/api/rules/catalog')
                .then(function(data) {
                    builtinRules = Array.isArray(data.rules) ? data.rules : [];
                    builtinPresets = Array.isArray(data.presets) ? data.presets : [];
                    savedProfiles = Array.isArray(data.saved_profiles) ? data.saved_profiles : [];
                    renderRulesCatalog();
                    applyDifferentialDefaults(data.differential || {});
                    renderProfileSelector(preferredSelection || 'preset:default-all');
                })
                .catch(function() {
                    var box = document.getElementById('rulesCatalog');
                    renderRuleEmptyState(box, '规则目录加载失败，将使用系统默认规则。');
                });
        }

        function clearChildren(node) {
            while (node.firstChild) {
                node.removeChild(node.firstChild);
            }
        }

        function fetchJSON(url, options) {
            return fetch(url, options).then(function(resp) {
                var contentType = resp.headers.get('Content-Type') || '';
                if (contentType.indexOf('application/json') === -1) {
                    throw new Error('服务返回了非 JSON 响应');
                }
                return resp.json().then(function(data) {
                    if (!resp.ok) {
                        throw new Error((data && data.error) || ('请求失败（HTTP ' + resp.status + '）'));
                    }
                    return data;
                });
            });
        }

        function renderRuleEmptyState(box, message) {
            clearChildren(box);
            var empty = document.createElement('div');
            empty.className = 'rule-empty';
            empty.textContent = message;
            box.appendChild(empty);
        }

        function renderProfileSelector(preferredSelection) {
            var selector = document.getElementById('profileSelector');
            clearChildren(selector);
            if (!builtinPresets.length) {
                appendProfileOption(selector, 'preset:default-all', '默认全量基线（系统）');
            }
            for (var i = 0; i < builtinPresets.length; i++) {
                var p = builtinPresets[i];
                appendProfileOption(selector, 'preset:' + (p.key || ''), '模板：' + (p.name || ''));
            }
            if (savedProfiles.length > 0) {
                for (var j = 0; j < savedProfiles.length; j++) {
                    var s = savedProfiles[j];
                    appendProfileOption(selector, 'saved:' + (s.name || ''), '我的配置：' + (s.name || ''));
                }
            }
            var fallback = 'preset:default-all';
            var target = preferredSelection || fallback;
            var hasOption = false;
            for (var k = 0; k < selector.options.length; k++) {
                if (selector.options[k].value === target) {
                    hasOption = true;
                    break;
                }
            }
            selector.value = hasOption ? target : fallback;
            applyProfileSelection(selector.value);
        }

        function appendProfileOption(selector, value, label) {
            var option = document.createElement('option');
            option.value = value;
            option.textContent = label;
            selector.appendChild(option);
        }

        document.getElementById('profileSelector').addEventListener('change', function(e) {
            applyProfileSelection(e.target.value || '');
        });

        function applyProfileSelection(val) {
            if (val.indexOf('preset:') === 0) {
                applyPresetByKey(val.slice(7));
                return;
            }
            if (val.indexOf('saved:') === 0) {
                applySavedProfileByName(val.slice(6));
            }
        }

        document.getElementById('saveProfileBtn').addEventListener('click', saveCurrentProfile);
        document.getElementById('renameProfileBtn').addEventListener('click', renameSelectedProfile);
        document.getElementById('deleteProfileBtn').addEventListener('click', deleteSelectedProfile);

        function applyPresetByKey(key) {
            var preset = null;
            for (var i = 0; i < builtinPresets.length; i++) {
                if ((builtinPresets[i].key || '') === key) {
                    preset = builtinPresets[i];
                    break;
                }
            }
            if (!preset) {
                return;
            }
            applyRuleConfig(preset.selected_rule_ids || [], [], {
                enabled: preset.differential_enabled !== false,
                delayThresholdSecs: preset.delay_threshold_secs
            });
        }

        function applySavedProfileByName(name) {
            var profile = null;
            for (var i = 0; i < savedProfiles.length; i++) {
                if ((savedProfiles[i].name || '') === name) {
                    profile = savedProfiles[i];
                    break;
                }
            }
            if (!profile) {
                return;
            }
            applyRuleConfig(profile.selected_rule_ids || [], profile.custom_rules || [], {
                enabled: profile.differential_enabled !== false,
                delayThresholdSecs: profile.evasion_delay_threshold_secs
            });
        }

        function applyRuleConfig(selectedRuleIDs, customRules, diffSettings) {
            setSelectedRuleIDs(selectedRuleIDs || []);
            setCustomRules(customRules || []);
            setDiffSettings(diffSettings || {});
        }

        function setSelectedRuleIDs(ids) {
            var selected = {};
            for (var i = 0; i < ids.length; i++) {
                selected[ids[i]] = true;
            }
            var boxes = document.querySelectorAll('.rule-checkbox');
            for (var j = 0; j < boxes.length; j++) {
                var id = boxes[j].getAttribute('data-rule-id');
                boxes[j].checked = !!selected[id];
            }
            syncSelectAllState();
        }

        function setCustomRules(rules) {
            var container = document.getElementById('customRulesContainer');
            clearChildren(container);
            customRuleCount = 0;
            for (var i = 0; i < rules.length; i++) {
                appendCustomRuleRow(rules[i]);
            }
        }

        function setDiffSettings(diffSettings) {
            document.getElementById('diffEnabled').checked = diffSettings.enabled !== false;
            if (diffSettings.delayThresholdSecs) {
                document.getElementById('delayThreshold').value = diffSettings.delayThresholdSecs;
            }
        }

        function saveCurrentProfile() {
            var name = document.getElementById('newProfileName').value.trim();
            if (!name) {
                alert('请先输入配置名称');
                return;
            }
            var diff = collectDifferentialSettings();
            var payload = {
                name: name,
                selected_rule_ids: collectSelectedRuleIDs(),
                custom_rules: collectCustomRules(),
                differential_enabled: diff.enabled,
                evasion_delay_threshold_secs: Number(diff.delayThresholdSecs || 0)
            };
            if (payload.selected_rule_ids.length === 0 && payload.custom_rules.length === 0) {
                alert('至少选择一条规则后才能保存配置');
                return;
            }
            fetchJSON('/api/rules/profiles', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
                .then(function(data) {
                    if (data && data.status === 'ok') {
                        alert('规则配置已保存');
                        loadRulesCatalog('saved:' + name);
                        document.getElementById('newProfileName').value = '';
                    } else {
                        alert('保存失败: ' + ((data && data.error) || '未知错误'));
                    }
                })
                .catch(function(err) {
                    alert('保存失败: ' + err.message);
                });
        }

        function renameSelectedProfile() {
            var selected = getSelectedSavedProfileName();
            if (!selected) {
                alert('请先在下拉框选择“我的配置”后再重命名');
                return;
            }
            var newName = document.getElementById('newProfileName').value.trim();
            if (!newName) {
                alert('请在“新配置名称”中输入新名称');
                return;
            }
            fetchJSON('/api/rules/profiles', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_name: selected, new_name: newName })
            })
                .then(function(data) {
                    if (data && data.status === 'ok') {
                        alert('重命名成功');
                        loadRulesCatalog('saved:' + newName);
                        document.getElementById('newProfileName').value = '';
                    } else {
                        alert('重命名失败: ' + ((data && data.error) || '未知错误'));
                    }
                })
                .catch(function(err) {
                    alert('重命名失败: ' + err.message);
                });
        }

        function deleteSelectedProfile() {
            var selected = getSelectedSavedProfileName();
            if (!selected) {
                alert('请先在下拉框选择“我的配置”后再删除');
                return;
            }
            if (!confirm('确认删除配置「' + selected + '」吗？')) {
                return;
            }
            fetchJSON('/api/rules/profiles', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: selected })
            })
                .then(function(data) {
                    if (data && data.status === 'ok') {
                        alert('配置已删除');
                        loadRulesCatalog('preset:default-all');
                    } else {
                        alert('删除失败: ' + ((data && data.error) || '未知错误'));
                    }
                })
                .catch(function(err) {
                    alert('删除失败: ' + err.message);
                });
        }

        function getSelectedSavedProfileName() {
            var val = document.getElementById('profileSelector').value || '';
            if (val.indexOf('saved:') !== 0) {
                return '';
            }
            return val.slice(6);
        }

        function renderRulesCatalog() {
            var box = document.getElementById('rulesCatalog');
            if (!builtinRules.length) {
                renderRuleEmptyState(box, '未获取到规则目录，将使用系统默认规则。');
                return;
            }
            clearChildren(box);
            for (var i = 0; i < builtinRules.length; i++) {
                var rule = builtinRules[i];
                var severity = rule.severity || riskLabelFromLegacyLayer(rule.layer || '');
                var layerClass = severityClass(severity);
                var label = document.createElement('label');
                label.className = 'rule-item';
                var checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = 'rule-checkbox';
                checkbox.checked = true;
                checkbox.setAttribute('data-rule-id', rule.id || '');
                var layer = document.createElement('span');
                layer.className = 'rule-layer ' + layerClass;
                layer.textContent = severity;
                var text = document.createElement('span');
                text.textContent = (rule.id || '') + ' ' + (rule.name || '');
                label.appendChild(checkbox);
                label.appendChild(layer);
                label.appendChild(text);
                box.appendChild(label);
            }
            bindRuleSelectionEvents();
        }

        function bindRuleSelectionEvents() {
            var selectAll = document.getElementById('selectAllRules');
            var boxes = document.querySelectorAll('.rule-checkbox');
            selectAll.addEventListener('change', function() {
                for (var i = 0; i < boxes.length; i++) {
                    boxes[i].checked = selectAll.checked;
                }
            });
            for (var i = 0; i < boxes.length; i++) {
                boxes[i].addEventListener('change', syncSelectAllState);
            }
        }

        function syncSelectAllState() {
            var boxes = document.querySelectorAll('.rule-checkbox');
            if (!boxes.length) {
                return;
            }
            var allChecked = true;
            for (var i = 0; i < boxes.length; i++) {
                if (!boxes[i].checked) {
                    allChecked = false;
                    break;
                }
            }
            document.getElementById('selectAllRules').checked = allChecked;
        }

        function applyDifferentialDefaults(diff) {
            if (typeof diff.delay_threshold_secs === 'number' && diff.delay_threshold_secs > 0) {
                document.getElementById('delayThreshold').value = diff.delay_threshold_secs;
            }
            document.getElementById('diffEnabled').checked = diff.enabled !== false;
        }

        document.getElementById('addCustomRuleBtn').addEventListener('click', function() {
            appendCustomRuleRow(null);
        });

        function appendCustomRuleRow(initial) {
            customRuleCount += 1;
            var id = 'customRule' + customRuleCount;
            var row = document.createElement('div');
            row.className = 'custom-rule-row';
            row.id = id;
            var defaultSeverity = (initial && initial.severity) || riskLabelFromLegacyLayer((initial && initial.layer) || '') || '中风险';
            var grid = document.createElement('div');
            grid.className = 'custom-rule-grid';

            var nameInput = document.createElement('input');
            nameInput.type = 'text';
            nameInput.className = 'cr-name';
            nameInput.placeholder = '规则名称（必填）';
            nameInput.value = (initial && initial.name) || '';

            var severitySelect = document.createElement('select');
            severitySelect.className = 'cr-severity';
            appendSeverityOption(severitySelect, '高风险');
            appendSeverityOption(severitySelect, '中风险');
            appendSeverityOption(severitySelect, '低风险');
            severitySelect.value = defaultSeverity;

            var patternsInput = document.createElement('input');
            patternsInput.type = 'text';
            patternsInput.className = 'cr-patterns';
            patternsInput.placeholder = '匹配模式（逗号分隔，必填）';
            patternsInput.value = (initial && Array.isArray(initial.patterns)) ? initial.patterns.join(', ') : '';

            var reasonInput = document.createElement('input');
            reasonInput.type = 'text';
            reasonInput.className = 'cr-reason';
            reasonInput.placeholder = '命中原因（可选）';
            reasonInput.value = (initial && initial.reason) || '';

            var removeButton = document.createElement('button');
            removeButton.type = 'button';
            removeButton.className = 'tiny-btn remove';
            removeButton.textContent = '删除该规则';
            removeButton.addEventListener('click', function() {
                row.parentNode.removeChild(row);
            });

            grid.appendChild(nameInput);
            grid.appendChild(severitySelect);
            grid.appendChild(patternsInput);
            grid.appendChild(reasonInput);
            row.appendChild(grid);
            row.appendChild(removeButton);
            document.getElementById('customRulesContainer').appendChild(row);
        }

        function appendSeverityOption(select, label) {
            var option = document.createElement('option');
            option.value = label;
            option.textContent = label;
            select.appendChild(option);
        }

        function collectSelectedRuleIDs() {
            var boxes = document.querySelectorAll('.rule-checkbox:checked');
            var ids = [];
            for (var i = 0; i < boxes.length; i++) {
                var id = boxes[i].getAttribute('data-rule-id');
                if (id) {
                    ids.push(id);
                }
            }
            return ids;
        }

        function collectCustomRules() {
            var rows = document.querySelectorAll('#customRulesContainer .custom-rule-row');
            var out = [];
            for (var i = 0; i < rows.length; i++) {
                var row = rows[i];
                var name = row.querySelector('.cr-name').value.trim();
                var severity = row.querySelector('.cr-severity').value;
                var patternsRaw = row.querySelector('.cr-patterns').value.trim();
                var reason = row.querySelector('.cr-reason').value.trim();
                if (!name || !patternsRaw) {
                    continue;
                }
                var patterns = patternsRaw.split(',').map(function(item) { return item.trim(); }).filter(Boolean);
                if (!patterns.length) {
                    continue;
                }
                var rule = {
                    name: name,
                    severity: severity,
                    patterns: patterns,
                    reason: reason
                };
                out.push(rule);
            }
            return out;
        }

        function riskLabelFromLegacyLayer(layer) {
            switch ((layer || '').toUpperCase()) {
            case 'P0': return '高风险';
            case 'P1': return '中风险';
            case 'P2': return '低风险';
            default: return '';
            }
        }

        function severityClass(severity) {
            switch (severity) {
            case '高风险': return 'high';
            case '中风险': return 'medium';
            case '低风险': return 'low';
            default: return 'medium';
            }
        }

        function collectDifferentialSettings() {
            var delayThreshold = document.getElementById('delayThreshold').value;
            return {
                enabled: document.getElementById('diffEnabled').checked,
                delayThresholdSecs: delayThreshold
            };
        }

        function setMode(mode) {
            currentMode = mode;
            document.getElementById('modeFile').classList.toggle('active', mode === 'file');
            document.getElementById('modeFolder').classList.toggle('active', mode === 'folder');
            var fi = document.getElementById('fileInput');
            var icon = document.getElementById('uploadIcon');
            var title = document.getElementById('uploadTitle');
            var hint = document.getElementById('uploadHint');
            var hint2 = document.getElementById('uploadHint2');
            
            if (mode === 'folder') {
                fi.setAttribute('webkitdirectory', '');
                fi.setAttribute('directory', '');
                fi.removeAttribute('accept');
                icon.textContent = '📁';
                title.textContent = '选择文件夹';
                hint.textContent = '点击选择文件夹，将上传其中所有文件';
                hint2.textContent = '支持任意代码文件，递归上传子文件夹';
            } else {
                fi.removeAttribute('webkitdirectory');
                fi.removeAttribute('directory');
                fi.setAttribute('accept', '*/*');
                fi.setAttribute('multiple', '');
                icon.textContent = '📄';
                title.textContent = '选择文件';
                hint.textContent = '点击选择或将文件拖拽到此处';
                hint2.textContent = '支持任意代码文件，可多选';
            }
            fi.value = '';
            selectedFiles = [];
            updateFileList();
        }

        var dropZone = document.getElementById('dropZone');
        var fileInput = document.getElementById('fileInput');
        
        dropZone.addEventListener('click', function() { fileInput.click(); });
        dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('dragover'); });
        dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('dragover'); });
        dropZone.addEventListener('drop', function(e) {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                // 拖拽上传时，无法模拟webkitdirectory，因此使用拖拽的文件列表
                fileInput.files = e.dataTransfer.files;
                handleFileSelect(e.dataTransfer.files);
            }
        });
        
        fileInput.addEventListener('change', function() { handleFileSelect(fileInput.files); });

        function handleFileSelect(files) {
            selectedFiles = [];
            for (var i = 0; i < files.length; i++) {
                selectedFiles.push(files[i]);
            }
            updateFileList();
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }

        function updateFileList() {
            var container = document.getElementById('fileListContainer');
            var summary = document.getElementById('fileSummary');
            var itemsDiv = document.getElementById('fileItems');
            var submitBtn = document.getElementById('submitBtn');
            
            if (selectedFiles.length === 0) {
                container.classList.remove('show');
                submitBtn.classList.remove('show');
                return;
            }
            
            container.classList.add('show');
            submitBtn.classList.add('show');
            
            var totalSize = 0;
            var fileNames = [];
            for (var i = 0; i < selectedFiles.length; i++) {
                totalSize += selectedFiles[i].size;
                fileNames.push(selectedFiles[i].name);
            }
            
            summary.textContent = '已选择 ' + selectedFiles.length + ' 个文件，总大小 ' + formatSize(totalSize);
            clearChildren(itemsDiv);
            for (var i = 0; i < selectedFiles.length; i++) {
                var f = selectedFiles[i];
                var item = document.createElement('div');
                item.className = 'file-item';
                var name = document.createElement('span');
                name.className = 'name';
                name.textContent = f.name;
                var size = document.createElement('span');
                size.className = 'size';
                size.textContent = formatSize(f.size);
                item.appendChild(name);
                item.appendChild(size);
                itemsDiv.appendChild(item);
            }
        }
        
        var ACTIVE_TASK_KEY = 'skill-scanner-active-task';
        var activeTaskTimer = null;

        function stageTextForTask(task) {
            var stageText = {
                'queued': '任务排队中，等待开始扫描。',
                'running:p0': '正在执行高优先级风险检测。',
                'running:p1': '正在执行重点复核检测。',
                'running:p2': '正在执行低风险整改检测。',
                'scoring': '正在汇总风险等级并生成报告。',
                'completed': '扫描已完成，报告已生成。',
                'failed': '扫描失败，请根据失败原因处理后重试。'
            };
            return stageText[task.status] || '扫描中，请稍候。';
        }

        function stageBadgeForTask(task) {
            var stageBadge = {
                'queued': '排队中',
                'running:p0': '执行中',
                'running:p1': '复核中',
                'running:p2': '整改分析中',
                'scoring': '出报告中',
                'completed': '已完成',
                'failed': '失败'
            };
            return stageBadge[task.status] || '运行中';
        }

        function persistActiveTask(taskId) {
            localStorage.setItem(ACTIVE_TASK_KEY, JSON.stringify({ id: taskId, updated_at: Date.now() }));
        }

        function readActiveTask() {
            try {
                var raw = localStorage.getItem(ACTIVE_TASK_KEY);
                return raw ? JSON.parse(raw) : null;
            } catch (e) {
                return null;
            }
        }

        function clearActiveTask() {
            localStorage.removeItem(ACTIVE_TASK_KEY);
            if (activeTaskTimer) {
                clearInterval(activeTaskTimer);
                activeTaskTimer = null;
            }
        }

        function reportViewURL(reportId) {
            if (!reportId) {
                return '';
            }
            return '/reports/view/' + encodeURIComponent(reportId);
        }

        function renderTaskStatus(task) {
            var panel = document.getElementById('taskStatusPanel');
            var title = document.getElementById('taskStatusTitle');
            var text = document.getElementById('taskStatusText');
            var badge = document.getElementById('taskStatusBadge');
            var meta = document.getElementById('taskStatusMeta');
            var progress = document.getElementById('taskProgress');
            var viewBtn = document.getElementById('taskViewReportBtn');
            panel.classList.add('show');
            title.textContent = '当前扫描任务：' + (task.file_name || task.id || '未命名任务');
            text.textContent = stageTextForTask(task);
            badge.textContent = stageBadgeForTask(task);
            var summaryParts = [];
            if (typeof task.finding_count === 'number' && task.status === 'completed') {
                summaryParts.push('风险项：' + task.finding_count);
            }
            if (typeof task.high_risk === 'number' || typeof task.medium_risk === 'number' || typeof task.low_risk === 'number') {
                summaryParts.push('高/中/低：' + (task.high_risk || 0) + '/' + (task.medium_risk || 0) + '/' + (task.low_risk || 0));
            }
            if (task.pdf_engine) {
                summaryParts.push('PDF引擎：' + task.pdf_engine);
            }
            if (task.pdf_font_file) {
                summaryParts.push('字体：' + task.pdf_font_file);
            }
            if (task.pdf_trace) {
                summaryParts.push('链路：' + task.pdf_trace);
            }
            var summaryText = summaryParts.length ? ' | 概要：' + summaryParts.join('，') : '';
            meta.textContent = '任务ID：' + (task.id || '-') + (task.message ? ' | 说明：' + task.message : '') + summaryText;
            if (task.report_id) {
                viewBtn.href = reportViewURL(task.report_id);
                viewBtn.style.display = 'inline-flex';
            } else {
                viewBtn.href = '/reports';
                viewBtn.style.display = 'none';
            }
            clearChildren(progress);
            if (task.progress) {
                appendTaskProgressChip(progress, task.progress.p0, '高优先级检测');
                appendTaskProgressChip(progress, task.progress.p1, '重点复核检测');
                appendTaskProgressChip(progress, task.progress.p2, '低风险整改检测');
                appendTaskProgressChip(progress, task.progress.scoring, '报告生成');
            }
        }

        function appendTaskProgressChip(container, done, label) {
            var chip = document.createElement('span');
            if (done) {
                chip.className = 'done';
            }
            chip.textContent = label;
            container.appendChild(chip);
        }

        function startTaskPolling(taskId, loading, submitBtn) {
            if (!taskId) {
                return;
            }
            persistActiveTask(taskId);
            if (activeTaskTimer) {
                clearInterval(activeTaskTimer);
            }
            var poll = function() {
                fetchJSON('/api/scan/tasks/' + encodeURIComponent(taskId))
                    .then(function(task) {
                        if (!task || !task.status) {
                            return;
                        }
                        renderTaskStatus(task);
                        if (loading) {
                            loading.style.display = (task.status === 'completed' || task.status === 'failed') ? 'none' : 'block';
                            loading.querySelector('p').textContent = stageTextForTask(task);
                        }
                        if (task.status === 'completed') {
                            clearActiveTask();
                            if (submitBtn) {
                                submitBtn.disabled = false;
                            }
                            if (loading) {
                                loading.style.display = 'none';
                            }
                        } else if (task.status === 'failed') {
                            clearActiveTask();
                            if (submitBtn) {
                                submitBtn.disabled = false;
                            }
                        }
                    })
                    .catch(function(err) {
                        if (err && /无权访问|未登录|任务不存在/.test(err.message || '')) {
                            clearActiveTask();
                            document.getElementById('taskStatusPanel').classList.remove('show');
                        }
                        if (loading) {
                            loading.style.display = 'none';
                        }
                        if (submitBtn) {
                            submitBtn.disabled = false;
                        }
                    });
            };
            poll();
            activeTaskTimer = setInterval(poll, 1200);
        }

        document.getElementById('clearTaskStatusBtn').addEventListener('click', function() {
            clearActiveTask();
            document.getElementById('taskStatusPanel').classList.remove('show');
            document.getElementById('taskViewReportBtn').style.display = 'none';
            document.getElementById('submitBtn').disabled = false;
            document.getElementById('loading').style.display = 'none';
        });

        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (selectedFiles.length === 0) {
                alert('请至少选择一个文件');
                return;
            }
            
            var loading = document.getElementById('loading');
            var sb = document.getElementById('submitBtn');
            loading.style.display = 'block';
            sb.disabled = true;
            
            var formData = new FormData();
            // 将所有选中的文件都添加到 FormData
            for (var i = 0; i < selectedFiles.length; i++) {
                formData.append('files', selectedFiles[i]);
            }
            
            var selectedRuleIDs = collectSelectedRuleIDs();
            var customRules = collectCustomRules();
            var diffSettings = collectDifferentialSettings();
            if (selectedRuleIDs.length === 0 && customRules.length === 0) {
                alert('请至少勾选一条内置规则，或新增一条自定义规则');
                loading.style.display = 'none';
                sb.disabled = false;
                return;
            }
            formData.append('selected_rule_ids', selectedRuleIDs.join(','));
            formData.append('custom_rules', JSON.stringify(customRules));
            formData.append('differential_enabled', diffSettings.enabled ? 'true' : 'false');
            formData.append('evasion_delay_threshold_secs', String(diffSettings.delayThresholdSecs || ''));
            
            fetchJSON('/scan', { method: 'POST', body: formData })
                .then(function(data) {
                    if (data.success) {
                        startTaskPolling(data.task_id, loading, sb);
                    } else {
                        loading.style.display = 'none';
                        alert('扫描失败: ' + (data.error || '未知错误'));
                        sb.disabled = false;
                    }
                })
                .catch(function(err) {
                    loading.style.display = 'none';
                    alert('上传失败: ' + err.message);
                    sb.disabled = false;
                });
        });

        (function resumeTaskIfNeeded() {
            var savedTask = readActiveTask();
            if (savedTask && savedTask.id) {
                startTaskPolling(savedTask.id, document.getElementById('loading'), document.getElementById('submitBtn'));
            }
        })();
    </script>
</body>
</html>
`

// PersonalHTML is the personal center page template.
const PersonalHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>个人中心 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 600px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .info-row { padding: 16px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; }
        .info-row:last-child { border-bottom: none; }
        .info-row .label { color: #888; font-size: 14px; width: 100px; flex-shrink: 0; }
        .info-row .value { color: #333; font-weight: 500; }
        .admin-badge { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>👤 个人中心</h1></div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="personalUserMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>账号信息</h2>
            </div>
			<div class="panel" style="margin-top:20px;">
				<div class="panel-header">
					<h2>🤖 LLM 深度分析配置</h2>
				</div>
				<div style="padding:24px;">
					<div id="llmMsg" style="display:none; padding:12px; border-radius:6px; margin-bottom:16px;"></div>
					<div class="form-group">
						<label style="display:flex; align-items:center; gap:10px;">
							<input type="checkbox" id="llmEnabled"> 启用 LLM 辅助分析
						</label>
					</div>
					<div class="form-group">
						<label>选择提供商</label>
						<select id="llmProvider" style="padding:10px; border-radius:6px; border:1px solid #ddd; width:100%;">
							<option value="deepseek">DeepSeek</option>
							<option value="minimax">MiniMax</option>
						</select>
					</div>
					<div class="form-group" id="minimaxGroupDiv" style="display:none;">
						<label>MiniMax Group ID</label>
						<input type="text" id="minimaxGroupId" placeholder="输入 Group ID" style="width:100%; padding:10px; border-radius:6px; border:1px solid #ddd;">
					</div>
					<div class="form-group">
						<label>API Key</label>
						<input type="password" id="llmApiKey" placeholder="输入新的 API Key（留空则保留原有 Key）" style="width:100%; padding:10px; border-radius:6px; border:1px solid #ddd;">
						<p class="hint" style="font-size:13px; color:#888; margin-top:6px;">已保存的 Key 不会显示。输入新 Key 将替换旧 Key。</p>
					</div>
					<div style="display:flex; gap:12px;">
						<button id="saveLLMBtn" style="padding:10px 24px; background:#667eea; color:white; border:none; border-radius:6px; cursor:pointer;">保存配置</button>
						<button id="deleteLLMBtn" style="padding:10px 24px; background:white; color:#c00; border:1px solid #c00; border-radius:6px; cursor:pointer;">删除已保存的 API Key</button>
					</div>
				</div>
			</div>
            <div class="info-row">
                <span class="label">用户名</span>
                <span class="value">{{.Username}}</span>
            </div>
            <div class="info-row">
                <span class="label">团队</span>
                <span class="value">{{.Team}}</span>
            </div>
            <div class="info-row">
                <span class="label">创建时间</span>
                <span class="value">{{.CreatedAt}}</span>
            </div>
            <div class="info-row">
                <span class="label">报告数量</span>
                <span class="value">{{.ReportCount}} 份</span>
            </div>
            <div class="info-row">
                <span class="label">身份</span>
                <span class="value">
                    {{if .IsAdmin}}
                    <span class="admin-badge">👑 管理员</span>
                    {{else}}
                    <span>普通用户</span>
                    {{end}}
                </span>
            </div>
        </div>
    </div>
    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }
        bindDropdownMenu('personalUserMenuButton', 'userDropdown');
		// ----- LLM 配置相关 -----
		var llmProviderSelect = document.getElementById('llmProvider');
		var minimaxGroupDiv = document.getElementById('minimaxGroupDiv');

		llmProviderSelect.addEventListener('change', function() {
			minimaxGroupDiv.style.display = this.value === 'minimax' ? 'block' : 'none';
		});

		// 加载当前配置
		fetch('/api/user/llm', { headers: { 'Accept': 'application/json' } })
			.then(res => {
				var contentType = res.headers.get('Content-Type') || '';
				if (contentType.indexOf('application/json') === -1) {
					throw new Error('服务返回了非 JSON 响应');
				}
				if (!res.ok) {
					throw new Error('加载失败');
				}
				return res.json();
			})
			.then(data => {
				document.getElementById('llmEnabled').checked = data.enabled || false;
				llmProviderSelect.value = data.provider || 'deepseek';
				minimaxGroupDiv.style.display = data.provider === 'minimax' ? 'block' : 'none';
				var keyHint = document.querySelector('#llmApiKey + .hint');
				if (data.has_key) {
					keyHint.textContent = '已保存 API Key（未显示），输入新 Key 将替换。';
				} else {
					keyHint.textContent = '未保存 API Key，请输入。';
				}
			})
			.catch(() => {
				showLLMMsg('加载当前配置失败，请刷新后重试。', false);
			});

		function showLLMMsg(text, isSuccess) {
			var msg = document.getElementById('llmMsg');
			msg.textContent = text;
			msg.style.display = 'block';
			msg.style.background = isSuccess ? '#efe' : '#fee';
			msg.style.color = isSuccess ? '#060' : '#c00';
			setTimeout(() => msg.style.display = 'none', 3000);
		}

		document.getElementById('saveLLMBtn').addEventListener('click', function() {
			var enabled = document.getElementById('llmEnabled').checked;
			var provider = llmProviderSelect.value;
			var apiKey = document.getElementById('llmApiKey').value.trim();
			var groupId = document.getElementById('minimaxGroupId') ? document.getElementById('minimaxGroupId').value.trim() : '';

			var payload = {
				enabled: enabled,
				provider: provider,
				api_key: apiKey,
				minimax_group_id: groupId,
				delete_key: false
			};

			fetch('/api/user/llm', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify(payload)
			})
			.then(res => {
				if (!res.ok) throw new Error('保存失败');
				return res.json();
			})
			.then(() => {
				showLLMMsg('✅ 配置已保存', true);
				document.getElementById('llmApiKey').value = '';
				var hint = document.querySelector('#llmApiKey + .hint');
				if (apiKey) {
					hint.textContent = '已保存新的 API Key。';
				} else {
					hint.textContent = '配置已更新，API Key 保持不变。';
				}
			})
			.catch(err => showLLMMsg('保存失败: ' + err.message, false));
		});

		document.getElementById('deleteLLMBtn').addEventListener('click', function() {
			if (!confirm('确定要删除已保存的 API Key 吗？')) return;

			var enabled = document.getElementById('llmEnabled').checked;
			var provider = llmProviderSelect.value;
			var groupId = document.getElementById('minimaxGroupId') ? document.getElementById('minimaxGroupId').value.trim() : '';

			fetch('/api/user/llm', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({
					enabled: enabled,
					provider: provider,
					api_key: '',
					minimax_group_id: groupId,
					delete_key: true
				})
			})
			.then(res => {
				if (!res.ok) throw new Error('删除失败');
				return res.json();
			})
			.then(() => {
				showLLMMsg('✅ API Key 已删除', true);
				document.querySelector('#llmApiKey + .hint').textContent = '未保存 API Key，请输入。';
			})
			.catch(err => showLLMMsg('删除失败: ' + err.message, false));
		});
    </script>
</body>
</html>
`

// AdminUsersHTML is the admin user management page template.
const AdminUsersHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户管理 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        .msg { padding: 12px 24px; border-radius: 8px; margin-bottom: 16px; }
        .msg.error { background: #fee; color: #c00; }
        .msg.success { background: #efe; color: #060; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; margin-bottom: 20px; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 12px; align-items: end; padding: 24px; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { color: #555; font-size: 14px; margin-bottom: 6px; font-weight: 500; }
        .form-group input { padding: 10px 14px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 14px; }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .submit-btn { padding: 10px 24px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; white-space: nowrap; }
        .submit-btn:hover { transform: translateY(-1px); }
        .user-table { width: 100%; border-collapse: collapse; }
        .user-table th, .user-table td { padding: 14px 24px; text-align: left; border-bottom: 1px solid #eee; }
        .user-table th { background: #f9f9f9; color: #666; font-size: 13px; font-weight: 600; }
        .user-table td { color: #333; }
        .user-table tr:last-child td { border-bottom: none; }
        .admin-tag { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .team-tag { background: #eef; color: #06c; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .delete-btn { color: #c00; background: none; border: 1px solid #c00; padding: 5px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .delete-btn:hover { background: #fee; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>👥 用户管理</h1></div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="adminUsersMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        {{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
        {{if .Success}}<div class="msg success">{{.Success}}</div>{{end}}

        <div class="panel">
            <div class="panel-header">
                <h2>添加用户</h2>
            </div>
            <form method="POST" action="/admin/users">
                <input type="hidden" name="action" value="add">
                <div class="form-row">
                    <div class="form-group">
                        <label>用户名</label>
                        <input type="text" name="username" placeholder="请输入用户名" required>
                    </div>
                    <div class="form-group">
                        <label>密码</label>
                        <input type="password" name="password" placeholder="请输入密码" required>
                    </div>
                    <div class="form-group">
                        <label>团队名称</label>
                        <input type="text" name="team" placeholder="可选，如无则用户无团队">
                    </div>
                    <button type="submit" class="submit-btn">添加用户</button>
                </div>
            </form>
        </div>

        <div class="panel">
            <div class="panel-header">
                <h2>用户列表</h2>
            </div>
            <table class="user-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>团队</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Users}}
                    <tr>
                        <td>{{.Username}}{{if .IsAdmin}} <span class="admin-tag">管理员</span>{{end}}</td>
                        <td>{{.Team}}</td>
                        <td>{{.CreatedAt}}</td>
                        <td>
                            {{if .CanDelete}}
                            <form method="POST" action="/admin/users" style="display:inline;" class="delete-user-form" data-confirm="{{.DeleteConfirmMessage}}">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="username" value="{{.Username}}">
                                <button type="submit" class="delete-btn">删除</button>
                            </form>
                            {{else}}
                            <span style="color:#98a2b3;font-size:13px;">不可删除</span>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }
        bindDropdownMenu('adminUsersMenuButton', 'userDropdown');
        document.querySelectorAll('.delete-user-form').forEach(function(form) {
            form.addEventListener('submit', function(e) {
                var message = form.getAttribute('data-confirm') || '确认执行删除操作吗？';
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>
`

// LoginLogHTML is the login log viewer page (admin only).
const LoginLogHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录日志 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .readonly-note { background: #f0f7ff; color: #667eea; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .log-table { width: 100%; border-collapse: collapse; }
        .log-table th, .log-table td { padding: 14px 24px; text-align: left; border-bottom: 1px solid #eee; }
        .log-table th { background: #f9f9f9; color: #666; font-size: 13px; font-weight: 600; }
        .log-table td { color: #333; font-size: 14px; }
        .log-table tr:last-child td { border-bottom: none; }
        .result-tag { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .result-tag.success { background: #efe; color: #060; }
        .result-tag.fail { background: #fee; color: #c00; }
        .empty { text-align: center; padding: 60px; color: #888; }
        .ip { color: #888; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;"><h1>📋 登录日志</h1></div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="loginLogUserMenuButton" type="button">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>登录记录</h2>
                <span class="readonly-note">🔒 此记录不可删除，仅管理员可见</span>
            </div>
            {{if .Logs}}
            <table class="log-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>登录时间</th>
                        <th>结果</th>
                        <th>IP 地址</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Logs}}
                    <tr>
                        <td>{{.Username}}</td>
                        <td>{{.Timestamp}}</td>
                        <td><span class="result-tag {{.ResultClass}}">{{.Result}}</span></td>
                        <td><span class="ip">{{.IP}}</span></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">
                <div style="font-size:40px;margin-bottom:10px;">📭</div>
                暂无登录记录
            </div>
            {{end}}
        </div>
    </div>
    <script>
        function bindDropdownMenu(buttonId, menuId) {
            var button = document.getElementById(buttonId);
            var menu = document.getElementById(menuId);
            if (!button || !menu) {
                return;
            }
            button.addEventListener('click', function() {
                menu.classList.toggle('show');
            });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        }
        bindDropdownMenu('loginLogUserMenuButton', 'userDropdown');
    </script>
</body>
</html>
`

// SettingsHTML is the system settings page template.
const SettingsHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统设置 - 技能扫描器</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
.header h1 { font-size: 24px; }
.header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
.header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
.header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
.header-nav a.active { background: rgba(255,255,255,0.25); color: white; }
.header-right { display: flex; align-items: center; gap: 10px; }
.user-dropdown { position: relative; }
.dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
.dropdown-btn:hover { background: rgba(255,255,255,0.3); }
.dropdown-btn .arrow { font-size: 10px; }
.dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
.dropdown-menu.show { display: block; }
.dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
.dropdown-menu a:hover { background: #f5f6fa; }
.dropdown-menu a.danger { color: #c00; }
.dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
.container { max-width: 800px; margin: 40px auto; padding: 0 20px; }
.card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
.card h2 { color: #333; margin-bottom: 30px; font-size: 22px; }
.form-group { margin-bottom: 24px; }
.form-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
.form-group input { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
.form-group input:focus { outline: none; border-color: #667eea; }
.form-group .hint { font-size: 13px; color: #888; margin-top: 6px; }
.form-group .configured { font-size: 13px; color: #060; background: #efe; padding: 6px 12px; border-radius: 6px; margin-top: 8px; display: inline-block; }
.section-title { color: #333; font-size: 18px; margin: 30px 0 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }
.error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; display: none; }
.success { background: #efe; color: #060; padding: 12px; border-radius: 6px; margin-bottom: 20px; display: none; }
button { padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s; }
button:hover { transform: translateY(-2px); }
button:disabled { opacity: 0.7; cursor: not-allowed; }
</style>
</head>
<body>
<div class="header">
<div style="display: flex; align-items: center; gap: 20px;">
<h1>🎯 技能扫描器</h1>
</div>
<div class="header-nav">
<a href="/dashboard">🎯 首页</a>
<a href="/scan">🔍 扫描</a>
<a href="/reports">📊 报告</a>
<a href="/admission/skills">准入库</a>
<a href="/combination/overview">组合分析</a>
</div>
<div class="header-right">
<div class="user-dropdown">
<button class="dropdown-btn" id="settingsUserMenuButton" type="button">
👤 {{.Username}} <span class="arrow">▾</span>
</button>
<div class="dropdown-menu" id="userDropdown">
{{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
{{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
{{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
<div class="divider"></div>
<a href="/change-password">🔑 修改密码</a>
<a href="/logout" class="danger">🚪 退出</a>
</div>
</div>
</div>
</div>
<div class="container">
<div class="card">
<h2>⚙️ 系统设置</h2>
<div id="errorMsg" class="error"></div>
<div id="successMsg" class="success"></div>
<div class="section-title">🤖 LLM 深度分析配置</div>
<p class="hint">配置大模型 API 密钥，启用代码深度意图分析能力，帮助检测隐蔽的安全风险。</p>

<div class="form-group">
<label for="deepseek_key">DeepSeek API Key</label>
<input type="password" id="deepseek_key" placeholder="输入你的 DeepSeek API Key" value="{{if .Config}}{{.Config.DeepSeekAPIKey}}{{end}}">
{{if and .Config .Config.DeepSeekAPIKey}}
<div class="configured">✅ 已配置，当前密钥已脱敏存储</div>
{{end}}
<div class="hint">如果你使用 DeepSeek 大模型，请在此填写 API Key。</div>
</div>

<div class="form-group">
<label for="minimax_group">MiniMax Group ID</label>
<input type="text" id="minimax_group" placeholder="输入你的 MiniMax Group ID" value="{{if .Config}}{{.Config.MiniMaxGroupID}}{{end}}">
{{if and .Config .Config.MiniMaxGroupID}}
<div class="configured">✅ 已配置，当前 Group ID: {{.Config.MiniMaxGroupID}}</div>
{{end}}
</div>

<div class="form-group">
<label for="minimax_key">MiniMax API Key</label>
<input type="password" id="minimax_key" placeholder="输入你的 MiniMax API Key" value="{{if .Config}}{{.Config.MiniMaxAPIKey}}{{end}}">
{{if and .Config .Config.MiniMaxAPIKey}}
<div class="configured">✅ 已配置，当前密钥已脱敏存储</div>
{{end}}
<div class="hint">如果你使用 MiniMax 大模型，请在此填写 Group ID 和 API Key。</div>
</div>

<button id="saveBtn">保存配置</button>
</div>
</div>

<script>
function bindDropdownMenu(buttonId, menuId) {
    var button = document.getElementById(buttonId);
    var menu = document.getElementById(menuId);
    if (!button || !menu) {
        return;
    }
    button.addEventListener('click', function() {
        menu.classList.toggle('show');
    });
    document.addEventListener('click', function(event) {
        var dropdown = button.closest('.user-dropdown');
        if (dropdown && !dropdown.contains(event.target)) {
            menu.classList.remove('show');
        }
    });
}
bindDropdownMenu('settingsUserMenuButton', 'userDropdown');

document.getElementById('saveBtn').addEventListener('click', async function() {
    const btn = this;
    const errorMsg = document.getElementById('errorMsg');
    const successMsg = document.getElementById('successMsg');
    errorMsg.style.display = 'none';
    successMsg.style.display = 'none';
    btn.disabled = true;
    btn.textContent = '保存中...';
    try {
        const config = {
            deepseek_api_key: document.getElementById('deepseek_key').value.trim(),
            minimax_group_id: document.getElementById('minimax_group').value.trim(),
            minimax_api_key: document.getElementById('minimax_key').value.trim()
        };
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.error || '保存失败');
        }
        successMsg.textContent = data.success;
        successMsg.style.display = 'block';
        // 刷新页面，更新配置显示
        setTimeout(() => window.location.reload(), 1000);
    } catch (e) {
        errorMsg.textContent = e.message;
        errorMsg.style.display = 'block';
        btn.disabled = false;
        btn.textContent = '保存配置';
    }
});
</script>
</body>
</html>
`

const AdmissionListHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>准入技能库 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .dropdown-menu a.danger { color: #c00; }
        .container { max-width: 1100px; margin: 40px auto; padding: 0 20px; }
        .toolbar { background: white; border-radius: 12px; padding: 18px 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 18px; }
        .search-form { display: grid; grid-template-columns: minmax(220px, 1.6fr) repeat(3, minmax(140px, 1fr)) auto auto; gap: 12px; }
        .search-form input, .search-form select { width: 100%; padding: 12px 14px; border: 1px solid #d0d5dd; border-radius: 8px; }
        .search-form button, .search-form a { padding: 12px 18px; border: none; border-radius: 8px; background: #667eea; color: white; cursor: pointer; text-decoration: none; text-align: center; }
        .search-form a { background: #98a2b3; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .item { padding: 18px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
        .item:last-child { border-bottom: none; }
        .title { font-weight: 600; color: #111827; }
        .meta { color: #667085; font-size: 13px; margin-top: 6px; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
        .action { display: inline-block; padding: 8px 14px; background: #0f766e; color: white; text-decoration: none; border-radius: 8px; white-space: nowrap; }
        .action.secondary { background: #eef2ff; color: #4338ca; }
        .empty { text-align: center; color: #667085; padding: 56px 24px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>准入技能库</h1>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports">报告</a>
            <a href="/admission/skills" class="active">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="admissionListUserMenuButton" type="button">{{.Username}} <span>▾</span></button>
                <div class="dropdown-menu" id="admissionListUserDropdown">
                    {{if .HasPersonal}}<a href="/personal">个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">修改密码</a>
                    <a href="/logout" class="danger">退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="toolbar">
            <form method="GET" action="/admission/skills" class="search-form">
                <input type="text" name="q" value="{{.Query}}" placeholder="按技能名、版本、风险标签搜索">
                <select name="status">
                    <option value="">全部状态</option>
                    <option value="pending" {{if eq .AdmissionStatus "pending"}}selected{{end}}>待定</option>
                    <option value="approved" {{if eq .AdmissionStatus "approved"}}selected{{end}}>已准入</option>
                    <option value="rejected" {{if eq .AdmissionStatus "rejected"}}selected{{end}}>拒绝准入</option>
                </select>
                <select name="decision">
                    <option value="">全部结论</option>
                    <option value="review" {{if eq .ReviewDecision "review"}}selected{{end}}>需人工复核</option>
                    <option value="pass" {{if eq .ReviewDecision "pass"}}selected{{end}}>建议通过</option>
                    <option value="block" {{if eq .ReviewDecision "block"}}selected{{end}}>需完成修复并复测</option>
                </select>
                <input type="text" name="risk_tag" value="{{.RiskTag}}" placeholder="风险标签，如 outbound_network">
                <button type="submit">搜索</button>
                <a href="/admission/skills">重置</a>
            </form>
        </div>
        <div class="panel">
            <div class="panel-header"><h2>已录入技能</h2></div>
            {{if .Items}}
                {{range .Items}}
                <div class="item">
                    <div>
                        <div class="title">{{.DisplayName}}</div>
                        <div class="meta">ID {{.SkillID}} · 版本 {{.Version}} · 状态 {{.AdmissionStatus}} · 决策 {{.ReviewDecision}}</div>
                        <div class="meta">来源报告 {{.ReportID}} · 更新时间 {{.UpdatedAt}}</div>
                        {{if .RiskTags}}
                        <div class="tags">
                            {{range .RiskTags}}<span class="tag">{{.}}</span>{{end}}
                        </div>
                        {{end}}
                    </div>
                    <div class="actions">
                        <a href="{{.AddToComboURL}}" class="action secondary">加入组合</a>
                        <a href="/admission/skills/{{.SkillID}}" class="action">查看详情</a>
                    </div>
                </div>
                {{end}}
            {{else}}
                <div class="empty">准入技能库为空，请先从报告页录入技能。</div>
            {{end}}
        </div>
    </div>
    <script>
        (function() {
            var button = document.getElementById('admissionListUserMenuButton');
            var menu = document.getElementById('admissionListUserDropdown');
            if (!button || !menu) return;
            button.addEventListener('click', function() { menu.classList.toggle('show'); });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        })();
    </script>
</body>
</html>
`

const AdmissionImportHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>录入准入库 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .dropdown-menu a.danger { color: #c00; }
        .container { max-width: 860px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 28px 30px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 10px; }
        .meta { color: #667085; font-size: 14px; margin-bottom: 18px; }
        .error { background: #fff1f0; color: #b42318; border: 1px solid #f0b7bf; padding: 12px 14px; border-radius: 10px; margin-bottom: 16px; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; color: #344054; font-weight: 600; margin-bottom: 8px; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px 14px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 14px; }
        .form-group textarea { min-height: 110px; resize: vertical; }
        .hint { color: #667085; font-size: 12px; margin-top: 6px; }
        .actions { display: flex; gap: 12px; margin-top: 20px; }
        .primary-btn, .secondary-btn { display: inline-block; padding: 12px 18px; border-radius: 8px; text-decoration: none; border: none; cursor: pointer; font-size: 14px; }
        .primary-btn { background: #0f766e; color: white; }
        .secondary-btn { background: #eef2ff; color: #4338ca; }
    </style>
</head>
<body>
    <div class="header">
        <h1>录入准入库</h1>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports" class="active">报告</a>
            <a href="/admission/skills">准入库</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="admissionImportUserMenuButton" type="button">{{.Username}} <span>▾</span></button>
                <div class="dropdown-menu" id="admissionImportUserDropdown">
                    {{if .HasPersonal}}<a href="/personal">个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">修改密码</a>
                    <a href="/logout" class="danger">退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <div class="title">确认录入扫描报告</div>
            <div class="meta">报告 ID: {{.ReportID}} | 文件名: {{.FileName}}</div>
            {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
            <form method="POST" action="/admission/import/{{.ReportID}}">
                <div class="form-group">
                    <label for="display_name">技能显示名</label>
                    <input type="text" id="display_name" name="display_name" value="{{.DefaultName}}" required>
                </div>
                <div class="form-group">
                    <label for="version">版本</label>
                    <input type="text" id="version" name="version" placeholder="例如 v1.0.0">
                </div>
                <div class="form-group">
                    <label for="description">用途说明</label>
                    <textarea id="description" name="description">{{.DefaultDesc}}</textarea>
                    <div class="hint">建议补充该技能的主要用途，后续会用于准入库检索和人工审查。</div>
                </div>
                <div class="form-group">
                    <label for="admission_status">准入状态</label>
                    <select id="admission_status" name="admission_status">
                        <option value="pending">待定</option>
                        <option value="approved">已准入</option>
                        <option value="rejected">拒绝准入</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="review_decision">审查结论</label>
                    <select id="review_decision" name="review_decision">
                        <option value="review">需人工复核</option>
                        <option value="pass">建议通过</option>
                        <option value="block">需完成修复并复测</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="review_summary">审查摘要</label>
                    <textarea id="review_summary" name="review_summary" placeholder="补充录入原因、限制条件或审查备注"></textarea>
                </div>
                <div class="actions">
                    <button type="submit" class="primary-btn">确认录入</button>
                    <a href="/reports" class="secondary-btn">返回报告列表</a>
                </div>
            </form>
        </div>
    </div>
    <script>
        (function() {
            var button = document.getElementById('admissionImportUserMenuButton');
            var menu = document.getElementById('admissionImportUserDropdown');
            if (!button || !menu) return;
            button.addEventListener('click', function() { menu.classList.toggle('show'); });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        })();
    </script>
</body>
</html>
`

const CombinationOverviewHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>组合风险分析 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .dropdown-menu a.danger { color: #c00; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; display: grid; gap: 18px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 24px; }
        .section-title { color: #111827; font-size: 20px; margin-bottom: 16px; }
        .search-grid { display: grid; grid-template-columns: 2fr auto auto; gap: 12px; margin-bottom: 18px; align-items: end; }
        .search-grid input { width: 100%; padding: 12px 14px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 14px; }
        .skill-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
        .skill-option { border: 1px solid #eaecf0; border-radius: 10px; padding: 14px; display: flex; gap: 10px; align-items: flex-start; }
        .skill-option input { margin-top: 4px; }
        .skill-name { font-weight: 600; color: #111827; }
        .meta { color: #667085; font-size: 13px; margin-top: 4px; }
        .actions { margin-top: 16px; }
        .primary-btn, .secondary-btn { display: inline-block; padding: 12px 18px; border-radius: 8px; border: none; cursor: pointer; text-decoration: none; font-size: 14px; }
        .primary-btn { background: #0f766e; color: white; }
        .secondary-btn { background: #eef2ff; color: #4338ca; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .list { display: grid; gap: 10px; }
        .list-item { border: 1px solid #eaecf0; border-radius: 10px; padding: 12px 14px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
        .summary-box { background: #f8fafc; border-radius: 10px; padding: 12px 14px; }
        .summary-box strong { display: block; margin-bottom: 6px; color: #344054; font-size: 12px; }
        .summary-box.risk-high { background: #fef2f2; }
        .summary-box.risk-medium { background: #fff7ed; }
        .summary-box.risk-low { background: #ecfdf3; }
        .selection-toolbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin: 14px 0 16px; flex-wrap: wrap; }
        .selection-badges { display: flex; gap: 8px; flex-wrap: wrap; }
        .selection-badge { display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; background: #f8fafc; border: 1px solid #dbe2f3; border-radius: 999px; font-size: 13px; color: #344054; }
        .selection-badge a { color: #b42318; text-decoration: none; font-weight: 600; }
        .recommendation { margin-top: 12px; color: #475467; line-height: 1.6; }
        .top-link { margin-top: 12px; }
        .top-link a { color: #4338ca; text-decoration: none; font-size: 14px; }
        .empty { color: #667085; font-size: 14px; padding: 12px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>组合风险分析</h1>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports">报告</a>
            <a href="/admission/skills">准入库</a>
            <a href="/combination/overview" class="active">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="combinationUserMenuButton" type="button">{{.Username}} <span>▾</span></button>
                <div class="dropdown-menu" id="combinationUserDropdown">
                    {{if .HasPersonal}}<a href="/personal">个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">修改密码</a>
                    <a href="/logout" class="danger">退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <div class="section-title">选择技能组合</div>
            <form method="GET" action="/combination/overview">
                {{range .SelectedSkills}}<input type="hidden" name="skill_id" value="{{.SkillID}}">{{end}}
                <div class="search-grid">
                    <input type="text" name="q" value="{{.SearchQuery}}" placeholder="模糊搜索技能 ID、技能名">
                    <select name="status">
                        <option value="">全部准入状态</option>
                        <option value="pending" {{if eq .AdmissionStatus "pending"}}selected{{end}}>待定</option>
                        <option value="approved" {{if eq .AdmissionStatus "approved"}}selected{{end}}>已准入</option>
                        <option value="rejected" {{if eq .AdmissionStatus "rejected"}}selected{{end}}>拒绝准入</option>
                    </select>
                    <select name="decision">
                        <option value="">全部审查结论</option>
                        <option value="review" {{if eq .ReviewDecision "review"}}selected{{end}}>需人工复核</option>
                        <option value="pass" {{if eq .ReviewDecision "pass"}}selected{{end}}>建议通过</option>
                        <option value="block" {{if eq .ReviewDecision "block"}}selected{{end}}>需完成修复并复测</option>
                    </select>
                    <input type="text" name="risk_tag" value="{{.RiskTag}}" placeholder="风险标签，如 outbound_network">
                    <button type="submit" class="secondary-btn">搜索技能</button>
                    <a href="/combination/overview" class="secondary-btn">重置</a>
                </div>
            </form>
            {{if .SelectedSkills}}
            <div class="selection-toolbar">
                <div class="selection-badges">
                    {{range .SelectedSkills}}
                    <span class="selection-badge">{{.DisplayName}} ({{.SkillID}}) <a href="{{.RemoveComboURL}}">移除</a></span>
                    {{end}}
                </div>
                <a href="{{.ClearSelectionURL}}" class="secondary-btn">清空已选</a>
            </div>
            {{end}}
            <form method="GET" action="/combination/overview">
                {{if .SearchQuery}}<input type="hidden" name="q" value="{{.SearchQuery}}">{{end}}
                {{if .AdmissionStatus}}<input type="hidden" name="status" value="{{.AdmissionStatus}}">{{end}}
                {{if .ReviewDecision}}<input type="hidden" name="decision" value="{{.ReviewDecision}}">{{end}}
                {{if .RiskTag}}<input type="hidden" name="risk_tag" value="{{.RiskTag}}">{{end}}
                <div class="skill-grid">
                    {{if .Items}}
                    {{range .Items}}
                    <label class="skill-option">
                        <input type="checkbox" name="skill_id" value="{{.SkillID}}" {{if .Selected}}checked{{end}}>
                        <div>
                            <div class="skill-name">{{.DisplayName}}</div>
                            <div class="meta">ID {{.SkillID}} · 版本 {{.Version}}</div>
                            <div class="meta">状态 {{.AdmissionStatus}} · 结论 {{.ReviewDecision}}</div>
                        </div>
                    </label>
                    {{end}}
                    {{else}}
                    <div class="empty">没有匹配的技能，请调整搜索词后重试。</div>
                    {{end}}
                </div>
                <div class="actions"><button type="submit" class="primary-btn">分析组合风险</button></div>
            </form>
        </div>
        <div class="card">
            <div class="section-title">组合摘要</div>
            <div class="summary-grid" style="margin-bottom:16px;">
                <div class="summary-box risk-{{.Conclusion.RiskLevel}}">
                    <strong>组合结论</strong>
                    {{.Conclusion.RiskLabel}}
                </div>
                <div class="summary-box">
                    <strong>已选技能数</strong>
                    {{.Conclusion.SelectedSkillCount}}
                </div>
                <div class="summary-box">
                    <strong>命中能力数</strong>
                    {{.Conclusion.CapabilityCount}}
                </div>
                <div class="summary-box">
                    <strong>敏感信号数</strong>
                    {{.Conclusion.SensitiveSignalCount}}
                </div>
                <div class="summary-box">
                    <strong>高风险项</strong>
                    {{.Conclusion.HighRiskCount}}
                </div>
                <div class="summary-box">
                    <strong>中风险项</strong>
                    {{.Conclusion.MediumRiskCount}}
                </div>
                <div class="summary-box">
                    <strong>低风险项</strong>
                    {{.Conclusion.LowRiskCount}}
                </div>
            </div>
            {{if .RunID}}
            <div class="meta" style="margin-bottom:12px;">快照 ID {{.RunID}}{{if .SavedAt}} · 更新时间 {{.SavedAt}}{{end}}</div>
            {{end}}
            {{if .HistoryURL}}<div class="top-link"><a href="{{.HistoryURL}}">查看历史快照</a></div>{{end}}
            <div class="recommendation">{{.Conclusion.Recommendation}}</div>
            {{if .SelectedSkills}}
            <div class="meta" style="margin-top:14px;">以下列表展示当前纳入组合分析的技能资产。</div>
            {{end}}
            {{if .SelectedSkills}}
            <div class="list">
                {{range .SelectedSkills}}
                <div class="list-item">
                    <strong>{{.DisplayName}}</strong>
                    <div class="meta">{{.SkillID}} · {{.AdmissionStatus}} · {{.ReviewDecision}}</div>
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">请先选择两个或以上技能以查看聚合结果。</div>
            {{end}}
        </div>
        <div class="card">
            <div class="section-title">聚合能力画像</div>
            {{if .CapabilitySummary}}
            <div class="summary-grid">
                {{range .CapabilitySummary}}
                <div class="summary-box"><strong>能力</strong>{{.}}</div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">尚未形成聚合能力。</div>
            {{end}}
            {{if .CombinedTags}}
            <div class="tags" style="margin-top:14px;">
                {{range .CombinedTags}}<span class="tag">{{.}}</span>{{end}}
            </div>
            {{end}}
        </div>
        <div class="card">
            <div class="section-title">聚合残余风险</div>
            {{if .CombinedRisks}}
            <div class="list">
                {{range .CombinedRisks}}
                <div class="list-item">
                    <strong>{{.Risk.Title}}</strong>
                    <div class="meta">类别 {{.Risk.Category}} · 等级 {{.Risk.Level}}</div>
                    <div class="meta">{{.Risk.Description}}</div>
                    {{if .Risk.Mitigation}}<div class="meta">建议：{{.Risk.Mitigation}}</div>{{end}}
                    {{if .SourceSkills}}
                    <div class="meta">来源技能：{{range $index, $item := .SourceSkills}}{{if $index}}、{{end}}{{$item.DisplayName}} ({{$item.SkillID}}){{end}}</div>
                    {{end}}
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">当前选择尚未聚合出残余风险。</div>
            {{end}}
        </div>
        <div class="card">
            <div class="section-title">动态链路推理</div>
            {{if .InferredChains}}
            <div class="list">
                {{range .InferredChains}}
                <div class="list-item">
                    <strong>{{.Title}}</strong>
                    <div class="meta">等级 {{.Level}}</div>
                    <div class="meta">{{.Summary}}</div>
                    {{if .Evidence}}<div class="meta">触发证据：{{range $index, $item := .Evidence}}{{if $index}}、{{end}}{{$item}}{{end}}</div>{{end}}
                    {{if .Recommendation}}<div class="meta">建议：{{.Recommendation}}</div>{{end}}
                    {{if .SourceSkills}}<div class="meta">涉及技能：{{range $index, $item := .SourceSkills}}{{if $index}}、{{end}}{{$item.DisplayName}} ({{$item.SkillID}}){{end}}</div>{{end}}
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">当前选择尚未形成明显的跨技能动态链路。</div>
            {{end}}
        </div>
    </div>
    <script>
        (function() {
            var button = document.getElementById('combinationUserMenuButton');
            var menu = document.getElementById('combinationUserDropdown');
            if (!button || !menu) return;
            button.addEventListener('click', function() { menu.classList.toggle('show'); });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        })();
    </script>
</body>
</html>
`

const CombinationRunsHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>组合快照历史 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header-nav a { color: rgba(255,255,255,0.85); text-decoration: none; margin-right: 12px; }
        .header-nav .active { color: white; }
        .container { max-width: 1100px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 24px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 14px; }
        .filters { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr auto; gap: 12px; margin-bottom: 18px; }
        .filters input, .filters select { width: 100%; padding: 10px 12px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 14px; }
        .filters .actions { display: flex; gap: 10px; }
        .filters button, .filters a { display: inline-block; padding: 10px 14px; border-radius: 8px; border: none; text-decoration: none; font-size: 14px; cursor: pointer; }
        .filters button { background: #0f766e; color: white; }
        .filters a { background: #eef2ff; color: #4338ca; }
        .list { display: grid; gap: 12px; }
        .item { border: 1px solid #eaecf0; border-radius: 10px; padding: 14px; }
        .item a { color: #111827; text-decoration: none; font-weight: 600; }
        .meta { color: #667085; font-size: 13px; margin-top: 6px; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .links { display: flex; gap: 12px; margin-top: 10px; }
        .links a { color: #4338ca; text-decoration: none; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <div><strong>组合快照历史</strong></div>
        <div class="header-nav">
            <a href="/combination/overview">组合分析</a>
            <a href="/combination/runs" class="active">历史快照</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <div class="title">历史快照</div>
            <form method="GET" action="/combination/runs" class="filters">
                <input type="text" name="q" value="{{.Query}}" placeholder="搜索 run_id、skill_id、能力、标签、结论">
                <select name="risk_level">
                    <option value="" {{if eq .RiskLevel ""}}selected{{end}}>全部风险等级</option>
                    <option value="high" {{if eq .RiskLevel "high"}}selected{{end}}>高风险</option>
                    <option value="medium" {{if eq .RiskLevel "medium"}}selected{{end}}>中风险</option>
                    <option value="low" {{if eq .RiskLevel "low"}}selected{{end}}>低风险</option>
                </select>
                <input type="date" name="start_date" value="{{.StartDate}}">
                <input type="date" name="end_date" value="{{.EndDate}}">
                <select name="sort">
                    <option value="updated_desc" {{if eq .Sort "updated_desc"}}selected{{end}}>最近更新优先</option>
                    <option value="updated_asc" {{if eq .Sort "updated_asc"}}selected{{end}}>最早更新优先</option>
                </select>
                <div class="actions">
                    <button type="submit">筛选</button>
                    <a href="/combination/runs">重置</a>
                </div>
            </form>
            {{if .Items}}
            <div class="list">
                {{range .Items}}
                <div class="item">
                    <a href="/combination/runs/{{.RunID}}">{{.RunID}}</a>
                    <div class="meta">风险结论 {{.RiskLabel}} · 已选技能 {{.SelectedSkillCount}} · 更新时间 {{.UpdatedAt}}</div>
                    <div class="links">{{if .OverviewURL}}<a href="{{.OverviewURL}}">重新载入该组合</a>{{end}}</div>
                    {{if .Capabilities}}<div class="meta">能力：{{range $index, $item := .Capabilities}}{{if $index}}、{{end}}{{$item}}{{end}}</div>{{end}}
                    {{if .CombinedTags}}<div class="tags">{{range .CombinedTags}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">暂无组合分析快照。</div>
            {{end}}
        </div>
    </div>
</body>
</html>
`

const CombinationRunHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>组合快照详情 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; }
        .header a { color: rgba(255,255,255,0.9); text-decoration: none; }
        .container { max-width: 1100px; margin: 40px auto; padding: 0 20px; display: grid; gap: 18px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 24px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 12px; }
        .meta { color: #667085; font-size: 13px; margin-top: 6px; }
        .list { display: grid; gap: 10px; }
        .list-item { border: 1px solid #eaecf0; border-radius: 10px; padding: 12px 14px; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .links { display: flex; gap: 12px; margin-top: 10px; }
        .links a { color: #4338ca; text-decoration: none; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header"><a href="/combination/runs">返回组合快照历史</a></div>
    <div class="container">
        <div class="card">
            <div class="title">组合快照详情</div>
            <div class="meta">快照 ID {{.RunID}}</div>
            <div class="meta">创建时间 {{.SavedAt}} · 更新时间 {{.UpdatedAt}}</div>
            <div class="meta">风险结论 {{.RiskLabel}}</div>
            <div class="links">
                {{if .ExportJSONURL}}<a href="{{.ExportJSONURL}}">导出 JSON</a>{{end}}
                {{if .ExportMarkdownURL}}<a href="{{.ExportMarkdownURL}}">导出 Markdown</a>{{end}}
                {{if .OverviewURL}}<a href="{{.OverviewURL}}">重新载入该组合</a>{{end}}
            </div>
            {{if .SelectedSkills}}<div class="meta">已选技能：{{range $index, $item := .SelectedSkills}}{{if $index}}、{{end}}{{$item.DisplayName}} ({{$item.SkillID}}){{end}}</div>{{end}}
            {{if .Capabilities}}<div class="meta">能力：{{range $index, $item := .Capabilities}}{{if $index}}、{{end}}{{$item}}{{end}}</div>{{end}}
            {{if .CombinedTags}}<div class="tags">{{range .CombinedTags}}<span class="tag">{{.}}</span>{{end}}</div>{{end}}
        </div>
        <div class="card">
            <div class="title">聚合残余风险</div>
            {{if .CombinedRisks}}
            <div class="list">
                {{range .CombinedRisks}}
                <div class="list-item">
                    <strong>{{.Title}}</strong>
                    <div class="meta">类别 {{.Category}} · 等级 {{.Level}}</div>
                    <div class="meta">{{.Description}}</div>
                    {{if .Mitigation}}<div class="meta">建议：{{.Mitigation}}</div>{{end}}
                </div>
                {{end}}
            </div>
            {{else}}<div class="meta">暂无聚合残余风险。</div>{{end}}
        </div>
        <div class="card">
            <div class="title">动态链路推理</div>
            {{if .InferredChains}}
            <div class="list">
                {{range .InferredChains}}
                <div class="list-item">
                    <strong>{{.Title}}</strong>
                    <div class="meta">等级 {{.Level}}</div>
                    <div class="meta">{{.Summary}}</div>
                    {{if .Evidence}}<div class="meta">触发证据：{{range $index, $item := .Evidence}}{{if $index}}、{{end}}{{$item}}{{end}}</div>{{end}}
                </div>
                {{end}}
            </div>
            {{else}}<div class="meta">暂无动态链路推理结果。</div>{{end}}
        </div>
    </div>
</body>
</html>
`

const AdmissionEditHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑准入信息 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .dropdown-menu a.danger { color: #c00; }
        .container { max-width: 860px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 28px 30px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 10px; }
        .meta { color: #667085; font-size: 14px; margin-bottom: 18px; }
        .error { background: #fff1f0; color: #b42318; border: 1px solid #f0b7bf; padding: 12px 14px; border-radius: 10px; margin-bottom: 16px; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; color: #344054; font-weight: 600; margin-bottom: 8px; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px 14px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 14px; }
        .form-group textarea { min-height: 110px; resize: vertical; }
        .actions { display: flex; gap: 12px; margin-top: 20px; }
        .primary-btn, .secondary-btn { display: inline-block; padding: 12px 18px; border-radius: 8px; text-decoration: none; border: none; cursor: pointer; font-size: 14px; }
        .primary-btn { background: #0f766e; color: white; }
        .secondary-btn { background: #eef2ff; color: #4338ca; }
    </style>
</head>
<body>
    <div class="header">
        <h1>编辑准入信息</h1>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports">报告</a>
            <a href="/admission/skills" class="active">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="admissionEditUserMenuButton" type="button">{{.Username}} <span>▾</span></button>
                <div class="dropdown-menu" id="admissionEditUserDropdown">
                    {{if .HasPersonal}}<a href="/personal">个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">修改密码</a>
                    <a href="/logout" class="danger">退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <div class="title">编辑准入技能</div>
            <div class="meta">技能 ID: {{.SkillID}} | 原文件: {{.FileName}}</div>
            {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
            <form method="POST" action="/admission/edit/{{.SkillID}}">
                <div class="form-group">
                    <label for="display_name">技能显示名</label>
                    <input type="text" id="display_name" name="display_name" value="{{.DisplayName}}" required>
                </div>
                <div class="form-group">
                    <label for="version">版本</label>
                    <input type="text" id="version" name="version" value="{{.Version}}">
                </div>
                <div class="form-group">
                    <label for="description">用途说明</label>
                    <textarea id="description" name="description">{{.Description}}</textarea>
                </div>
                <div class="form-group">
                    <label for="admission_status">准入状态</label>
                    <select id="admission_status" name="admission_status">
                        <option value="pending" {{if eq .AdmissionStatus "pending"}}selected{{end}}>待定</option>
                        <option value="approved" {{if eq .AdmissionStatus "approved"}}selected{{end}}>已准入</option>
                        <option value="rejected" {{if eq .AdmissionStatus "rejected"}}selected{{end}}>拒绝准入</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="review_decision">审查结论</label>
                    <select id="review_decision" name="review_decision">
                        <option value="review" {{if eq .ReviewDecision "review"}}selected{{end}}>需人工复核</option>
                        <option value="pass" {{if eq .ReviewDecision "pass"}}selected{{end}}>建议通过</option>
                        <option value="block" {{if eq .ReviewDecision "block"}}selected{{end}}>需完成修复并复测</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="review_summary">审查摘要</label>
                    <textarea id="review_summary" name="review_summary">{{.ReviewSummary}}</textarea>
                </div>
                <div class="actions">
                    <button type="submit" class="primary-btn">保存修改</button>
                    <a href="/admission/skills/{{.SkillID}}" class="secondary-btn">返回详情</a>
                </div>
            </form>
        </div>
    </div>
    <script>
        (function() {
            var button = document.getElementById('admissionEditUserMenuButton');
            var menu = document.getElementById('admissionEditUserDropdown');
            if (!button || !menu) return;
            button.addEventListener('click', function() { menu.classList.toggle('show'); });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        })();
    </script>
</body>
</html>
`

const AdmissionDetailHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>准入技能详情 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; }
        .header-nav a:hover, .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .dropdown-menu a.danger { color: #c00; }
        .container { max-width: 1100px; margin: 32px auto; padding: 0 20px; display: grid; gap: 18px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 22px 24px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 10px; }
        .meta { color: #667085; font-size: 14px; margin-bottom: 6px; }
        .section-title { font-size: 18px; color: #111827; margin-bottom: 14px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
        .kv { background: #f8fafc; border-radius: 10px; padding: 12px 14px; }
        .kv strong { display: block; color: #344054; font-size: 12px; margin-bottom: 6px; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .list { display: grid; gap: 10px; }
        .list-item { border: 1px solid #eaecf0; border-radius: 10px; padding: 12px 14px; }
        .back-link { display: inline-block; color: #4338ca; text-decoration: none; margin-bottom: 6px; }
    </style>
</head>
<body>
    <div class="header">
        <div style="font-size:24px;font-weight:700;">准入技能详情</div>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports">报告</a>
            <a href="/admission/skills" class="active">准入库</a>
            <a href="/combination/overview">组合分析</a>
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" id="admissionDetailUserMenuButton" type="button">{{.Username}} <span>▾</span></button>
                <div class="dropdown-menu" id="admissionDetailUserDropdown">
                    {{if .HasPersonal}}<a href="/personal">个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">修改密码</a>
                    <a href="/logout" class="danger">退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <a href="/admission/skills" class="back-link">返回准入库列表</a>
            <div style="margin-bottom:10px; display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
                <a href="/admission/edit/{{.Skill.SkillID}}" class="back-link">编辑准入信息</a>
                <a href="{{if .CombinationURL}}{{.CombinationURL}}{{else}}/combination/overview?skill_id={{.Skill.SkillID}}{{end}}" class="back-link">进入组合分析</a>
            </div>
            <div class="title">{{if .Skill.DisplayName}}{{.Skill.DisplayName}}{{else}}{{.Skill.Name}}{{end}}</div>
            <div class="meta">技能 ID: {{.Skill.SkillID}}</div>
            <div class="meta">来源报告: {{.Skill.ReportID}} | 原文件: {{.Skill.FileName}}</div>
            <div class="meta">准入状态: {{.Skill.AdmissionStatus}} | 审查结论: {{.Skill.ReviewDecision}}</div>
            <div class="meta">用途摘要: {{if .Skill.PurposeSummary}}{{.Skill.PurposeSummary}}{{else}}-{{end}}</div>
            <div style="margin-top:12px;">
                <a href="{{if .CombinationURL}}{{.CombinationURL}}{{else}}/combination/overview?skill_id={{.Skill.SkillID}}{{end}}" class="back-link">组合分析</a>
            </div>
        </div>
        <div class="card">
            <div class="section-title">能力画像</div>
            <div class="grid">
                <div class="kv"><strong>网络访问</strong>{{.Profile.NetworkAccess}}</div>
                <div class="kv"><strong>文件读取</strong>{{.Profile.FileRead}}</div>
                <div class="kv"><strong>文件写入</strong>{{.Profile.FileWrite}}</div>
                <div class="kv"><strong>命令执行</strong>{{.Profile.CommandExec}}</div>
                <div class="kv"><strong>敏感数据访问</strong>{{.Profile.SensitiveDataAccess}}</div>
                <div class="kv"><strong>外部拉取</strong>{{.Profile.ExternalFetch}}</div>
                <div class="kv"><strong>数据采集</strong>{{.Profile.DataCollection}}</div>
                <div class="kv"><strong>持久化</strong>{{.Profile.Persistence}}</div>
            </div>
            {{if .Profile.Tags}}
            <div style="margin-top:14px;" class="tags">{{range .Profile.Tags}}<span class="tag">{{.}}</span>{{end}}</div>
            {{end}}
            {{if .Profile.Evidence}}
            <div class="list" style="margin-top:14px;">
                {{range .Profile.Evidence}}<div class="list-item">{{.}}</div>{{end}}
            </div>
            {{end}}
        </div>
        <div class="card">
            <div class="section-title">残余风险</div>
            {{if .Risks}}
            <div class="list">
                {{range .Risks}}
                <div class="list-item">
                    <div><strong>{{.Title}}</strong></div>
                    <div class="meta">类别 {{.Category}} | 等级 {{.Level}}</div>
                    <div class="meta">{{.Description}}</div>
                    <div class="meta">缓解建议: {{.Mitigation}}</div>
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">暂无残余风险记录。</div>
            {{end}}
        </div>
        <div class="card">
            <div class="section-title">审查记录</div>
            {{if .ReviewRecords}}
            <div class="list">
                {{range .ReviewRecords}}
                <div class="list-item">
                    <div><strong>{{.Reviewer}}</strong></div>
                    <div class="meta">结论 {{.Decision}} | 时间 {{.CreatedAt}}</div>
                    <div class="meta">{{.Summary}}</div>
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="meta">暂无审查记录。</div>
            {{end}}
        </div>
    </div>
    <script>
        (function() {
            var button = document.getElementById('admissionDetailUserMenuButton');
            var menu = document.getElementById('admissionDetailUserDropdown');
            if (!button || !menu) return;
            button.addEventListener('click', function() { menu.classList.toggle('show'); });
            document.addEventListener('click', function(e) {
                var dropdown = button.closest('.user-dropdown');
                if (dropdown && !dropdown.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });
        })();
    </script>
</body>
</html>
`
