// Package templates holds all HTML template strings for the skill scanner web UI.
package templates

const CommonPartialsHTML = `
{{define "appHeader"}}
<div class="header">
  <div style="display:flex;align-items:center;gap:20px;"><h1>{{.Title}}</h1></div>
  <div class="header-nav">
    <a href="/dashboard" {{if eq .Active "dashboard"}}class="active"{{end}}>首页</a>
    <a href="/scan" {{if eq .Active "scan"}}class="active"{{end}}>扫描</a>
    <a href="/reports" {{if eq .Active "reports"}}class="active"{{end}}>报告</a>
    <a href="/admission/skills" {{if eq .Active "admission"}}class="active"{{end}}>准入库</a>
    <a href="/combination/overview" {{if eq .Active "combination"}}class="active"{{end}}>组合分析</a>
    {{if or .HasUserMgmt .HasLogPerm}}<a href="/settings" {{if eq .Active "settings"}}class="active"{{end}}>设置</a>{{end}}
  </div>
  <div class="header-right">
    <div class="user-dropdown">
      <button class="dropdown-btn" id="{{.MenuButtonID}}" type="button">👤 {{.Username}} <span class="arrow">▾</span></button>
      <div class="dropdown-menu" id="{{.MenuID}}">
        {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
        <div class="divider"></div>
        <a href="/change-password">🔑 修改密码</a>
        <a href="/logout" class="danger">🚪 退出</a>
      </div>
    </div>
  </div>
</div>
{{end}}

{{define "dropdownBaseCSS"}}
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
.header h1 { font-size: 24px; }
.header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
.header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
.header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
.header-nav .active, .header-nav a.active { background: rgba(255,255,255,0.25); color: white; }
.header-right { display: flex; align-items: center; gap: 10px; }
.user-dropdown { position: relative; }
.dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
.dropdown-btn:hover { background: rgba(255,255,255,0.3); }
.dropdown-btn .arrow { font-size: 10px; }
.dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
.dropdown-menu.show { display: block; }
.dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
.dropdown-menu a:hover { background: #f5f6fa; }
.dropdown-menu a.danger { color: #c00; background: transparent; }
.dropdown-menu a.danger:hover { background: #f5f6fa; }
.dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
{{end}}

{{define "bindDropdownMenuScript"}}
function bindDropdownMenu(buttonId, menuId) {
  var button = document.getElementById(buttonId);
  var menu = document.getElementById(menuId);
  if (!button || !menu) return;
  button.addEventListener('click', function() { menu.classList.toggle('show'); });
  document.addEventListener('click', function(e) {
    var dropdown = button.closest('.user-dropdown');
    if (dropdown && !dropdown.contains(e.target)) menu.classList.remove('show');
  });
}
{{end}}

{{define "runtimeStatusCSS"}}
.runtime-status { background: #f8fbff; border: 1px solid #d9e3ff; padding: 18px 20px; border-radius: 12px; margin-bottom: 22px; color: #24324a; line-height: 1.6; }
.runtime-status h3 { margin: 0 0 10px; font-size: 16px; color: #24324a; }
.runtime-status p { margin: 6px 0 0; color: #52627c; font-size: 14px; }
.runtime-status .summary { margin-bottom: 12px; }
.runtime-status .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; margin-left: 8px; }
.runtime-status .badge.ready { background: #e7f7ee; color: #067647; }
.runtime-status .badge.blocked { background: #fdecec; color: #b42318; }
.runtime-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; margin: 12px 0; }
.runtime-card { background: white; border: 1px solid #dfe7f5; border-radius: 10px; padding: 12px; }
.runtime-card strong { display: block; color: #24324a; margin-bottom: 6px; }
.runtime-card span { display: inline-block; margin-bottom: 6px; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }
.runtime-card span.ready { background: #e7f7ee; color: #067647; }
.runtime-card span.blocked { background: #fdecec; color: #b42318; }
.runtime-card p { margin: 0; font-size: 12px; color: #5a6880; }
.runtime-list { margin: 10px 0 0 18px; color: #52627c; }
.runtime-list li { margin: 4px 0; }
.runtime-action { display: inline-flex; align-items: center; justify-content: center; margin-top: 8px; padding: 6px 10px; border-radius: 8px; background: #eef2ff; color: #364152; text-decoration: none; font-size: 12px; font-weight: 600; }
.runtime-action:hover { background: #dde5ff; }
{{end}}

{{define "runtimeStatusPanel"}}
{{if .RuntimeStatus.Summary}}
<div class="runtime-status" data-runtime-status="true">
  <h3>运行时检查
    <span class="badge {{if .RuntimeStatus.Ready}}ready{{else}}blocked{{end}}">{{if .RuntimeStatus.Ready}}可提交扫描{{else}}存在阻塞项{{end}}</span>
  </h3>
  <p class="summary"><strong>启动自检:</strong> {{.RuntimeStatus.Summary}}</p>
  {{if .RuntimeStatus.CheckedAtText}}<p><strong>最近检查:</strong> {{.RuntimeStatus.CheckedAtText}}</p>{{end}}
  <div class="runtime-grid">
    {{range .RuntimeStatus.Components}}
    <div class="runtime-card">
      <strong>{{.DisplayName}}</strong>
      <span class="{{if .Ready}}ready{{else}}blocked{{end}}">{{if .Ready}}已就绪{{else}}未就绪{{end}}</span>
      <p>{{.Message}}</p>
      {{if .Action.Href}}<a class="runtime-action" href="{{.Action.Href}}">{{.Action.Label}}</a>{{end}}
    </div>
    {{end}}
    <div class="runtime-card">
      <strong>当前账号 LLM</strong>
      <span class="{{if .RuntimeStatus.UserLLM.Ready}}ready{{else}}blocked{{end}}">{{if .RuntimeStatus.UserLLM.Ready}}已就绪{{else}}未就绪{{end}}</span>
      <p>{{.RuntimeStatus.UserLLM.Message}}</p>
      {{if .RuntimeStatus.UserLLM.Action.Href}}<a class="runtime-action" href="{{.RuntimeStatus.UserLLM.Action.Href}}">{{.RuntimeStatus.UserLLM.Action.Label}}</a>{{end}}
    </div>
  </div>
  {{if .RuntimeStatus.ScanPreview.Failures}}
  <p><strong>阻塞项</strong></p>
  <ul class="runtime-list">
    {{range .RuntimeStatus.ScanPreview.Failures}}<li>{{.}}</li>{{end}}
  </ul>
  {{end}}
  {{if .RuntimeStatus.ScanPreview.Warnings}}
  <p><strong>警告项</strong></p>
  <ul class="runtime-list">
    {{range .RuntimeStatus.ScanPreview.Warnings}}<li>{{.}}</li>{{end}}
  </ul>
  {{end}}
</div>
{{end}}
{{end}}

{{define "runtimeStatusAutoRefreshScript"}}
<script>
function enableRuntimeStatusAutoRefresh() {
  if (typeof window === 'undefined' || !window.fetch) {
    return;
  }
  var panels = document.querySelectorAll('[data-runtime-status="true"]');
  if (!panels.length) {
    return;
  }
  function escapeRuntimeHTML(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function renderRuntimeAction(action) {
    if (!action || !action.href || !action.label) {
      return '';
    }
    return '<a class="runtime-action" href="' + escapeRuntimeHTML(action.href) + '">' + escapeRuntimeHTML(action.label) + '</a>';
  }
  function renderRuntimeList(title, items) {
    if (!items || !items.length) {
      return '';
    }
    var html = '<p><strong>' + escapeRuntimeHTML(title) + '</strong></p><ul class="runtime-list">';
    for (var i = 0; i < items.length; i++) {
      html += '<li>' + escapeRuntimeHTML(items[i]) + '</li>';
    }
    html += '</ul>';
    return html;
  }
  function renderRuntimePanelHTML(data) {
    if (!data || !data.summary) {
      return '';
    }
    var components = Array.isArray(data.components) ? data.components.slice() : [];
    var cardsHTML = '';
    for (var i = 0; i < components.length; i++) {
      var item = components[i] || {};
      cardsHTML += '<div class="runtime-card">'
        + '<strong>' + escapeRuntimeHTML(item.display_name) + '</strong>'
        + '<span class="' + (item.ready ? 'ready' : 'blocked') + '">' + (item.ready ? '已就绪' : '未就绪') + '</span>'
        + '<p>' + escapeRuntimeHTML(item.message) + '</p>'
        + renderRuntimeAction(item.action)
        + '</div>';
    }
    var userLLM = data.user_llm || {};
    cardsHTML += '<div class="runtime-card">'
      + '<strong>当前账号 LLM</strong>'
      + '<span class="' + (userLLM.ready ? 'ready' : 'blocked') + '">' + (userLLM.ready ? '已就绪' : '未就绪') + '</span>'
      + '<p>' + escapeRuntimeHTML(userLLM.message) + '</p>'
      + renderRuntimeAction(userLLM.action)
      + '</div>';
    var checkedAtHTML = data.checked_at_text ? '<p><strong>最近检查:</strong> ' + escapeRuntimeHTML(data.checked_at_text) + '</p>' : '';
    var scanPreflight = data.scan_preflight || {};
    return '<div class="runtime-status" data-runtime-status="true">'
      + '<h3>运行时检查 <span class="badge ' + (data.ready ? 'ready' : 'blocked') + '">' + (data.ready ? '可提交扫描' : '存在阻塞项') + '</span></h3>'
      + '<p class="summary"><strong>启动自检:</strong> ' + escapeRuntimeHTML(data.summary) + '</p>'
      + checkedAtHTML
      + '<div class="runtime-grid">' + cardsHTML + '</div>'
      + renderRuntimeList('阻塞项', scanPreflight.failures)
      + renderRuntimeList('警告项', scanPreflight.warnings)
      + '</div>';
  }
  function replaceRuntimePanels(data) {
    var html = renderRuntimePanelHTML(data);
    if (!html) {
      return;
    }
    var currentPanels = document.querySelectorAll('[data-runtime-status="true"]');
    for (var i = 0; i < currentPanels.length; i++) {
      currentPanels[i].outerHTML = html;
    }
  }
  function hasDirtyRuntimePageState() {
    if (document.querySelector('.task-error-panel.show')) {
      return true;
    }
    if (document.querySelector('.task-status-panel.show')) {
      return true;
    }
    if (document.querySelector('.loading') && document.querySelector('.loading').style.display === 'block') {
      return true;
    }
    if (document.querySelector('#fileItems .file-item')) {
      return true;
    }
    if (document.querySelector('[data-runtime-autorefresh-block="true"]')) {
      return true;
    }
    return false;
  }
  var timer = window.setInterval(function() {
    if (hasDirtyRuntimePageState()) {
      return;
    }
    fetch('/api/runtime/status', { credentials: 'same-origin' })
      .then(function(resp) {
        if (!resp.ok) {
          throw new Error('runtime status request failed');
        }
        return resp.json();
      })
      .then(function(data) {
        replaceRuntimePanels(data);
      })
      .catch(function() {});
  }, 30000);
  window.addEventListener('beforeunload', function() {
    window.clearInterval(timer);
  }, { once: true });
}
</script>
{{end}}
`

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
        {{template "dropdownBaseCSS"}}
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
        .report-item .hintline { color: #586174; font-size: 13px; margin-top: 6px; line-height: 1.5; }
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
    {{template "appHeader" (dict "Title" "技能扫描器" "Active" "dashboard" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "dashboardUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        {{if .RemindPwdChange}}
        <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;">
            <span>⚠️ 检测到您正在使用默认密码，建议前往 <a href="/change-password" style="font-weight:600;">修改密码</a> 页面更换。</span>
            <button onclick="this.parentElement.style.display='none'" style="background:none;border:none;cursor:pointer;font-size:18px;">✕</button>
        </div>
        {{end}}
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
                        <div class="meta">{{.Username}} · {{.CreatedAt}} · {{.StatusLabel}}{{if .TaskID}} · 任务 {{.TaskID}}{{end}}{{if .RequestID}} · 请求 {{.RequestID}}{{end}}</div>
                        {{if .DecisionHint}}<div class="hintline">处置提示：{{.DecisionHint}}</div>{{end}}
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
        {{template "bindDropdownMenuScript"}}
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
        {{template "dropdownBaseCSS"}}
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
        .report-item .hintline { color: #586174; font-size: 13px; margin-top: 6px; line-height: 1.5; }
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
        .filter-bar { padding: 14px 24px; border-bottom: 1px solid #f0f2f5; background: #fbfcff; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .filter-bar input { width: 320px; max-width: 100%; padding: 8px 10px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 13px; }
        .filter-btn { padding: 8px 14px; border-radius: 8px; border: none; background: #2156d1; color: #fff; font-size: 13px; cursor: pointer; }
        .filter-reset { color: #667085; font-size: 13px; text-decoration: none; }
        .empty { text-align: center; padding: 60px; color: #888; }
    </style>
</head>
<body>
    {{template "appHeader" (dict "Title" "风险报告" "Active" "reports" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "reportsUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>报告列表</h2>
                {{if .IsAdmin}}<span class="admin-hint">👑 管理员视图（显示所有报告）</span>{{else}}<span class="team-hint">显示您及同团队成员的报告</span>{{end}}
            </div>
            <form method="GET" action="/reports" class="filter-bar">
                <label for="taskIDFilter">按任务ID筛选：</label>
                <input id="taskIDFilter" name="task_id" type="text" value="{{.TaskID}}" placeholder="输入完整或部分 Task ID">
                <label for="requestIDFilter">按请求ID筛选：</label>
                <input id="requestIDFilter" name="request_id" type="text" value="{{.RequestID}}" placeholder="输入完整或部分 Request ID">
                <button type="submit" class="filter-btn">筛选</button>
                <a href="/reports" class="filter-reset">重置</a>
            </form>
            {{if .Notice}}<div class="flash success">{{.Notice}}</div>{{end}}
            {{if .Error}}<div class="flash error">{{.Error}}</div>{{end}}
            {{if .RunningTasks}}
                {{range .RunningTasks}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
                        <div class="meta">任务 {{.ID}}{{if .RequestID}} · 请求 {{.RequestID}}{{end}} · 创建 {{.CreatedAt}} · 更新 {{.UpdatedAt}} · {{.StatusLabel}}</div>
                        <div class="badges">
                            <span class="badge status">{{.StatusLabel}}</span>
                            <span style="color:#888;font-size:12px;margin-left:4px;">扫描进行中，报告尚未生成</span>
                        </div>
                        {{if .Message}}<div class="meta">{{.Message}}</div>{{end}}
                    </div>
                    <div class="report-actions">
                        <a href="/scan" class="view-btn">查看扫描进度</a>
                        <button type="button" class="delete-btn cancel-task-btn" data-task-id="{{.ID}}">取消任务</button>
                    </div>
                </div>
                {{end}}
            {{end}}
            {{if .Reports}}
                {{range .Reports}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
					<div class="meta">{{.Username}} · {{.CreatedAt}} · {{.StatusLabel}}{{if .TaskID}} · 任务 {{.TaskID}}{{end}}{{if .RequestID}} · 请求 {{.RequestID}}{{end}}</div>
					{{if .DecisionHint}}<div class="hintline">处置提示：{{.DecisionHint}}</div>{{end}}
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
        {{template "bindDropdownMenuScript"}}

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
        document.querySelectorAll('.cancel-task-btn').forEach(function(button) {
            button.addEventListener('click', function() {
                var taskID = button.getAttribute('data-task-id') || '';
                if (!taskID || !confirm('确认取消该扫描任务吗？')) {
                    return;
                }
                button.disabled = true;
                fetch('/api/scan/tasks/' + encodeURIComponent(taskID) + '/cancel', { method: 'POST', headers: { 'Accept': 'application/json' } })
                    .then(function(resp) {
                        return resp.json().catch(function() { return {}; }).then(function(data) {
                            if (!resp.ok) {
                                throw new Error(data.error || '取消任务失败');
                            }
                            window.location.reload();
                        });
                    })
                    .catch(function(err) {
                        alert(err.message || '取消任务失败');
                        button.disabled = false;
                    });
            });
        });
        // 安全下载：通过 window.open data URL 绕过 Chrome HTTP 下载阻止
        function safeDownload(url, filename) {
            fetch(url, { credentials: 'same-origin' })
                .then(function(resp) {
                    if (!resp.ok) throw new Error('下载失败: ' + resp.status);
                    return resp.text();
                })
                .then(function(html) {
                    // 在新窗口中打开 HTML 内容，用户可 Ctrl+S 保存
                    var win = window.open('', '_blank');
                    if (win) {
                        win.document.write(html);
                        win.document.close();
                    } else {
                        // popup 被阻止时，用 data URL 下载
                        var b64 = btoa(unescape(encodeURIComponent(html)));
                        var a = document.createElement('a');
                        a.href = 'data:text/html;base64,' + b64;
                        a.download = filename || 'report.html';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                    }
                })
                .catch(function(err) { alert(err.message || '下载失败'); });
        }
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
        {{template "dropdownBaseCSS"}}
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
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
        .task-error-panel { display: none; margin: 14px 0 18px; padding: 16px 18px; border-radius: 12px; border: 1px solid #f3c7c2; background: linear-gradient(180deg, #fff7f6 0%, #fff1ef 100%); }
        .task-error-panel.show { display: block; }
        .task-error-panel h3 { margin: 0 0 8px; font-size: 15px; color: #b42318; }
        .task-error-panel p { margin: 6px 0; color: #7a271a; line-height: 1.6; }
        .task-error-panel .suggestion { color: #9f2d20; font-weight: 600; }
        .task-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
        .task-status-panel .task-actions { gap: 14px; }
        .task-status-panel .task-actions .task-link { flex: 1 1 0; }
        .task-link { display: inline-flex; align-items: center; justify-content: center; padding: 9px 14px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 600; border: 1px solid #c7d5fb; background: white; color: #2156d1; cursor: pointer; white-space: nowrap; }
        .task-link.primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-color: transparent; color: white; }
        .task-progress { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
        .task-progress span { padding: 4px 10px; border-radius: 999px; font-size: 12px; background: #edf2ff; color: #52627c; }
        .task-progress span.done { background: #e7f7ee; color: #067647; }
        .review-trace-summary { font-size: 13px; color: #4d5b70; line-height: 1.6; }
        .llm-io-panel { margin-top: 14px; border: 1px solid #dbe5ff; border-radius: 14px; overflow: hidden; background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%); box-shadow: 0 8px 24px rgba(42, 67, 101, 0.08); }
        .llm-io-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 16px; border-bottom: 1px solid #e3ebff; background: linear-gradient(90deg, #eef4ff 0%, #f8fbff 100%); }
        .llm-io-head h4 { margin: 0; color: #24324a; font-size: 14px; }
        .llm-io-head p { margin: 4px 0 0; color: #607089; font-size: 12px; }
        .llm-io-copy { border: 1px solid #cfdaf8; background: white; color: #3353a8; border-radius: 8px; padding: 7px 12px; font-size: 12px; font-weight: 700; cursor: pointer; }
        .llm-io-body { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0; }
        .llm-io-column { padding: 16px; min-height: 220px; }
        .llm-io-column + .llm-io-column { border-left: 1px solid #edf2ff; }
        .llm-io-column h5 { margin: 0 0 10px; color: #24324a; font-size: 13px; }
        .llm-io-column pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace; font-size: 12px; line-height: 1.7; color: #334155; background: #fbfdff; border: 1px solid #e6eeff; border-radius: 10px; padding: 12px; min-height: 160px; user-select: text; }
        .llm-io-empty { color: #7a8699; }
        .tips { background: #f0f7ff; border-left: 4px solid #667eea; padding: 16px 20px; border-radius: 0 8px 8px 0; margin-top: 30px; }
        .tips h4 { color: #333; margin-bottom: 10px; }
        .tips ul { color: #666; padding-left: 20px; line-height: 1.8; }
        {{template "runtimeStatusCSS"}}
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
        .modal-backdrop { display: none; position: fixed; inset: 0; z-index: 1000; align-items: center; justify-content: center; padding: 22px; background: rgba(15, 23, 42, 0.42); backdrop-filter: blur(8px); }
        .modal-backdrop.show { display: flex; }
        .modal-card { width: min(1080px, 100%); max-height: min(88vh, 860px); overflow: hidden; border: 1px solid rgba(209, 219, 255, 0.92); border-radius: 22px; background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%); box-shadow: 0 28px 80px rgba(15, 23, 42, 0.24); }
        .modal-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; padding: 20px 24px; border-bottom: 1px solid #e5ebfb; background: radial-gradient(circle at top left, rgba(102,126,234,0.16), transparent 36%), linear-gradient(90deg, #f5f8ff 0%, #ffffff 100%); }
        .modal-head h3 { margin: 0; color: #1f2a44; font-size: 18px; }
        .modal-head p { margin: 6px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
        .modal-body { max-height: calc(min(88vh, 860px) - 76px); overflow-y: auto; padding: 22px 24px 24px; }
        .modal-grid { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(340px, 0.95fr); gap: 20px; align-items: start; }
        .manual-rule-grid { display: grid; grid-template-columns: 1fr 180px; gap: 12px; }
        .manual-rule-field { margin-bottom: 14px; }
        .manual-rule-field label { display: block; margin-bottom: 7px; color: #344054; font-size: 13px; font-weight: 700; }
        .manual-rule-field input, .manual-rule-field select, .manual-rule-field textarea { width: 100%; border: 1px solid #d8e0f3; border-radius: 12px; background: #fff; color: #24324a; font-size: 14px; line-height: 1.5; padding: 11px 13px; outline: none; transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease; }
        .manual-rule-field textarea { min-height: 104px; resize: vertical; }
        .manual-rule-field input:focus, .manual-rule-field select:focus, .manual-rule-field textarea:focus { border-color: #7583f5; box-shadow: 0 0 0 4px rgba(102,126,234,0.14); background: #fefeff; }
        .smart-toggle { display: flex; align-items: flex-start; gap: 10px; margin: 4px 0 16px; padding: 13px 14px; border: 1px solid #dbe5ff; border-radius: 14px; background: linear-gradient(180deg, #f8fbff 0%, #ffffff 100%); color: #344054; font-size: 13px; font-weight: 700; }
        .smart-toggle span { display: block; color: #6b7891; font-size: 12px; font-weight: 500; line-height: 1.5; margin-top: 3px; }
        .smart-rule-panel { display: none; margin: 0 0 16px; padding: 16px; border: 1px solid #dbe5ff; border-radius: 16px; background: linear-gradient(180deg, #f8fbff 0%, #ffffff 100%); }
        .smart-rule-panel.show { display: block; }
        .modal-actions { display: flex; justify-content: flex-end; gap: 10px; flex-wrap: wrap; margin-top: 8px; }
        .primary-btn, .secondary-btn { border: 1px solid transparent; border-radius: 10px; padding: 9px 14px; font-size: 13px; font-weight: 700; cursor: pointer; }
        .primary-btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; box-shadow: 0 8px 18px rgba(102,126,234,0.22); }
        .primary-btn:disabled { opacity: 0.62; cursor: wait; box-shadow: none; }
        .secondary-btn { background: #ffffff; color: #44546f; border-color: #cfd8ef; }
        .trace-sidecard { position: sticky; top: 0; border: 1px solid #dbe5ff; border-radius: 18px; overflow: hidden; background: #ffffff; box-shadow: 0 12px 32px rgba(42, 67, 101, 0.08); }
        .trace-sidecard h4 { margin: 0; padding: 15px 16px 0; color: #24324a; font-size: 14px; }
        .trace-sidecard .review-trace-summary { padding: 8px 16px 0; color: #5d6b82; }
        .rich-trace-box { margin: 14px; border: 1px solid #e1e9ff; border-radius: 14px; background: linear-gradient(180deg, #fbfdff 0%, #f6f9ff 100%); overflow: hidden; }
        .rich-trace-section { padding: 14px 15px; border-top: 1px solid #e8eefc; }
        .rich-trace-section:first-child { border-top: none; }
        .rich-trace-section h5 { margin: 0 0 8px; color: #1f2a44; font-size: 13px; }
        .rich-trace-content { min-height: 76px; padding: 11px 12px; border: 1px solid #e7edfb; border-radius: 11px; background: rgba(255,255,255,0.84); color: #334155; font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-word; user-select: text; }
        .rich-trace-placeholder { color: #8792a8; }
        .trace-step { margin: 10px 14px; padding: 12px 13px; border: 1px solid #e5ebfb; border-radius: 12px; background: #ffffff; }
        .trace-step strong { display: block; color: #24324a; font-size: 13px; }
        .trace-step p { margin: 6px 0 0; color: #5d6b82; font-size: 12px; line-height: 1.55; }
        .trace-step ul { margin: 8px 0 0 18px; color: #5d6b82; font-size: 12px; line-height: 1.6; }
        .agent-analysis-card { width: min(1180px, 100%); }
        .agent-analysis-card .llm-io-panel { margin: 0; }
        .agent-analysis-card .llm-io-column { min-height: 360px; }
        .agent-analysis-card .llm-io-column pre { min-height: 300px; max-height: 52vh; overflow: auto; }
        .agent-analysis-picker { display: grid; gap: 7px; margin-bottom: 14px; }
        .agent-analysis-picker label { color: #344054; font-size: 13px; font-weight: 700; }
        .agent-analysis-picker select { width: 100%; max-width: 520px; border: 1px solid #d8e0f3; border-radius: 10px; padding: 10px 12px; color: #24324a; background: #fff; font-size: 13px; }
        @media (max-width: 720px) {
            .config-toolbar { grid-template-columns: 1fr; }
            .manual-rule-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 900px) {
            .llm-io-body, .modal-grid { grid-template-columns: 1fr; }
            .llm-io-column + .llm-io-column { border-left: none; border-top: 1px solid #edf2ff; }
            .trace-sidecard { position: static; }
        }
    </style>
</head>
<body>
    {{template "appHeader" (dict "Title" "技能扫描" "Active" "scan" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "scanUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        <div class="panel">
            <h2>上传技能文件</h2>
            <p>选择文件或整个文件夹，系统将自动扫描并生成风险报告。</p>
            <!-- 运行时检查 当前账号 LLM 可提交扫描 存在阻塞项 -->
            {{template "runtimeStatusPanel" .}}

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
                        <option value="preset:scenario2-default">默认规则（场景二）（系统）</option>
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
                <div class="hint-text" id="rulesCatalogStats">可按当前技能风险面裁剪评估项；高风险规则建议保持勾选。</div>
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

                <div style="margin:16px 0;">
                    <label for="skillName" style="display:block;color:#475467;font-size:13px;font-weight:600;margin-bottom:6px;">技能名（可选）</label>
                    <input type="text" id="skillName" name="skill_name" placeholder="留空则自动从 SKILL.md 的 name 字段或上传文件夹名提取" style="width:100%;padding:10px 12px;border:1px solid #d0d5dd;border-radius:8px;font-size:13px;font-family:inherit;box-sizing:border-box;" maxlength="100">
                    <p style="color:#98a2b3;font-size:12px;margin-top:4px;">用于报告命名和前端显示。上传文件夹时会自动提取文件夹名。</p>
                </div>

                <div style="margin:16px 0;">
                    <label for="userNotes" style="display:block;color:#475467;font-size:13px;font-weight:600;margin-bottom:6px;">补充说明（可选）</label>
                    <textarea id="userNotes" name="user_notes" placeholder="如有需要特别说明的内容请填写，例如：&#10;- 该技能需要 numpy、pandas 依赖&#10;- 运行时需要网络访问&#10;- 请使用 Python 3.10 测试" style="width:100%;padding:10px 12px;border:1px solid #d0d5dd;border-radius:8px;font-size:13px;min-height:72px;resize:vertical;font-family:inherit;box-sizing:border-box;" maxlength="2000"></textarea>
                    <p style="color:#98a2b3;font-size:12px;margin-top:4px;">最多 2000 字符。内容会传递给测试 Agent 作为参考，但不会修改技能文件。</p>
                </div>

                <button type="submit" class="submit-btn" id="submitBtn">🔍 开始扫描</button>
            </form>

            <div class="task-error-panel" id="taskErrorPanel">
                <h3 id="taskErrorTitle">扫描提交失败</h3>
                <p id="taskErrorText"></p>
                <p class="suggestion" id="taskErrorSuggestion"></p>
                <p id="taskErrorDetails"></p>
                <div class="task-actions">
                    <a href="#" class="task-link" id="taskErrorAction" style="display:none;"></a>
                    <button type="button" class="tiny-btn" id="taskErrorDismissBtn">关闭提示</button>
                </div>
            </div>

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
                    <button type="button" class="task-link primary" id="openAgentAnalysisBtn">智能体分析详情</button>
                    <a href="/admission/skills" class="task-link primary">进入准入库</a>
                    <a href="/combination/overview" class="task-link primary">进入组合分析</a>
                    <button type="button" class="task-link primary" id="clearTaskStatusBtn">清除任务状态</button>
                </div>
            </div>

            <div class="modal-backdrop" id="agentAnalysisModal">
                <div class="modal-card agent-analysis-card">
                    <div class="modal-head">
                        <div>
                            <h3>智能体分析详情</h3>
                            <p>展示当前选中风险项的系统输入、公开分析过程和最终判断，内容会随扫描进度更新。</p>
                        </div>
                        <button type="button" class="secondary-btn" id="closeAgentAnalysisModalBtn">关闭</button>
                    </div>
                    <div class="modal-body">
                        <div class="agent-analysis-picker">
                            <label for="agentAnalysisSelect">选择 LLM 对话</label>
                            <select id="agentAnalysisSelect">
                                <option value="">暂无 LLM 对话</option>
                            </select>
                        </div>
                <div class="llm-io-panel" id="taskLLMIOPanel" style="display:none;">
                    <div class="llm-io-head">
                        <div>
                            <h4>LLM 交互记录</h4>
                            <p>展示当前选中风险项的公开输入摘要、结构化分析过程和最终判断，内容只读且可复制。</p>
                        </div>
                        <button type="button" class="llm-io-copy" id="copyLLMIOBtn">复制内容</button>
                    </div>
                    <div class="llm-io-body">
                        <div class="llm-io-column">
                            <h5>发送内容</h5>
                            <pre id="taskLLMInput" class="llm-io-empty">复核开始后，这里会自动展示发送给 LLM 的目标、输入摘要和采用标准。</pre>
                        </div>
                        <div class="llm-io-column">
                            <h5>分析过程</h5>
                            <pre id="taskLLMProcess" class="llm-io-empty">这里会展示公开的阶段轨迹、工具步骤和中间判断。</pre>
                        </div>
                        <div class="llm-io-column">
                            <h5>最终判断</h5>
                            <pre id="taskLLMDecision" class="llm-io-empty">这里会展示裁决、理由、缺失证据和修复建议。</pre>
                        </div>
                    </div>
                </div>
                    </div>
                </div>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>扫描中，请稍候...</p>
            </div>

            <div class="modal-backdrop" id="customRuleModal">
                <div class="modal-card">
                    <div class="modal-head">
                        <div>
                            <h3>新增自定义规则</h3>
                            <p>先填写静态规则；启用智能分析后，可用自然语言描述需求并生成可编辑草案。</p>
                        </div>
                        <button type="button" class="secondary-btn" id="closeCustomRuleModalBtn">关闭</button>
                    </div>
                    <div class="modal-body">
                        <div class="modal-grid">
                            <div>
                                <div class="smart-rule-panel show" id="manualRulePanel">
                                    <div class="manual-rule-grid">
                                        <div class="manual-rule-field">
                                            <label for="manualRuleName">规则名称</label>
                                            <input type="text" id="manualRuleName" placeholder="例如：危险命令拼接执行">
                                        </div>
                                        <div class="manual-rule-field">
                                            <label for="manualRuleSeverity">风险等级</label>
                                            <select id="manualRuleSeverity">
                                                <option value="高风险">高风险</option>
                                                <option value="中风险" selected>中风险</option>
                                                <option value="低风险">低风险</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="manual-rule-field">
                                        <label for="manualRulePatterns">全匹配规则</label>
                                        <textarea id="manualRulePatterns" placeholder="每行一个正则模式，保存后将作为 patterns 写入自定义规则"></textarea>
                                    </div>
                                    <div class="manual-rule-field">
                                        <label for="manualRuleReason">命中原因</label>
                                        <input type="text" id="manualRuleReason" placeholder="可选，例如：拦截可执行上下文中的高危命令拼接">
                                    </div>
                                </div>
                                <label class="smart-toggle"><input type="checkbox" id="smartRuleEnabled"> 是否启用智能分析 <span>智能体会结合你的自然语言描述和上方已填写规则生成草案，结果仍以你的需求为准，可继续编辑后加入列表。</span></label>
                                <div class="smart-rule-panel" id="smartRulePanel">
                                    <div class="manual-rule-field">
                                        <label for="smartRuleDescription">智能分析需求</label>
                                        <textarea id="smartRuleDescription" placeholder="输入你想要的规则，例如：识别把用户输入拼接进 shell 命令的 Python 代码，优先匹配 os.system、subprocess shell=True，并说明命中原因"></textarea>
                                    </div>
                                    <div class="modal-actions" style="justify-content:flex-start; margin-top:0;">
                                        <button type="button" class="primary-btn" id="generateSmartRuleBtn">生成规则草案</button>
                                    </div>
                                </div>
                                <div class="modal-actions">
                                    <button type="button" class="secondary-btn" id="cancelCustomRuleBtn">取消</button>
                                    <button type="button" class="primary-btn" id="confirmCustomRuleBtn">加入规则列表</button>
                                </div>
                            </div>
                            <div class="trace-sidecard">
                                <h4>智能补充轨迹</h4>
                                <div id="customRuleTraceSummary" class="review-trace-summary">这里展示规则生成过程中的公开阶段信息和结构化结果。</div>
                                <div class="rich-trace-box">
                                    <div class="rich-trace-section">
                                        <h5>系统输入</h5>
                                        <div id="customRuleTraceInput" class="rich-trace-content rich-trace-placeholder">启用智能分析并提交后，这里会展示发送给智能体的用户需求和已填写规则摘要。</div>
                                    </div>
                                    <div class="rich-trace-section">
                                        <h5>LLM 分析过程</h5>
                                        <div id="customRuleTraceProcess" class="rich-trace-content rich-trace-placeholder">这里会展示公开的分析步骤、生成策略和结构化转换过程。</div>
                                    </div>
                                    <div class="rich-trace-section">
                                        <h5>判断结果</h5>
                                        <div id="customRuleTraceDecision" class="rich-trace-content rich-trace-placeholder">这里会展示规则名称、风险等级、匹配模式数量和确认建议。</div>
                                    </div>
                                </div>
                                <div id="customRuleTraceList"></div>
                            </div>
                        </div>
                    </div>
                </div>
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
        {{template "bindDropdownMenuScript"}}

        bindDropdownMenu('scanUserMenuButton', 'userDropdown');

        var currentMode = 'file';
        var selectedFiles = [];
        var builtinRules = [];
        var builtinPresets = [];
        var savedProfiles = [];
        var rulesStats = null;
        var customRuleCount = 0;
        var selectedReviewTraceEntryId = '';
        var pendingCustomRuleDraft = null;
        var currentTaskID = '';
        var currentReviewTrace = null;
        var currentReviewTraceEntries = [];

        document.getElementById('modeFile').addEventListener('click', function() {
            setMode('file');
        });
        document.getElementById('modeFolder').addEventListener('click', function() {
            setMode('folder');
        });

        loadRulesCatalog('preset:scenario2-default');

        function loadRulesCatalog(preferredSelection) {
            fetchJSON('/api/rules/catalog')
                .then(function(data) {
                    builtinRules = Array.isArray(data.rules) ? data.rules : [];
                    builtinPresets = Array.isArray(data.presets) ? data.presets : [];
                    savedProfiles = Array.isArray(data.saved_profiles) ? data.saved_profiles : [];
                    rulesStats = data.stats || null;
                    renderRulesCatalog();
                    applyDifferentialDefaults(data.differential || {});
                    renderProfileSelector(preferredSelection || 'preset:scenario2-default');
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
                        var err = new Error((data && data.error) || ('请求失败（HTTP ' + resp.status + '）'));
                        err.data = data || {};
                        err.status = resp.status;
                        throw err;
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
                appendProfileOption(selector, 'preset:scenario2-default', '默认规则（场景二）（系统）');
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
            var fallback = 'preset:scenario2-default';
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
                        loadRulesCatalog('preset:scenario2-default');
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
            renderRulesCatalogStats();
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
                var scenario = rule.scenario ? ('[' + rule.scenario + '] ') : '';
                text.textContent = scenario + (rule.id || '') + ' ' + (rule.name || '');
                label.appendChild(checkbox);
                label.appendChild(layer);
                label.appendChild(text);
                box.appendChild(label);
            }
            bindRuleSelectionEvents();
        }

        function renderRulesCatalogStats() {
            var el = document.getElementById('rulesCatalogStats');
            if (!el) {
                return;
            }
            if (!rulesStats) {
                el.textContent = '可按当前技能风险面裁剪评估项；高风险规则建议保持勾选。';
                return;
            }
            el.textContent = '规则总数：' + (rulesStats.total || 0) + '（场景二：' + (rulesStats.scenario2 || 0) + '，场景三：' + (rulesStats.scenario3 || 0) + '）。可按风险面裁剪评估项；高风险规则建议保持勾选。';
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

        document.getElementById('addCustomRuleBtn').addEventListener('click', openCustomRuleModal);

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

        function openCustomRuleModal() {
            pendingCustomRuleDraft = null;
            document.getElementById('customRuleModal').classList.add('show');
            document.getElementById('smartRuleEnabled').checked = false;
            document.getElementById('manualRuleName').value = '';
            document.getElementById('manualRuleSeverity').value = '中风险';
            document.getElementById('manualRulePatterns').value = '';
            document.getElementById('manualRuleReason').value = '';
            document.getElementById('smartRuleDescription').value = '';
            renderCustomRuleTrace([], '这里展示规则生成过程中的公开阶段信息和结构化结果。');
            syncCustomRuleModalMode();
        }

        function closeCustomRuleModal() {
            document.getElementById('customRuleModal').classList.remove('show');
        }

        function syncCustomRuleModalMode() {
            var enabled = document.getElementById('smartRuleEnabled').checked;
            document.getElementById('manualRulePanel').classList.add('show');
            document.getElementById('smartRulePanel').classList.toggle('show', enabled);
        }

        document.getElementById('smartRuleEnabled').addEventListener('change', syncCustomRuleModalMode);
        document.getElementById('closeCustomRuleModalBtn').addEventListener('click', closeCustomRuleModal);
        document.getElementById('cancelCustomRuleBtn').addEventListener('click', closeCustomRuleModal);

        document.getElementById('generateSmartRuleBtn').addEventListener('click', function() {
            var btn = this;
            var description = document.getElementById('smartRuleDescription').value.trim();
            if (!description) {
                alert('请先输入规则描述');
                return;
            }
            btn.disabled = true;
            pendingCustomRuleDraft = null;
            var currentRule = collectRuleDraftFromModalFields();
            renderCustomRuleTrace([{ title: '提交规则描述', status: 'running', summary: '正在请求 LLM 生成规则草案。', details: ['描述已提交到规则增强接口。'] }], '正在生成规则草案...', currentRule);
            fetchJSON('/api/rules/augment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description: description, current_rule: currentRule })
            }).then(function(data) {
                pendingCustomRuleDraft = data.draft || null;
                if (pendingCustomRuleDraft) {
                    hydrateCustomRuleModalDraft(pendingCustomRuleDraft);
                }
                renderCustomRuleTrace(Array.isArray(data.trace) ? data.trace : [], '已生成规则草案，可直接确认或继续修改。', currentRule, pendingCustomRuleDraft);
            }).catch(function(err) {
                var data = err && err.data ? err.data : {};
                renderCustomRuleTrace(Array.isArray(data.trace) ? data.trace : [], (data.error || err.message || '规则草案生成失败'), currentRule);
                alert(data.error || err.message || '规则草案生成失败');
            }).finally(function() {
                btn.disabled = false;
            });
        });

        document.getElementById('confirmCustomRuleBtn').addEventListener('click', function() {
            var rule = collectRuleFromModal();
            if (!rule) {
                return;
            }
            appendCustomRuleRow(rule);
            closeCustomRuleModal();
        });

        function hydrateCustomRuleModalDraft(draft) {
            document.getElementById('manualRuleName').value = draft.name || '';
            document.getElementById('manualRuleSeverity').value = draft.severity || '中风险';
            document.getElementById('manualRulePatterns').value = Array.isArray(draft.patterns) ? draft.patterns.join('\n') : '';
            document.getElementById('manualRuleReason').value = draft.reason || '';
        }

        function collectRuleFromModal() {
            var draft = collectRuleDraftFromModalFields();
            var name = draft.name;
            var severity = draft.severity;
            var patterns = draft.patterns;
            var reason = draft.reason;
            if (!name) {
                alert('请填写规则名称');
                return null;
            }
            if (!patterns.length) {
                alert('请至少填写一条全匹配规则');
                return null;
            }
            return {
                name: name,
                severity: severity,
                patterns: patterns,
                reason: reason
            };
        }

        function collectRuleDraftFromModalFields() {
            return {
                name: document.getElementById('manualRuleName').value.trim(),
                severity: document.getElementById('manualRuleSeverity').value,
                patterns: document.getElementById('manualRulePatterns').value.split('\n').map(function(item) { return item.trim(); }).filter(Boolean),
                reason: document.getElementById('manualRuleReason').value.trim()
            };
        }

        function renderCustomRuleTrace(trace, summary, currentRule, draft) {
            var summaryNode = document.getElementById('customRuleTraceSummary');
            var listNode = document.getElementById('customRuleTraceList');
            if (!summaryNode || !listNode) {
                return;
            }
            summaryNode.textContent = summary || '';
            renderCustomRuleRichTrace(trace, currentRule, draft);
            clearChildren(listNode);
            if (!Array.isArray(trace) || !trace.length) {
                return;
            }
            for (var i = 0; i < trace.length; i++) {
                var item = trace[i] || {};
                var block = document.createElement('div');
                block.className = 'trace-step';
                var title = document.createElement('strong');
                title.textContent = (item.title || item.stage || '步骤') + ' [' + localizeTraceStatus(item.status) + ']';
                block.appendChild(title);
                var summaryText = document.createElement('p');
                summaryText.textContent = item.summary || '';
                block.appendChild(summaryText);
                if (Array.isArray(item.details) && item.details.length) {
                    var list = document.createElement('ul');
                    for (var j = 0; j < item.details.length; j++) {
                        var li = document.createElement('li');
                        li.textContent = String(item.details[j] || '').trim();
                        list.appendChild(li);
                    }
                    block.appendChild(list);
                }
                listNode.appendChild(block);
            }
        }

        function renderCustomRuleRichTrace(trace, currentRule, draft) {
            var inputNode = document.getElementById('customRuleTraceInput');
            var processNode = document.getElementById('customRuleTraceProcess');
            var decisionNode = document.getElementById('customRuleTraceDecision');
            if (!inputNode || !processNode || !decisionNode) {
                return;
            }
            var description = document.getElementById('smartRuleDescription').value.trim();
            setRichTraceContent(inputNode, formatRuleTraceInput(description, currentRule), '启用智能分析并提交后，这里会展示发送给智能体的用户需求和已填写规则摘要。');
            setRichTraceContent(processNode, formatRuleTraceProcess(trace), '这里会展示公开的分析步骤、生成策略和结构化转换过程。');
            setRichTraceContent(decisionNode, formatRuleTraceDecision(draft, trace), '这里会展示规则名称、风险等级、匹配模式数量和确认建议。');
        }

        function setRichTraceContent(node, text, placeholder) {
            var value = (text || '').trim();
            node.textContent = value || placeholder;
            node.classList.toggle('rich-trace-placeholder', !value);
        }

        function formatRuleTraceInput(description, currentRule) {
            if (!description && (!currentRule || (!currentRule.name && !currentRule.patterns.length && !currentRule.reason))) {
                return '';
            }
            var lines = [];
            if (description) {
                lines.push('用户需求：' + description);
            }
            if (currentRule && (currentRule.name || currentRule.patterns.length || currentRule.reason)) {
                lines.push('已填写规则：');
                if (currentRule.name) lines.push('名称：' + currentRule.name);
                lines.push('风险等级：' + (currentRule.severity || '中风险'));
                if (currentRule.patterns.length) lines.push('匹配模式：' + currentRule.patterns.join('；'));
                if (currentRule.reason) lines.push('命中原因：' + currentRule.reason);
            }
            return lines.join('\n');
        }

        function formatRuleTraceProcess(trace) {
            if (!Array.isArray(trace) || !trace.length) {
                return '';
            }
            return trace.map(function(item) {
                var parts = [(item.title || item.stage || '步骤') + '：' + localizeTraceStatus(item.status), item.summary || ''];
                if (Array.isArray(item.details) && item.details.length) {
                    parts.push('细节：' + item.details.join('；'));
                }
                return parts.filter(Boolean).join('\n');
            }).join('\n\n');
        }

        function formatRuleTraceDecision(draft, trace) {
            if (draft && draft.name) {
                return [
                    '规则名称：' + draft.name,
                    '风险等级：' + (draft.severity || '中风险'),
                    '匹配模式数量：' + (Array.isArray(draft.patterns) ? draft.patterns.length : 0),
                    '判断结果：草案已生成，用户可编辑后加入自定义规则列表。'
                ].join('\n');
            }
            if (Array.isArray(trace) && trace.length) {
                var last = trace[trace.length - 1] || {};
                return (last.title || '当前状态') + '：' + (last.summary || localizeTraceStatus(last.status));
            }
            return '';
        }

        function localizeTraceStatus(status) {
            switch ((status || '').trim()) {
                case 'running': return '进行中';
                case 'completed': return '已完成';
                case 'failed': return '失败';
                default: return (status || '').trim() || '待处理';
            }
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
                fi.webkitdirectory = true;
                fi.directory = true;
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
            // 自动提取文件夹名作为技能名
            var skillNameInput = document.getElementById('skillName');
            if (skillNameInput && !skillNameInput.value) {
                for (var i = 0; i < files.length; i++) {
                    var relPath = files[i].webkitRelativePath || files[i].name || '';
                    var parts = relPath.split('/');
                    if (parts.length > 1 && parts[0]) {
                        skillNameInput.value = parts[0];
                        break;
                    }
                }
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
                'running:p0': '正在执行规则基线检测（含高/中/低风险规则）。',
                'running:p1': '正在执行行为与差分复核。',
                'running:p2': '正在执行结构化整理与 LLM 复核。',
                'scoring': '正在汇总风险等级并生成报告。',
                'completed': '扫描已完成，报告已生成。',
                'failed': '扫描失败，请根据失败原因处理后重试。'
            };
            if (task && task.message) {
                return task.message;
            }
            return stageText[task.status] || '扫描中，请稍候。';
        }

        function stageBadgeForTask(task) {
            var stageBadge = {
                'queued': '排队中',
                'running:p0': '规则检测中',
                'running:p1': '行为复核中',
                'running:p2': '结构化复核中',
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
            hideTaskError();
            var panel = document.getElementById('taskStatusPanel');
            var title = document.getElementById('taskStatusTitle');
            var text = document.getElementById('taskStatusText');
            var badge = document.getElementById('taskStatusBadge');
            var meta = document.getElementById('taskStatusMeta');
            var progress = document.getElementById('taskProgress');
            var viewBtn = document.getElementById('taskViewReportBtn');
            var agentBtn = document.getElementById('openAgentAnalysisBtn');
            currentTaskID = task.id || currentTaskID || '';
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
            if (task.detection_errors && task.detection_errors.length) {
                var skippedCount = 0;
                var failedCount = 0;
                for (var i = 0; i < task.detection_errors.length; i++) {
                    var item = task.detection_errors[i] || {};
                    if (item.kind === 'skipped') {
                        skippedCount++;
                    } else {
                        failedCount++;
                    }
                }
                summaryParts.push('检测降级：跳过' + skippedCount + '项/失败' + failedCount + '项');
            }
            var summaryText = summaryParts.length ? ' | 概要：' + summaryParts.join('，') : '';
            var detectionHint = '';
            if (task.detection_errors && task.detection_errors.length) {
                var previews = [];
                for (var j = 0; j < task.detection_errors.length && j < 2; j++) {
                    var err = task.detection_errors[j] || {};
                    var label = (err.kind === 'skipped' ? '跳过' : '失败');
                    previews.push('[' + label + '] ' + (err.rule_id || '-') + ': ' + (err.message || '未知原因'));
                }
                detectionHint = ' | 检测降级详情：' + previews.join('；');
                if (task.detection_errors.length > 2) {
                    detectionHint += '；其余' + (task.detection_errors.length - 2) + '项请查看报告';
                }
            }
            var reqPart = task.request_id ? (' | 请求ID：' + task.request_id) : '';
            meta.textContent = '任务ID：' + (task.id || '-') + reqPart + (task.message ? ' | 说明：' + task.message : '') + summaryText + detectionHint;
            if (task.report_id) {
                viewBtn.href = reportViewURL(task.report_id);
                viewBtn.style.display = 'inline-flex';
            } else {
                viewBtn.href = '/reports';
                viewBtn.style.display = 'none';
            }
            clearChildren(progress);
            if (task.progress) {
                appendTaskProgressChip(progress, task.progress.p0, '规则基线检测');
                appendTaskProgressChip(progress, task.progress.p1, '行为与差分复核');
                appendTaskProgressChip(progress, task.progress.p2, '结构化整理与 LLM 复核');
                appendTaskProgressChip(progress, task.progress.scoring, '报告生成');
            }
            if (agentBtn) {
                agentBtn.style.display = 'inline-flex';
            }
            renderReviewTrace(task.review_trace);
        }

        function showTaskError(title, message, details, action) {
            var panel = document.getElementById('taskErrorPanel');
            var titleNode = document.getElementById('taskErrorTitle');
            var textNode = document.getElementById('taskErrorText');
            var suggestionNode = document.getElementById('taskErrorSuggestion');
            var detailsNode = document.getElementById('taskErrorDetails');
            var actionNode = document.getElementById('taskErrorAction');
            if (!panel || !titleNode || !textNode || !suggestionNode || !detailsNode || !actionNode) {
                return;
            }
            titleNode.textContent = title || '扫描提交失败';
            textNode.textContent = message || '';
            suggestionNode.textContent = arguments.length > 4 && arguments[4] ? ('处理建议：' + arguments[4]) : '';
            detailsNode.textContent = details ? ('错误详情：' + details) : '';
            if (action && action.href && action.label) {
                actionNode.href = action.href;
                actionNode.textContent = action.label;
                actionNode.style.display = 'inline-flex';
            } else {
                actionNode.href = '#';
                actionNode.textContent = '';
                actionNode.style.display = 'none';
            }
            panel.classList.add('show');
        }

        function hideTaskError() {
            var panel = document.getElementById('taskErrorPanel');
            if (panel) {
                panel.classList.remove('show');
            }
        }

        function renderReviewTrace(trace) {
            currentReviewTrace = trace || null;
            currentReviewTraceEntries = [];
            if (!trace || !trace.total) {
                renderLLMIOPanel(null);
                renderAgentAnalysisOptions([], null);
                return;
            }
            var entries = Array.isArray(trace.entries) ? trace.entries.slice() : [];
            entries.sort(function(a, b) {
                return (b.updated_at || 0) - (a.updated_at || 0);
            });
            currentReviewTraceEntries = entries;
            if (!entries.length) {
                renderLLMIOPanel(null);
                renderAgentAnalysisOptions([], null);
                return;
            }
            var preferredId = selectedReviewTraceEntryId || (trace.current_finding_id || '');
            var activeEntry = entries[0];
            for (var i = 0; i < entries.length; i++) {
                if ((entries[i].finding_id || '') === preferredId) {
                    activeEntry = entries[i];
                    break;
                }
            }
            selectedReviewTraceEntryId = activeEntry.finding_id || '';
            renderLLMIOPanel(activeEntry, trace);
            renderAgentAnalysisOptions(entries, activeEntry);
        }

        function renderAgentAnalysisOptions(entries, activeEntry) {
            var select = document.getElementById('agentAnalysisSelect');
            if (!select) {
                return;
            }
            var previous = select.value;
            clearChildren(select);
            if (!Array.isArray(entries) || !entries.length) {
                var empty = document.createElement('option');
                empty.value = '';
                empty.textContent = '暂无 LLM 对话';
                select.appendChild(empty);
                selectedReviewTraceEntryId = '';
                return;
            }
            for (var i = 0; i < entries.length; i++) {
                var entry = entries[i] || {};
                var option = document.createElement('option');
                option.value = entry.finding_id || String(i);
                option.textContent = buildAgentAnalysisOptionLabel(entry, i + 1);
                select.appendChild(option);
            }
            var target = (activeEntry && activeEntry.finding_id) || previous || (entries[0] && entries[0].finding_id) || '';
            select.value = target;
            if (select.value !== target && select.options.length) {
                select.selectedIndex = 0;
            }
        }

        function buildAgentAnalysisOptionLabel(entry, index) {
            var title = (entry.finding_title || entry.finding_id || '待复核风险').trim();
            title = title.replace(/^S\d+-P\d+-\d+\s*/, '').replace(/^[-：:\s]+/, '');
            return index + '-' + title + '智能分析';
        }

        function findCurrentReviewTraceEntry(findingID) {
            for (var i = 0; i < currentReviewTraceEntries.length; i++) {
                var entry = currentReviewTraceEntries[i] || {};
                if ((entry.finding_id || String(i)) === findingID) {
                    return entry;
                }
            }
            return null;
        }

        function localizeReviewVerdict(verdict) {
            switch ((verdict || '').trim()) {
                case 'confirmed':
                    return '已确认风险';
                case 'likely_false_positive':
                    return '疑似误报';
                case 'needs_manual_review':
                    return '需人工复核';
                default:
                    return (verdict || '').trim() || '未给出裁决';
            }
        }

        function localizeReviewProgressStatus(status) {
            switch ((status || '').trim()) {
                case 'pending':
                    return '待执行';
                case 'running':
                    return '复核中';
                case 'completed':
                    return '已完成';
                case 'failed':
                    return '失败';
                default:
                    return (status || '').trim() || '未知状态';
            }
        }

        function localizeReviewToolStatus(status) {
            switch ((status || '').trim()) {
                case 'completed':
                    return '已完成';
                case 'rejected':
                    return '已拒绝';
                case 'failed':
                    return '失败';
                case 'running':
                    return '执行中';
                case 'pending':
                    return '待执行';
                default:
                    return (status || '').trim() || '未知状态';
            }
        }

        function renderLLMIOPanel(entry, trace) {
            var panel = document.getElementById('taskLLMIOPanel');
            var input = document.getElementById('taskLLMInput');
            var process = document.getElementById('taskLLMProcess');
            var decision = document.getElementById('taskLLMDecision');
            var openBtn = document.getElementById('openAgentAnalysisBtn');
            if (!panel || !input || !process || !decision) {
                return;
            }
            if (!entry) {
                panel.style.display = 'block';
                if (openBtn) {
                    openBtn.style.display = 'inline-flex';
                }
                input.textContent = '复核开始后，这里会自动展示发送给 LLM 的目标、输入摘要和采用标准。';
                process.textContent = '这里会展示公开的阶段轨迹、工具步骤和中间判断。';
                decision.textContent = '这里会展示裁决、理由、缺失证据和修复建议。';
                input.className = 'llm-io-empty';
                process.className = 'llm-io-empty';
                decision.className = 'llm-io-empty';
                return;
            }
            panel.style.display = 'block';
            if (openBtn) {
                openBtn.style.display = 'inline-flex';
            }
            input.className = '';
            process.className = '';
            decision.className = '';
            input.textContent = buildLLMInputText(entry, trace);
            process.textContent = buildLLMProcessText(entry, trace);
            decision.textContent = buildLLMDecisionText(entry, trace);
        }

        function buildLLMInputText(entry, trace) {
            var lines = [];
            lines.push('风险项：' + (entry.finding_title || entry.finding_id || '待复核风险'));
            if (entry.objective) {
                lines.push('复核目标：' + entry.objective);
            }
            if (entry.prompt_summary) {
                lines.push('提示词摘要：' + entry.prompt_summary);
            }
            if (entry.input_digest) {
                lines.push('输入摘要：' + entry.input_digest);
            }
            if (Array.isArray(entry.standards_applied) && entry.standards_applied.length) {
                lines.push('采用标准：');
                for (var i = 0; i < entry.standards_applied.length; i++) {
                    lines.push('- ' + entry.standards_applied[i]);
                }
            }
            if (trace && trace.current_summary) {
                lines.push('任务上下文：' + trace.current_summary);
            }
            return lines.join('\n');
        }

        function buildLLMProcessText(entry, trace) {
            var lines = [];
            lines.push('阶段状态：' + localizeReviewProgressStatus(entry.status));
            if (trace && trace.current_objective) {
                lines.push('当前总目标：' + trace.current_objective);
            }
            if (entry.tool_trace && entry.tool_trace.length) {
                lines.push('工具轨迹：');
                for (var i = 0; i < entry.tool_trace.length; i++) {
                    var tool = entry.tool_trace[i] || {};
                    var line = '- 第 ' + (tool.iteration || (i + 1)) + ' 步 | ' + (tool.tool_name || 'tool') + ' | ' + localizeReviewToolStatus(tool.status);
                    if (tool.summary) {
                        line += ' | ' + tool.summary;
                    }
                    lines.push(line);
                }
            }
            if (!entry.tool_trace || !entry.tool_trace.length) {
                lines.push('工具轨迹：当前暂无可展示步骤。');
            }
            if (entry.failure_kind) {
                lines.push('异常类型：' + localizeReviewFailureShortLabel(entry.failure_kind, entry.failure_label));
            }
            if (entry.duration_ms) {
                lines.push('耗时：' + entry.duration_ms + 'ms');
            }
            return lines.join('\n');
        }

        function buildLLMDecisionText(entry, trace) {
            var lines = [];
            lines.push('裁决：' + localizeReviewVerdict(entry.verdict));
            if (entry.confidence) {
                lines.push('置信度：' + entry.confidence);
            }
            if (entry.reviewer) {
                lines.push('Reviewer：' + entry.reviewer);
            }
            if (entry.reason) {
                lines.push('理由：' + entry.reason);
            }
            if (Array.isArray(entry.missing_evidence) && entry.missing_evidence.length) {
                lines.push('缺失证据：');
                for (var i = 0; i < entry.missing_evidence.length; i++) {
                    lines.push('- ' + entry.missing_evidence[i]);
                }
            }
            if (entry.fix) {
                lines.push('修复建议：' + entry.fix);
            }
            if (trace && trace.last_verdict) {
                lines.push('任务最近裁决：' + localizeReviewVerdict(trace.last_verdict));
            }
            return lines.join('\n');
        }

        function localizeReviewFailureShortLabel(kind, label) {
            switch ((kind || '').trim()) {
                case 'balance_exhausted':
                    return '余额不足';
                case 'request_canceled':
                    return '请求取消';
                case 'timeout':
                    return '超时';
                case 'invalid_response':
                    return '无效响应';
                case 'tool_rejected':
                    return '工具拒绝';
                case 'iteration_limit':
                    return '迭代上限';
                case 'execution_error':
                    return '执行失败';
                default:
                    return (label || '').trim() || '失败';
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
            if (!currentTaskID) {
                resetTaskStatusUI();
                return;
            }
            if (!confirm('确认取消当前扫描任务吗？')) {
                return;
            }
            cancelScanTask(currentTaskID).finally(function() {
                resetTaskStatusUI();
            });
        });

        function cancelScanTask(taskID) {
            return fetchJSON('/api/scan/tasks/' + encodeURIComponent(taskID) + '/cancel', { method: 'POST' })
                .catch(function(err) {
                    alert((err && err.message) || '取消任务失败');
                });
        }

        function resetTaskStatusUI() {
            clearActiveTask();
            currentTaskID = '';
            document.getElementById('taskStatusPanel').classList.remove('show');
            document.getElementById('taskViewReportBtn').style.display = 'none';
            document.getElementById('openAgentAnalysisBtn').style.display = 'none';
            document.getElementById('submitBtn').disabled = false;
            document.getElementById('loading').style.display = 'none';
            renderLLMIOPanel(null);
            closeAgentAnalysisModal();
            hideTaskError();
        }

        function openAgentAnalysisModal() {
            var modal = document.getElementById('agentAnalysisModal');
            var panel = document.getElementById('taskLLMIOPanel');
            if (modal) {
                modal.classList.add('show');
            }
            if (panel) {
                panel.style.display = 'block';
            }
        }

        function closeAgentAnalysisModal() {
            var modal = document.getElementById('agentAnalysisModal');
            if (modal) {
                modal.classList.remove('show');
            }
        }

        document.getElementById('openAgentAnalysisBtn').addEventListener('click', openAgentAnalysisModal);
        document.getElementById('closeAgentAnalysisModalBtn').addEventListener('click', closeAgentAnalysisModal);
        document.getElementById('agentAnalysisSelect').addEventListener('change', function() {
            var entry = findCurrentReviewTraceEntry(this.value);
            selectedReviewTraceEntryId = entry ? (entry.finding_id || '') : '';
            renderLLMIOPanel(entry, currentReviewTrace);
        });

        document.getElementById('copyLLMIOBtn').addEventListener('click', function() {
            var button = this;
            var input = document.getElementById('taskLLMInput');
            var process = document.getElementById('taskLLMProcess');
            var decision = document.getElementById('taskLLMDecision');
            var text = [
                '发送内容\n' + (input ? input.textContent : ''),
                '分析过程\n' + (process ? process.textContent : ''),
                '最终判断\n' + (decision ? decision.textContent : '')
            ].join('\n\n');
            var resetText = function() {
                button.textContent = '复制内容';
            };
            var markCopied = function() {
                button.textContent = '已复制';
                window.setTimeout(resetText, 1200);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(markCopied).catch(function() {
                    resetText();
                });
                return;
            }
            var textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                markCopied();
            } catch (e) {
                resetText();
            }
            document.body.removeChild(textarea);
        });

        document.getElementById('taskErrorDismissBtn').addEventListener('click', function() {
            hideTaskError();
        });

        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (selectedFiles.length === 0) {
                alert('请至少选择一个文件');
                return;
            }
            
            var loading = document.getElementById('loading');
            var sb = document.getElementById('submitBtn');
            hideTaskError();
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
            var skillName = (document.getElementById('skillName').value || '').trim();
            if (skillName.length > 100) { skillName = skillName.substring(0, 100); }
            formData.append('skill_name', skillName);
            var userNotes = (document.getElementById('userNotes').value || '').trim();
            if (userNotes.length > 2000) { userNotes = userNotes.substring(0, 2000); }
            formData.append('user_notes', userNotes);

            fetchJSON('/scan', { method: 'POST', body: formData })
                .then(function(data) {
                    if (data.success) {
                        startTaskPolling(data.task_id, loading, sb);
                    } else {
                        loading.style.display = 'none';
                        showTaskError('扫描提交失败', data.error || '未知错误', data.details || '', data.action || null, data.suggestion || '');
                        sb.disabled = false;
                    }
                })
                .catch(function(err) {
                    loading.style.display = 'none';
                    var data = err && err.data ? err.data : {};
                    showTaskError(data.error ? '扫描提交失败' : '上传失败', data.error || err.message || '未知错误', data.details || '', data.action || null, data.suggestion || '');
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
        {{template "dropdownBaseCSS"}}
        .container { max-width: 760px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .info-row { padding: 16px 24px; border-bottom: 1px solid #eee; display: flex; align-items: center; }
        .info-row:last-child { border-bottom: none; }
        .info-row .label { color: #888; font-size: 14px; width: 100px; flex-shrink: 0; }
        .info-row .value { color: #333; font-weight: 500; }
        .admin-badge { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .llm-card { margin: 20px 24px 24px; border: 1px solid #e6e9f5; border-radius: 16px; background: linear-gradient(180deg, #ffffff 0%, #fbfcff 100%); box-shadow: 0 12px 30px rgba(31, 41, 55, 0.06); overflow: hidden; }
        .llm-card .panel-header { background: #f8faff; }
        .llm-body { padding: 24px; }
        .llm-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
        .llm-field { display: flex; flex-direction: column; gap: 8px; }
        .llm-field label { color: #4b5563; font-size: 13px; font-weight: 700; }
        .llm-field select, .llm-field input { width: 100%; padding: 12px 14px; border: 1px solid #d6dbea; border-radius: 10px; font-size: 14px; background: white; }
        .llm-field select:focus, .llm-field input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,.14); }
        .llm-switch { display: inline-flex; align-items: center; gap: 10px; color: #374151; font-size: 14px; font-weight: 700; margin-bottom: 16px; }
        .llm-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 4px; }
        .llm-actions button { padding: 11px 18px; border: 0; border-radius: 10px; cursor: pointer; }
        .llm-primary { background: #4f46e5; color: #fff; }
        .llm-secondary { background: #eef2ff; color: #3730a3; }
        .llm-hint { color: #667085; font-size: 13px; line-height: 1.6; margin-top: 14px; }
        @media (max-width: 720px) { .llm-card { margin: 16px; } .llm-grid { grid-template-columns: 1fr; } .header { padding: 16px; flex-wrap: wrap; } .header-nav { width: 100%; overflow-x: auto; margin-right: 0; } }
    </style>
</head>
<body>
    {{template "appHeader" (dict "Title" "个人中心" "Active" "personal" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "personalUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>账号信息</h2>
            </div>
			<div class="llm-card">
				<div class="panel-header">
					<h2>LLM 深度分析配置</h2>
				</div>
				<div class="llm-body">
					<div id="llmMsg" class="msg" style="display:none;"></div>
					<label class="llm-switch">
							<input type="checkbox" id="llmEnabled"> 启用 LLM 辅助分析
					</label>
					<div class="llm-grid">
						<div class="llm-field">
							<label for="llmProvider">选择大模型</label>
							<select id="llmProvider"></select>
						</div>
						<div class="llm-field">
							<label for="llmApiKey">个人 API Key</label>
							<input type="password" id="llmApiKey" placeholder="填写后优先使用个人 Key">
						</div>
					</div>
					<div class="llm-actions">
						<button id="saveLLMBtn" class="llm-primary" type="button">保存配置</button>
						<button id="deleteLLMKeyBtn" class="llm-secondary" type="button">清除个人 Key</button>
					</div>
					<p class="llm-hint">个人 Key 会加密保存并优先用于扫描；留空时自动使用管理员在「设置 → 大模型」中配置的系统 Key。如果管理员已配置 API Key，你只需选择提供商并启用即可，无需重复填写。</p>
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
		{{template "bindDropdownMenuScript"}}
		bindDropdownMenu('personalUserMenuButton', 'userDropdown');
		// ----- LLM 配置相关 -----
		var llmProviderSelect = document.getElementById('llmProvider');

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
				document.getElementById('llmApiKey').value = '';
				llmProviderSelect.innerHTML = '';
				(data.providers || []).forEach(function(provider) {
					var option = document.createElement('option');
					option.value = provider.id;
					option.textContent = provider.name + ' / ' + provider.protocol + ' / ' + provider.model;
					llmProviderSelect.appendChild(option);
				});
				if (data.provider) {
					llmProviderSelect.value = data.provider;
				}
			})
			.catch(() => {
				showLLMMsg('加载当前配置失败，请刷新后重试。', false);
			});

		function showLLMMsg(text, isSuccess) {
			var msg = document.getElementById('llmMsg');
			msg.textContent = text;
			msg.className = 'msg ' + (isSuccess ? 'success' : 'error');
			msg.style.display = 'block';
			setTimeout(() => msg.style.display = 'none', 3000);
		}

		document.getElementById('saveLLMBtn').addEventListener('click', function() {
			var enabled = document.getElementById('llmEnabled').checked;
			var apiKey = document.getElementById('llmApiKey').value.trim();

			var payload = {
				enabled: enabled,
				provider: llmProviderSelect.value,
				api_key: apiKey,
				delete_key: false
			};

			fetch('/api/user/llm', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify(payload)
			})
			.then(res => res.json().catch(() => ({})).then(data => { if (!res.ok) throw new Error(data.error || '保存失败'); return data; }))
			.then(() => {
				showLLMMsg('配置已保存', true);
				document.getElementById('llmApiKey').value = '';
			})
			.catch(err => showLLMMsg('保存失败: ' + err.message, false));
		});

		document.getElementById('deleteLLMKeyBtn').addEventListener('click', function() {
			var payload = {
				enabled: document.getElementById('llmEnabled').checked,
				provider: llmProviderSelect.value,
				api_key: '',
				delete_key: true
			};
			fetch('/api/user/llm', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify(payload)
			})
			.then(res => res.json().catch(() => ({})).then(data => { if (!res.ok) throw new Error(data.error || '清除失败'); return data; }))
			.then(() => {
				document.getElementById('llmApiKey').value = '';
				showLLMMsg('个人 Key 已清除', true);
			})
			.catch(err => showLLMMsg('清除失败: ' + err.message, false));
		});
    </script>
</body>
</html>
`

const RuntimeHelpHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>运行环境修复说明 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        {{template "dropdownBaseCSS"}}
        .container { max-width: 980px; margin: 32px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 16px; box-shadow: 0 8px 28px rgba(15, 23, 42, 0.08); padding: 24px; margin-bottom: 18px; }
        .panel h2 { color: #101828; margin-bottom: 10px; }
        .panel p, .panel li { color: #475467; line-height: 1.7; }
        .panel ul { padding-left: 20px; margin-top: 10px; }
        .quick-links { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
        .quick-links a { display: inline-flex; align-items: center; justify-content: center; padding: 8px 12px; border-radius: 8px; background: #eef2ff; color: #364152; text-decoration: none; font-size: 13px; font-weight: 600; }
        .quick-links a:hover { background: #dde5ff; }
        code { background: #f2f4f7; padding: 2px 6px; border-radius: 6px; }
    </style>
</head>
<body>
{{template "appHeader" (dict "Title" "运行环境修复说明" "Active" "settings" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "runtimeHelpUserMenuButton" "MenuID" "userDropdown")}}
<div class="container">
    <div class="panel">
        <h2>修复入口</h2>
        <p>本页聚合当前运行环境常见阻塞项的修复说明。状态卡中的按钮会直接跳到对应段落。</p>
        <div class="quick-links">
            <a href="#sandbox">沙箱运行时</a>
            <a href="#semantic">语义引擎</a>
            <a href="/personal">个人中心 LLM 配置</a>
            <a href="/settings?tab=llm">系统 Provider 配置</a>
        </div>
    </div>
    <div class="panel" id="sandbox">
        <h2>沙箱运行时</h2>
        <p>当状态卡提示沙箱未就绪时，优先检查 runsc 和 Docker runtime 注册。</p>
        <ul>
            <li>确认 Docker 可用 (docker info)</li>
            <li>确认 zeroclaw-sandbox 镜像存在 (docker images | grep zeroclaw-sandbox)</li>
            <li>确认环境变量 REVIEW_SANDBOX_IMAGE 设置正确</li>
        </ul>
        <pre style="margin-top:14px;background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:12px;overflow:auto;"><code>docker info
docker images | grep zeroclaw-sandbox
</code></pre>
    </div>
    <div class="panel" id="semantic">
        <h2>语义引擎</h2>
        <p>当状态卡提示语义引擎未就绪时，优先检查 ONNX Runtime 和 BGE 模型目录。</p>
        <ul>
            <li>确认 SKILL_SCANNER_ONNX_RUNTIME_LIB 指向有效动态库</li>
            <li>确认 SKILL_SCANNER_BGE_MODEL_DIR 指向有效模型目录</li>
            <li>默认候选目录包含 <code>models/bge-large-zh-v1.5</code> 与 <code>../models/bge-large-zh-v1.5</code></li>
        </ul>
        <pre style="margin-top:14px;background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:12px;overflow:auto;"><code>ls "models/bge-large-zh-v1.5"
ls "/usr/local/lib/libonnxruntime.so"
</code></pre>
    </div>
</div>
<script>
{{template "bindDropdownMenuScript"}}
bindDropdownMenu('runtimeHelpUserMenuButton', 'userDropdown');
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
        {{template "dropdownBaseCSS"}}
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
    {{template "appHeader" (dict "Title" "用户管理" "Active" "settings" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "adminUsersMenuButton" "MenuID" "userDropdown")}}
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
        {{template "bindDropdownMenuScript"}}
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

// PolicyBlacklistHTML is the policy blacklist management page template.
const PolicyBlacklistHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>黑名单管理 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header a { color: white; text-decoration: none; opacity: .9; }
        .container { max-width: 1100px; margin: 30px auto; padding: 0 20px; }
        .msg { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; }
        .msg.error { background: #fee; color: #c00; }
        .msg.success { background: #efe; color: #060; }
        .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,.05); padding: 18px; margin-bottom: 16px; }
        .form-grid { display: grid; grid-template-columns: 160px 1fr auto; gap: 10px; }
        select, input { width: 100%; padding: 10px 12px; border: 1px solid #d0d5dd; border-radius: 8px; }
        button { padding: 10px 14px; border: 0; border-radius: 8px; background: #3b5ccc; color: #fff; cursor: pointer; }
        .toolbar { display: flex; gap: 10px; align-items: center; justify-content: space-between; flex-wrap: wrap; margin-bottom: 10px; }
        .search { display: flex; gap: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        .danger { background: #b42318; }
        .muted { color: #667085; font-size: 13px; }
        .pager { display: flex; gap: 6px; margin-top: 12px; }
        .pager a, .pager span { padding: 6px 10px; border-radius: 6px; text-decoration: none; background: #eef2ff; color: #364152; font-size: 13px; }
        .pager .active { background: #3b5ccc; color: #fff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>黑名单管理</h1>
        <a href="/settings?tab=blacklist">返回设置</a>
    </div>
    <div class="container">
        {{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
        {{if .Success}}<div class="msg success">{{.Success}}</div>{{end}}

        <div class="card">
            <h3 style="margin-bottom:10px;">新增黑名单</h3>
            <form method="POST" action="/admin/policy-blacklist?page={{.Page}}&page_size={{.PageSize}}{{.QuerySuffix}}">
                <input type="hidden" name="action" value="add">
                <div class="form-grid">
                    <select name="item_type">
                        <option value="domain">域名</option>
                        <option value="ip">IP（IPv4/IPv6）</option>
                    </select>
                    <input type="text" name="item" placeholder="域名示例：example.com，IP示例：2001:db8::1">
                    <button type="submit">添加</button>
                </div>
            </form>
        </div>

        <div class="card">
            <div class="toolbar">
                <div class="muted">共 {{.Total}} 条，当前每页 {{.PageSize}} 条</div>
                <div class="search">
                    <form method="GET" action="/admin/policy-blacklist" style="display:flex;gap:8px;">
                        <input type="text" name="q" value="{{.Keyword}}" placeholder="搜索黑名单内容">
                        <select name="page_size">
                            <option value="20" {{if eq .PageSize 20}}selected{{end}}>20/页</option>
                            <option value="50" {{if eq .PageSize 50}}selected{{end}}>50/页</option>
                            <option value="100" {{if eq .PageSize 100}}selected{{end}}>100/页</option>
                        </select>
                        <button type="submit">查询</button>
                    </form>
                </div>
            </div>
            <table>
                <thead><tr><th>类型</th><th>内容</th><th>创建时间</th><th>更新时间</th><th>操作</th></tr></thead>
                <tbody>
                    {{range .Items}}
                    <tr>
                        <td>{{.TypeLabel}}</td>
                        <td>{{.Value}}</td>
                        <td>{{.CreatedAt}}</td>
                        <td>{{.UpdatedAt}}</td>
                        <td style="display:flex;gap:8px;">
                            <form method="POST" action="/admin/policy-blacklist?page={{$.Page}}&page_size={{$.PageSize}}{{$.QuerySuffix}}" style="display:flex;gap:6px;">
                                <input type="hidden" name="action" value="update">
                                <input type="hidden" name="old_type" value="{{.Type}}">
                                <input type="hidden" name="old_value" value="{{.Value}}">
                                <select name="item_type" style="width:120px;">
                                    <option value="domain" {{if eq .Type "domain"}}selected{{end}}>域名</option>
                                    <option value="ip" {{if eq .Type "ip"}}selected{{end}}>IP</option>
                                </select>
                                <input type="text" name="item" value="{{.Value}}" style="width:220px;">
                                <button type="submit">修改</button>
                            </form>
                            <form method="POST" action="/admin/policy-blacklist?page={{$.Page}}&page_size={{$.PageSize}}{{$.QuerySuffix}}" style="display:inline;">
                                <input type="hidden" name="action" value="remove">
                                <input type="hidden" name="item_type" value="{{.Type}}">
                                <input type="hidden" name="item" value="{{.Value}}">
                                <button type="submit" class="danger">删除</button>
                            </form>
                        </td>
                    </tr>
                    {{else}}
                    <tr><td colspan="5" class="muted">暂无数据</td></tr>
                    {{end}}
                </tbody>
            </table>
            <div class="pager">
                <a href="/admin/policy-blacklist?page={{.PrevPage}}&page_size={{.PageSize}}{{.QuerySuffix}}">上一页</a>
                {{range .Pages}}
                    {{if eq . $.Page}}<span class="active">{{.}}</span>{{else}}<a href="/admin/policy-blacklist?page={{.}}&page_size={{$.PageSize}}{{$.QuerySuffix}}">{{.}}</a>{{end}}
                {{end}}
                <a href="/admin/policy-blacklist?page={{.NextPage}}&page_size={{.PageSize}}{{.QuerySuffix}}">下一页</a>
            </div>
        </div>
    </div>
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
        {{template "dropdownBaseCSS"}}
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
    {{template "appHeader" (dict "Title" "登录日志" "Active" "settings" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "loginLogUserMenuButton" "MenuID" "userDropdown")}}
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
        {{template "bindDropdownMenuScript"}}
        bindDropdownMenu('loginLogUserMenuButton', 'userDropdown');
    </script>
</body>
</html>
`

// SettingsHTML is the system settings page template.
const SettingsAdminHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>设置 - 技能扫描器</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; color: #111827; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); gap: 16px; flex-wrap: wrap; }
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
.dropdown-menu a.danger { color: #c00; background: transparent; }
.dropdown-menu a.danger:hover { background: #f5f6fa; }
.dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }

.layout { max-width: 1240px; margin: 28px auto; padding: 0 20px; display: grid; grid-template-columns: 240px 1fr; gap: 16px; }
.sidebar { background: #fff; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,.05); overflow: hidden; }
.sidebar h3 { padding: 14px 16px; font-size: 14px; color: #475467; border-bottom: 1px solid #eef2f6; background: #f9fbff; }
.sidebar a { display: block; padding: 12px 16px; text-decoration: none; color: #344054; border-left: 3px solid transparent; }
.sidebar a:hover { background: #f8faff; }
.sidebar a.active { background: #eef4ff; color: #2156d1; border-left-color: #2156d1; font-weight: 600; }
.main { background: #fff; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,.05); padding: 18px; }
.section-title { font-size: 18px; color: #101828; margin-bottom: 14px; }
.msg { padding: 10px 12px; border-radius: 8px; margin-bottom: 12px; }
.msg.error { background: #fff1f0; color: #b42318; border: 1px solid #f0b7bf; }
.msg.success { background: #ecfdf3; color: #067647; border: 1px solid #a6f4c5; }

.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.toolbar .group { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
input, select, textarea { padding: 9px 11px; border: 1px solid #d0d5dd; border-radius: 8px; min-height: 38px; font: inherit; }
input:focus, select:focus, textarea:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 2px rgba(102,126,234,.15); }
button { padding: 9px 12px; border: 0; border-radius: 8px; background: #3b5ccc; color: #fff; cursor: pointer; }
button:hover { background: #304fb4; }
.danger { background: #b42318; }
.danger:hover { background: #912018; }
.btn-link { display: inline-flex; align-items: center; justify-content: center; min-height: 38px; padding: 9px 12px; border-radius: 8px; background: #eef2ff; color: #364152; text-decoration: none; }
.btn-link:hover { background: #dde5ff; }
.blacklist-dialog-backdrop { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.45); display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 200; }
.blacklist-dialog { width: min(720px, 100%); background: #fff; border-radius: 16px; box-shadow: 0 20px 50px rgba(15, 23, 42, 0.24); overflow: hidden; }
.blacklist-dialog-header { display: flex; align-items: center; justify-content: space-between; padding: 18px 20px; border-bottom: 1px solid #eef2f6; }
.blacklist-dialog-title { font-size: 18px; font-weight: 600; color: #101828; }
.blacklist-dialog-close { background: transparent; color: #667085; font-size: 20px; padding: 4px 10px; }
.blacklist-dialog-close:hover { background: #f8faff; color: #344054; }
.blacklist-dialog-body { padding: 20px; }
.blacklist-dialog-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
.blacklist-leave-dialog .blacklist-dialog { width: min(560px, 100%); }
.filter-input { min-width: 160px; }
.filter-select { min-width: 120px; }

table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eef2f6; vertical-align: middle; }
th { color: #667085; font-size: 13px; background: #fafbfc; }
.pager { display: flex; gap: 6px; margin-top: 12px; }
.pager a, .pager span { display: inline-block; padding: 6px 10px; border-radius: 6px; text-decoration: none; background: #eef2ff; color: #364152; font-size: 13px; }
.pager .active { background: #3b5ccc; color: #fff; }
.muted { color: #667085; font-size: 13px; }
.table-wrap { width: 100%; overflow-x: auto; border: 1px solid #eef2f6; border-radius: 10px; }
.llm-config-card { border: 1px solid #e3e8f7; border-radius: 18px; background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%); box-shadow: 0 18px 45px rgba(31, 41, 55, 0.08); overflow: hidden; margin-bottom: 18px; }
.llm-config-head { padding: 20px 22px; border-bottom: 1px solid #eef2f6; display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; background: radial-gradient(circle at top left, rgba(102,126,234,.14), transparent 32%), #fbfcff; }
.llm-config-title { font-size: 18px; font-weight: 700; color: #101828; margin-bottom: 6px; }
.llm-config-copy { color: #667085; font-size: 13px; line-height: 1.6; max-width: 720px; }
.llm-provider-form { padding: 22px; display: grid; grid-template-columns: minmax(180px, .8fr) minmax(220px, 1fr) minmax(320px, 1.5fr); gap: 16px; align-items: end; }
.llm-provider-form .span-2 { grid-column: span 2; }
.llm-provider-form label { display: flex; flex-direction: column; gap: 7px; color: #344054; font-size: 13px; font-weight: 700; }
.llm-provider-form input, .llm-provider-form select { width: 100%; min-height: 44px; background: #fff; }
.llm-provider-actions { display: flex; align-items: end; }
.llm-provider-actions button { width: 100%; min-height: 44px; font-weight: 700; background: #4f46e5; }
.llm-provider-table td:nth-child(5) { min-width: 260px; }
.status-pill { display: inline-flex; align-items: center; padding: 4px 9px; border-radius: 999px; font-size: 12px; font-weight: 700; }
.status-pill.enabled { background: #ecfdf3; color: #067647; }
.status-pill.disabled { background: #f2f4f7; color: #667085; }
.llm-toggle-btn { background: #eef2ff; color: #3730a3; }
.llm-toggle-btn:hover { background: #dde5ff; }
{{template "runtimeStatusCSS"}}

@media (max-width: 1000px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { display: flex; flex-direction: column; }
  .llm-provider-form { grid-template-columns: 1fr 1fr; }
  .llm-provider-form .span-2 { grid-column: span 2; }
}

@media (max-width: 760px) {
  .header { padding: 14px 16px; }
  .header h1 { font-size: 20px; }
  .header-nav { width: 100%; margin-right: 0; overflow-x: auto; white-space: nowrap; padding-bottom: 2px; }
  .header-right { width: 100%; justify-content: flex-end; }
  .main { padding: 12px; }
  input, select, textarea, button, .btn-link { width: 100%; }
  .row { display: grid; grid-template-columns: 1fr; }
  .llm-provider-form { grid-template-columns: 1fr; padding: 16px; }
  .llm-provider-form .span-2 { grid-column: span 1; }
  .llm-config-head { flex-direction: column; padding: 16px; }
  .toolbar { align-items: stretch; }
  .toolbar .group { width: 100%; }
  .pager { flex-wrap: wrap; }
  .blacklist-dialog-actions { flex-direction: column; }
}
</style>
</head>
<body>
{{template "appHeader" (dict "Title" "设置" "Active" "settings" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "settingsAdminUserMenuButton" "MenuID" "userDropdown")}}

<div class="layout">
  <aside class="sidebar">
    <h3>系统设置</h3>
    {{if .HasUserMgmt}}<a href="/settings?tab=users" class="{{if eq .Tab "users"}}active{{end}}">用户管理</a>{{end}}
    {{if .HasLogPerm}}<a href="/settings?tab=logs" class="{{if eq .Tab "logs"}}active{{end}}">登录日志</a>{{end}}
    {{if .HasUserMgmt}}<a href="/settings?tab=blacklist" class="{{if eq .Tab "blacklist"}}active{{end}}">黑名单</a>{{end}}
    {{if .HasUserMgmt}}<a href="/settings?tab=llm" class="{{if eq .Tab "llm"}}active{{end}}">大模型</a>{{end}}
  </aside>
  <main class="main">
    {{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
    {{if .Success}}<div class="msg success">{{.Success}}</div>{{end}}
    {{template "runtimeStatusPanel" .}}

    {{if eq .Tab "users"}}
      <h2 class="section-title">用户管理</h2>
      <form method="POST" action="/settings?tab=users" class="row">
        <input type="hidden" name="action" value="add_user">
        <input name="username" placeholder="用户名" required>
        <input name="password" type="password" placeholder="密码" required>
        <input name="team" placeholder="团队">
        <button type="submit">添加用户</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>用户名</th><th>团队</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody>
          {{range .Users}}
            <tr>
              <td>{{.Username}}</td><td>{{.Team}}</td><td>{{.CreatedAt}}</td>
              <td>{{if .CanDelete}}<form method="POST" action="/settings?tab=users" style="display:inline;"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="username" value="{{.Username}}"><button class="danger" type="submit">删除</button></form>{{else}}<span class="muted">不可删除</span>{{end}}</td>
            </tr>
          {{end}}
        </tbody>
      </table></div>
    {{end}}

    {{if eq .Tab "logs"}}
      <h2 class="section-title">登录日志</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>用户名</th><th>时间</th><th>结果</th><th>IP</th></tr></thead>
        <tbody>
          {{range .Logs}}<tr><td>{{.Username}}</td><td>{{.Timestamp}}</td><td>{{.Result}}</td><td>{{.IP}}</td></tr>{{else}}<tr><td colspan="4" class="muted">暂无记录</td></tr>{{end}}
        </tbody>
      </table></div>
    {{end}}

      {{if eq .Tab "blacklist"}}
      <h2 class="section-title">黑名单</h2>
      {{if .BlacklistDraftDirty}}<div class="msg error">检测到未保存草稿：当前修改尚未生效。点击“保存配置”后才会应用到检测。</div>{{end}}
      <div class="toolbar">
        <form method="GET" action="/settings" class="group" style="margin:0;">
          <input type="hidden" name="tab" value="blacklist">
          <input name="q" value="{{.Keyword}}" placeholder="搜索黑名单" class="filter-input">
          <select name="type" class="filter-select">
            <option value="" {{if eq .BlacklistTypeFilter ""}}selected{{end}}>全部类型</option>
            <option value="domain" {{if eq .BlacklistTypeFilter "domain"}}selected{{end}}>仅域名</option>
            <option value="ipv4" {{if eq .BlacklistTypeFilter "ipv4"}}selected{{end}}>仅 IPv4</option>
            <option value="ipv6" {{if eq .BlacklistTypeFilter "ipv6"}}selected{{end}}>仅 IPv6</option>
          </select>
          <input type="date" name="date_from" value="{{.BlacklistDateFrom}}" class="filter-input">
          <input type="date" name="date_to" value="{{.BlacklistDateTo}}" class="filter-input">
          <select name="page_size" class="filter-select"><option value="20" {{if eq .PageSize 20}}selected{{end}}>20/页</option><option value="50" {{if eq .PageSize 50}}selected{{end}}>50/页</option><option value="100" {{if eq .PageSize 100}}selected{{end}}>100/页</option></select>
          <button type="submit">查询</button>
        </form>
        <div class="group">
          <a href="/settings?tab=blacklist&page={{.Page}}&page_size={{.PageSize}}&q={{.Keyword}}&type={{.BlacklistTypeFilter}}&date_from={{.BlacklistDateFrom}}&date_to={{.BlacklistDateTo}}&add=1" class="btn-link">添加</a>
          <form method="POST" action="/settings?tab=blacklist" class="row" style="margin:0;">
          <input type="hidden" name="action" value="save_blacklist">
          <button type="submit">保存配置</button>
          </form>
        </div>
      </div>
      {{if .BlacklistAddOpen}}
      <div class="blacklist-dialog-backdrop" id="blacklistAddBackdrop">
        <div class="blacklist-dialog" role="dialog" aria-modal="true" aria-labelledby="blacklistDialogTitle">
          <div class="blacklist-dialog-header">
            <div class="blacklist-dialog-title" id="blacklistDialogTitle">添加黑名单目标</div>
            <a href="/settings?tab=blacklist&page={{.Page}}&page_size={{.PageSize}}&q={{.Keyword}}&type={{.BlacklistTypeFilter}}&date_from={{.BlacklistDateFrom}}&date_to={{.BlacklistDateTo}}" class="btn-link" style="min-height:auto;padding:4px 10px;">关闭</a>
          </div>
          <div class="blacklist-dialog-body">
            <form method="POST" action="/settings?tab=blacklist&page={{.Page}}&page_size={{.PageSize}}&q={{.Keyword}}&type={{.BlacklistTypeFilter}}&date_from={{.BlacklistDateFrom}}&date_to={{.BlacklistDateTo}}" id="blacklistAddForm">
              <input type="hidden" name="action" value="add_blacklist">
              {{if .BlacklistAddError}}<div class="msg error" style="margin-bottom:12px;">{{.BlacklistAddError}}</div>{{end}}
              <div class="row" style="margin-bottom:0;align-items:flex-start;">
                <select name="item_type" id="blacklistItemType" style="min-width:140px;">
                  <option value="domain" {{if eq .BlacklistAddType "domain"}}selected{{end}}>域名</option>
                  <option value="ipv4" {{if eq .BlacklistAddType "ipv4"}}selected{{end}}>IPv4</option>
                  <option value="ipv6" {{if eq .BlacklistAddType "ipv6"}}selected{{end}}>IPv6</option>
                </select>
                <textarea name="item_value" id="blacklistItemValue" rows="8" style="flex:1;min-width:420px;resize:vertical;">{{.BlacklistAddValue}}</textarea>
              </div>
              <p class="muted" style="margin-top:10px;">输入校验：根据类型校验域名、IPv4、IPv6；支持批量换行输入，IP 类型支持 CIDR 段。</p>
              <div class="blacklist-dialog-actions">
                <a href="/settings?tab=blacklist&page={{.Page}}&page_size={{.PageSize}}&q={{.Keyword}}&type={{.BlacklistTypeFilter}}&date_from={{.BlacklistDateFrom}}&date_to={{.BlacklistDateTo}}" class="btn-link">取消</a>
                <button type="submit">确定</button>
              </div>
            </form>
          </div>
        </div>
      </div>
      {{end}}
      <div class="blacklist-dialog-backdrop blacklist-leave-dialog" id="blacklistLeaveDialog" style="display:none;">
        <div class="blacklist-dialog" role="dialog" aria-modal="true" aria-labelledby="blacklistLeaveDialogTitle">
          <div class="blacklist-dialog-header">
            <div class="blacklist-dialog-title" id="blacklistLeaveDialogTitle">离开黑名单页面</div>
            <button type="button" class="blacklist-dialog-close" id="blacklistLeaveCloseBtn" aria-label="关闭">×</button>
          </div>
          <div class="blacklist-dialog-body">
            <p style="color:#475467;line-height:1.7;">黑名单规则未保存。请选择保存当前草稿后离开，或放弃当前草稿后离开。</p>
            <div class="blacklist-dialog-actions">
              <button type="button" class="btn-link" id="blacklistLeaveDiscardBtn" style="border:0;">取消保存</button>
              <button type="button" id="blacklistLeaveSaveBtn">保存配置</button>
            </div>
          </div>
        </div>
      </div>
      <h3 class="section-title" style="font-size:16px;margin-top:10px;">当前配置</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>类型</th><th>内容</th><th>创建时间</th><th>更新时间</th><th>操作</th></tr></thead>
        <tbody>
          {{range .BlacklistItems}}
          <tr>
            <td>{{.TypeLabel}}</td><td>{{.Value}}</td><td>{{.CreatedAt}}</td><td>{{.UpdatedAt}}</td>
            <td>
              <form method="POST" action="/settings?tab=blacklist&page={{$.Page}}&page_size={{$.PageSize}}&q={{$.Keyword}}&type={{$.BlacklistTypeFilter}}&date_from={{$.BlacklistDateFrom}}&date_to={{$.BlacklistDateTo}}" style="display:inline-flex;gap:6px;">
                <input type="hidden" name="action" value="update_blacklist">
                <input type="hidden" name="old_type" value="{{.Type}}">
                <input type="hidden" name="old_value" value="{{.Value}}">
                <select name="item_type"><option value="domain" {{if eq .Type "domain"}}selected{{end}}>域名</option><option value="ipv4" {{if eq .Type "ipv4"}}selected{{end}}>IPv4</option><option value="ipv6" {{if eq .Type "ipv6"}}selected{{end}}>IPv6</option></select>
                <input name="item" value="{{.Value}}" style="min-width:220px;">
                <button type="submit">修改</button>
              </form>
              <form method="POST" action="/settings?tab=blacklist&page={{$.Page}}&page_size={{$.PageSize}}&q={{$.Keyword}}&type={{$.BlacklistTypeFilter}}&date_from={{$.BlacklistDateFrom}}&date_to={{$.BlacklistDateTo}}" style="display:inline;">
                <input type="hidden" name="action" value="remove_blacklist">
                <input type="hidden" name="item_type" value="{{.Type}}">
                <input type="hidden" name="item" value="{{.Value}}">
                <button class="danger" type="submit">删除</button>
              </form>
            </td>
          </tr>
          {{else}}<tr><td colspan="5" class="muted">当前无黑名单配置</td></tr>{{end}}
        </tbody>
      </table></div>
      {{if .BlacklistDraftDirty}}
      <h3 class="section-title" style="font-size:16px;margin-top:10px;">变更内容</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>操作</th><th>原类型</th><th>原内容</th><th>新类型</th><th>新内容</th><th>更新时间</th></tr></thead>
        <tbody>
          {{range .BlacklistChanges}}
          <tr>
            <td>{{.ActionLabel}}</td>
            <td>{{if .OldValue}}{{.OldTypeLabel}}{{else}}-{{end}}</td>
            <td>{{if .OldValue}}{{.OldValue}}{{else}}-{{end}}</td>
            <td>{{if .NewValue}}{{.NewTypeLabel}}{{else}}-{{end}}</td>
            <td>{{if .NewValue}}{{.NewValue}}{{else}}-{{end}}</td>
            <td>{{.UpdatedAt}}</td>
          </tr>
          {{else}}<tr><td colspan="6" class="muted">当前无待生效变更</td></tr>{{end}}
        </tbody>
      </table></div>
      {{end}}
      <div class="pager">{{range .Pages}}{{if eq . $.Page}}<span class="active">{{.}}</span>{{else}}<a href="/settings?tab=blacklist&page={{.}}&page_size={{$.PageSize}}&q={{$.Keyword}}&type={{$.BlacklistTypeFilter}}&date_from={{$.BlacklistDateFrom}}&date_to={{$.BlacklistDateTo}}">{{.}}</a>{{end}}{{end}}</div>
    {{end}}

    {{if eq .Tab "llm"}}
      <div class="llm-config-card">
        <div class="llm-config-head">
          <div>
            <div class="llm-config-title">大模型配置</div>
            <p class="llm-config-copy">保存前会发起一次测试请求。链接地址需使用公开 HTTPS 地址；输入 base URL 时系统会自动补全 OpenAI Compatible 的 /chat/completions 或 Anthropic Messages 的 /messages。</p>
          </div>
        </div>
        <div id="llmAdminMsg" class="msg" style="display:none; margin: 16px 22px 0;"></div>
        <form id="llmProviderForm" class="llm-provider-form">
          <label>协议模式
            <select name="protocol" required>
              <option value="openai">OpenAI Compatible</option>
              <option value="anthropic">Anthropic Messages</option>
            </select>
          </label>
          <label>模型名称
            <input name="name" placeholder="例如 DeepSeek" required>
          </label>
          <label>链接地址
            <input name="base_url" placeholder="https://api.example.com/v1" required>
          </label>
          <label>模型标识
            <input name="model" placeholder="例如 deepseek-v4-pro" required>
          </label>
          <label class="span-2">系统 API Key
            <input name="api_key" type="password" placeholder="用于未配置个人 Key 的用户" required>
          </label>
          <div class="llm-provider-actions"><button type="submit" id="llmProviderSaveBtn">测试并保存</button></div>
        </form>
      </div>
      <div class="table-wrap"><table class="llm-provider-table">
        <thead><tr><th>名称</th><th>Provider ID</th><th>协议</th><th>模型</th><th>地址</th><th>状态</th><th>Key</th><th>操作</th></tr></thead>
        <tbody>
          {{range .LLMProviders}}
          <tr>
            <td>{{.Name}}</td>
            <td>{{.ID}}</td>
            <td>{{.Protocol}}</td>
            <td>{{.Model}}</td>
            <td>{{.BaseURL}}</td>
            <td>{{if .Enabled}}<span class="status-pill enabled">启用</span>{{else}}<span class="status-pill disabled">停用</span>{{end}}</td>
            <td>{{if .APIKey}}{{.APIKey}}{{else}}未配置{{end}}</td>
            <td><button type="button" class="llm-toggle-btn" data-id="{{.ID}}" data-enabled="{{if .Enabled}}false{{else}}true{{end}}">{{if .Enabled}}停用{{else}}启用{{end}}</button></td>
          </tr>
          {{else}}<tr><td colspan="8" class="muted">当前无大模型配置</td></tr>{{end}}
        </tbody>
      </table></div>
    {{end}}
  </main>
</div>

<script>
{{template "bindDropdownMenuScript"}}
bindDropdownMenu('settingsAdminUserMenuButton', 'userDropdown');

(function() {
  var form = document.getElementById('llmProviderForm');
  var msg = document.getElementById('llmAdminMsg');
  function showLLMAdminMsg(text, ok) {
    if (!msg) return;
    msg.textContent = text;
    msg.className = 'msg ' + (ok ? 'success' : 'error');
    msg.style.display = 'block';
  }
  if (form) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var btn = document.getElementById('llmProviderSaveBtn');
      btn.disabled = true;
      btn.textContent = '测试中...';
      var payload = {
        protocol: form.elements.protocol.value,
        name: form.elements.name.value.trim(),
        base_url: form.elements.base_url.value.trim(),
        model: form.elements.model.value.trim(),
        api_key: form.elements.api_key.value.trim(),
        enabled: true
      };
      fetch('/api/admin/llm/providers', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)})
        .then(function(res) { return res.json().then(function(data) { if (!res.ok) throw new Error(data.error || '保存失败'); return data; }); })
        .then(function() { showLLMAdminMsg('测试通过，配置已保存。', true); setTimeout(function() { window.location.reload(); }, 800); })
        .catch(function(err) { showLLMAdminMsg(err.message, false); btn.disabled = false; btn.textContent = '测试并保存'; });
    });
  }
  document.querySelectorAll('.llm-toggle-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      fetch('/api/admin/llm/providers', {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id: btn.getAttribute('data-id'), enabled: btn.getAttribute('data-enabled') === 'true'})})
        .then(function(res) { if (!res.ok) throw new Error('更新失败'); return res.json(); })
        .then(function() { window.location.reload(); })
        .catch(function(err) { showLLMAdminMsg(err.message, false); });
    });
  });
})();

(function() {
  var dirty = {{if .BlacklistDraftDirty}}true{{else}}false{{end}};
  var suppressBeforeUnload = false;
  var pendingLeaveHref = '';
  var addForm = document.getElementById('blacklistAddForm');
  var leaveDialog = document.getElementById('blacklistLeaveDialog');
  var leaveCloseBtn = document.getElementById('blacklistLeaveCloseBtn');
  var leaveSaveBtn = document.getElementById('blacklistLeaveSaveBtn');
  var leaveDiscardBtn = document.getElementById('blacklistLeaveDiscardBtn');
  var typeField = document.getElementById('blacklistItemType');
  var valueField = document.getElementById('blacklistItemValue');

  function placeholderForType(kind) {
    if (kind === 'ipv4') return 'IPv4/CIDR（支持批量换行）\n192.168.1.10\n172.16.0.0/16';
    if (kind === 'ipv6') return 'IPv6/CIDR（支持批量换行）\n2001:db8::1\n2001:db8::/32';
    return '域名（支持批量换行）\nexample.com\napi.example.com';
  }

  function isBlacklistPageURL(href) {
    try {
      var url = new URL(href, window.location.origin);
      return url.pathname === '/settings' && url.searchParams.get('tab') === 'blacklist';
    } catch (err) {
      return false;
    }
  }

  if (typeField && valueField) {
    var syncPlaceholder = function() {
      valueField.placeholder = placeholderForType(typeField.value);
    };
    syncPlaceholder();
    typeField.addEventListener('change', syncPlaceholder);
  }

  function submitHiddenAction(actionName, href) {
    suppressBeforeUnload = true;
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/settings?tab=blacklist';
    form.style.display = 'none';
    var action = document.createElement('input');
    action.type = 'hidden';
    action.name = 'action';
    action.value = actionName;
    var redirect = document.createElement('input');
    redirect.type = 'hidden';
    redirect.name = 'redirect_to';
    redirect.value = href;
    form.appendChild(action);
    form.appendChild(redirect);
    document.body.appendChild(form);
    form.submit();
  }

  function closeLeaveDialog() {
    pendingLeaveHref = '';
    if (leaveDialog) leaveDialog.style.display = 'none';
  }

  if (leaveSaveBtn && leaveDiscardBtn) {
    leaveSaveBtn.addEventListener('click', function() {
      if (!pendingLeaveHref) return;
      submitHiddenAction('save_blacklist', pendingLeaveHref);
    });
    leaveDiscardBtn.addEventListener('click', function() {
      if (!pendingLeaveHref) return;
      submitHiddenAction('discard_blacklist', pendingLeaveHref);
    });
  }
  if (leaveCloseBtn) {
    leaveCloseBtn.addEventListener('click', closeLeaveDialog);
  }
  if (leaveDialog) {
    leaveDialog.addEventListener('click', function(e) {
      if (e.target === leaveDialog) closeLeaveDialog();
    });
  }

  if (!dirty) return;
  window.addEventListener('beforeunload', function(e) {
    if (suppressBeforeUnload) return;
    e.preventDefault();
    e.returnValue = '黑名单规则未保存，不保存离开将丢失本次修改。';
  });

  document.querySelectorAll('form[action*="/settings?tab=blacklist"]').forEach(function(form) {
    form.addEventListener('submit', function() {
      suppressBeforeUnload = true;
    });
  });

  document.addEventListener('click', function(e) {
    var anchor = e.target.closest('a');
    if (!anchor) return;
    var href = anchor.getAttribute('href') || '';
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
    if (anchor.hasAttribute('download') || anchor.target === '_blank') return;
    if (isBlacklistPageURL(anchor.href)) {
      suppressBeforeUnload = true;
      return;
    }
    e.preventDefault();
    pendingLeaveHref = href;
    if (leaveDialog) leaveDialog.style.display = 'flex';
  }, true);
})();
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
        .warn-detail { max-width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        pre.json-block { margin-top: 10px; background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 12px; overflow: auto; font-size: 12px; line-height: 1.5; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .tag.warn-error { background: #fef3f2; color: #b42318; }
        .tag.warn-warning { background: #fffaeb; color: #b54708; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
        .action { display: inline-block; padding: 8px 14px; background: #0f766e; color: white; text-decoration: none; border-radius: 8px; white-space: nowrap; }
        .action.secondary { background: #eef2ff; color: #4338ca; }
        .empty { text-align: center; color: #667085; padding: 56px 24px; }
    </style>
</head>
<body>
    {{template "appHeader" (dict "Title" "准入技能库" "Active" "admission" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "admissionListUserMenuButton" "MenuID" "admissionListUserDropdown")}}
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
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-btn .arrow { font-size: 10px; }
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
        .warning { background: #fffaeb; color: #b54708; border: 1px solid #fecd89; padding: 12px 14px; border-radius: 10px; margin-bottom: 16px; }
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
    {{template "appHeader" (dict "Title" "录入准入库" "Active" "reports" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "admissionImportUserMenuButton" "MenuID" "admissionImportUserDropdown")}}
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
    {{template "appHeader" (dict "Title" "组合风险分析" "Active" "combination" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "combinationUserMenuButton" "MenuID" "combinationUserDropdown")}}
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
            {{if .SourceReport}}
            <div class="meta" style="margin-bottom:12px;">来源报告 {{.SourceReport.ReportID}}{{if .SourceReport.FileName}} · 文件 {{.SourceReport.FileName}}{{end}}{{if .SourceReport.TaskID}} · 任务 {{.SourceReport.TaskID}}{{end}}{{if .SourceReport.RequestID}} · 请求 {{.SourceReport.RequestID}}{{end}}</div>
            {{if .SourceReport.DecisionHint}}<div class="meta" style="margin-bottom:12px;">来源报告闭环摘要：{{.SourceReport.DecisionHint}}</div>{{end}}
            <div class="top-link" style="margin-bottom:12px;"><a href="{{.SourceReport.ReportURL}}">查看来源报告</a> · <a href="{{.SourceReport.DownloadURL}}">下载来源 JSON</a></div>
            {{end}}
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
                <div class="summary-box">
                    <strong>TI目标数</strong>
                    {{.Conclusion.TITargetCount}}
                </div>
                <div class="summary-box">
                    <strong>TI高威胁</strong>
                    {{.Conclusion.TIThreatCount}}
                </div>
                <div class="summary-box">
                    <strong>TI可疑目标</strong>
                    {{.Conclusion.TISuspiciousCount}}
                </div>
                <div class="summary-box">
                    <strong>TI调整分</strong>
                    {{printf "%.2f" .Conclusion.TIAdjustmentScore}}
                </div>
            </div>
            {{if .RunID}}
            <div class="meta" style="margin-bottom:12px;">快照 ID {{.RunID}}{{if .SavedAt}} · 更新时间 {{.SavedAt}}{{end}}</div>
            {{end}}
            {{if .HistoryURL}}<div class="top-link"><a href="{{.HistoryURL}}">查看历史快照</a></div>{{end}}
            {{if .Conclusion.ClosureNarrative}}<div class="meta" style="margin-top:12px;">组合闭环摘要：{{.Conclusion.ClosureNarrative}}</div>{{end}}
            <div class="recommendation">{{.Conclusion.Recommendation}}</div>
            {{if .Conclusion.RuleConfigWarning}}
            <div class="meta" style="margin-top:10px;{{if eq .Conclusion.RuleConfigWarnLevel "error"}}color:#b42318;{{else}}color:#b54708;{{end}}">规则配置告警：{{.Conclusion.RuleConfigWarning}}</div>
            {{end}}
            {{if .SelectedSkills}}
            <div class="meta" style="margin-top:14px;">以下列表展示当前纳入组合分析的技能资产。</div>
            {{end}}
            {{if .SelectedSkills}}
            <div class="list">
                {{range .SelectedSkills}}
                <div class="list-item">
                    <strong>{{.DisplayName}}</strong>
                    <div class="meta">{{.SkillID}} · {{.AdmissionStatus}} · {{.ReviewDecision}}</div>
                    {{if .DecisionHint}}<div class="meta">闭环摘要：{{.DecisionHint}}</div>{{end}}
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
        {{template "dropdownBaseCSS"}}
        .container { max-width: 1100px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 24px; }
        .title { font-size: 24px; color: #111827; margin-bottom: 14px; }
        .filters { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr 1fr 1fr auto; gap: 12px; margin-bottom: 18px; }
        .filters input, .filters select { width: 100%; padding: 10px 12px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 14px; }
        .filters .actions { display: flex; gap: 10px; }
        .filters button, .filters a { display: inline-block; padding: 10px 14px; border-radius: 8px; border: none; text-decoration: none; font-size: 14px; cursor: pointer; }
        .filters button { background: #0f766e; color: white; }
        .filters a { background: #eef2ff; color: #4338ca; }
        .share-btn { background: #ecfdf3; color: #027a48; }
        .share-url { margin-top: 10px; color: #475467; font-size: 12px; word-break: break-all; }
        .share-url code { background: #f2f4f7; border-radius: 6px; padding: 2px 6px; }
        .list { display: grid; gap: 12px; }
        .item { border: 1px solid #eaecf0; border-radius: 10px; padding: 14px; }
        .item a { color: #111827; text-decoration: none; font-weight: 600; }
        .meta { color: #667085; font-size: 13px; margin-top: 6px; }
        .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
        .tag { background: #eef2ff; color: #4338ca; padding: 4px 8px; border-radius: 999px; font-size: 12px; }
        .links { display: flex; gap: 12px; margin-top: 10px; }
        .links a { color: #4338ca; text-decoration: none; font-size: 14px; }
        .coverage-box { margin: 12px 0 16px; padding: 12px; border: 1px solid #e4e7ec; border-radius: 10px; background: #f8fafc; }
    </style>
</head>
<body>
    {{template "appHeader" (dict "Title" "组合快照历史" "Active" "combination" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "combinationRunsUserMenuButton" "MenuID" "userDropdown")}}
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
                <select name="ti_risk">
                    <option value="" {{if eq .TIRisk ""}}selected{{end}}>全部TI信号</option>
                    <option value="high" {{if eq .TIRisk "high"}}selected{{end}}>TI高威胁</option>
                    <option value="suspicious" {{if eq .TIRisk "suspicious"}}selected{{end}}>TI可疑</option>
                    <option value="clean" {{if eq .TIRisk "clean"}}selected{{end}}>TI无异常</option>
                </select>
                <select name="rule_warn_level">
                    <option value="" {{if eq .RuleWarnLevel ""}}selected{{end}}>全部规则告警</option>
                    <option value="warning" {{if eq .RuleWarnLevel "warning"}}selected{{end}}>规则告警 Warning</option>
                    <option value="error" {{if eq .RuleWarnLevel "error"}}selected{{end}}>规则告警 Error</option>
                    <option value="none" {{if eq .RuleWarnLevel "none"}}selected{{end}}>无规则告警</option>
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
                    <button type="button" id="share-link-btn" class="share-btn">复制筛选链接</button>
                </div>
            </form>
            <div class="share-url">当前筛选链接：<code id="share-link-value">/combination/runs</code></div>
            <div class="coverage-box">
                <div class="meta"><strong>规则覆盖率统计</strong></div>
                {{if .RuleCoverageTop}}
                <div class="meta">高命中规则 Top{{len .RuleCoverageTop}}：</div>
                <div class="list">
                    {{range .RuleCoverageTop}}
                    <div class="meta">{{.RuleID}} · 命中 {{.Count}} 次 · 覆盖率 {{.Coverage}}</div>
                    {{end}}
                </div>
                {{else}}
                <div class="meta">当前暂无规则命中数据。</div>
                {{end}}
                <div class="meta" style="margin-top:8px;">死规则（从未命中）数量：{{.DeadRulesCount}}{{if .DeadRulesPreview}}，示例：{{range $index, $item := .DeadRulesPreview}}{{if $index}}、{{end}}{{$item}}{{end}}{{end}}</div>
            </div>
            {{if .Items}}
            <div class="list">
                {{range .Items}}
                <div class="item">
                    <a href="{{.DetailURL}}">{{.RunID}}</a>
                    <div class="meta">风险结论 {{.RiskLabel}} · 已选技能 {{.SelectedSkillCount}} · 更新时间 {{.UpdatedAt}}</div>
                    <div class="meta">TI高威胁 {{.TIThreatCount}} · TI可疑 {{.TISuspiciousCount}}</div>
                    {{if .RuleCoverageHint}}<div class="meta">命中规则：{{.RuleCoverageHint}}</div>{{end}}
                    <div class="links">{{if .OverviewURL}}<a href="{{.OverviewURL}}">重新载入该组合</a>{{end}}</div>
                    {{if .RuleConfigWarning}}
                    <div class="tags">
                        <span class="tag warn-{{.RuleConfigWarnLevel}}">规则告警 {{.RuleConfigWarnLevel}}</span>
                    </div>
                    <div class="meta warn-detail" title="{{.RuleConfigWarning}}">告警详情：{{.RuleConfigWarning}}</div>
                    {{end}}
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
    <script>
        {{template "bindDropdownMenuScript"}}
        bindDropdownMenu('combinationRunsUserMenuButton', 'userDropdown');
        (function() {
            var shareBtn = document.getElementById('share-link-btn');
            var shareValue = document.getElementById('share-link-value');
            if (!shareBtn) {
                return;
            }
            var defaultText = shareBtn.textContent;
            var relativeURL = window.location.pathname + window.location.search;
            if (shareValue) {
                shareValue.textContent = relativeURL || '/combination/runs';
            }
            function markCopied() {
                shareBtn.textContent = '已复制';
                setTimeout(function() {
                    shareBtn.textContent = defaultText;
                }, 1200);
            }
            shareBtn.addEventListener('click', function() {
                var shareURL = window.location.origin + (relativeURL || '/combination/runs');
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(shareURL).then(markCopied).catch(function() {
                        window.prompt('复制筛选链接：', shareURL);
                    });
                    return;
                }
                window.prompt('复制筛选链接：', shareURL);
            });
        })();
    </script>
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
        {{template "dropdownBaseCSS"}}
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
    {{template "appHeader" (dict "Title" "组合快照详情" "Active" "combination" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "combinationRunUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        <div class="card">
            <div class="meta" style="margin-bottom:10px;"><a href="{{.HistoryURL}}" style="color:#4338ca;text-decoration:none;">返回组合快照历史</a></div>
            <div class="title">组合快照详情</div>
            <div class="meta">快照 ID {{.RunID}}</div>
            <div class="meta">创建时间 {{.SavedAt}} · 更新时间 {{.UpdatedAt}}</div>
            <div class="meta">风险结论 {{.RiskLabel}}</div>
            {{if .ClosureNarrative}}<div class="meta">闭环摘要 {{.ClosureNarrative}}</div>{{end}}
            {{if .Recommendation}}<div class="meta">处置建议 {{.Recommendation}}</div>{{end}}
            {{if .RuleConfigWarning}}<div class="meta" style="{{if eq .RuleConfigWarnLevel "error"}}color:#b42318;{{else}}color:#b54708;{{end}}">规则配置告警 {{.RuleConfigWarning}}</div>{{end}}
            <div class="meta">TI摘要 目标 {{.TITargetCount}} · 高威胁 {{.TIThreatCount}} · 可疑 {{.TISuspiciousCount}} · 调整分 {{printf "%.2f" .TIAdjustmentScore}}</div>
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
        <div class="card">
            <div class="title">诊断数据</div>
            <details>
                <summary class="meta">展开 diagnostics JSON</summary>
                <pre class="json-block">{{.DiagnosticsJSON}}</pre>
            </details>
        </div>
    </div>
    <script>
        {{template "bindDropdownMenuScript"}}
        bindDropdownMenu('combinationRunUserMenuButton', 'userDropdown');
    </script>
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
        {{template "dropdownBaseCSS"}}
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
    {{template "appHeader" (dict "Title" "编辑准入信息" "Active" "admission" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "admissionEditUserMenuButton" "MenuID" "userDropdown")}}
    <div class="container">
        <div class="card">
            <div class="title">编辑准入技能</div>
            <div class="meta">技能 ID: {{.SkillID}} | 原文件: {{.FileName}}</div>
            <div class="meta">修复验证状态: {{.WorkflowStageLabel}}{{if .VerificationRequired}}（存在待验证修复）{{end}}</div>
            <div class="meta">最近修复时间: {{if .LastFixAt}}{{.LastFixAt}}{{else}}-{{end}} | 最近验证时间: {{if .LastVerifiedAt}}{{.LastVerifiedAt}}{{else}}-{{end}}</div>
            {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
            {{if .EnforceVerifyWarning}}<div class="warning">{{.EnforceVerifyWarning}}</div>{{end}}
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
                <div class="form-group">
                    <label for="workflow_action">修复验证动作</label>
                    <select id="workflow_action" name="workflow_action">
                        <option value="">不变更流程状态</option>
                        <option value="mark_fixed">标记“已修复，待验证”</option>
                        <option value="mark_verified">标记“完成复测验证”</option>
                    </select>
                </div>
                <div class="actions">
                    <button type="submit" class="primary-btn">保存修改</button>
                    <a href="/admission/skills/{{.SkillID}}" class="secondary-btn">返回详情</a>
                </div>
            </form>
        </div>
    </div>
    <script>
        {{template "bindDropdownMenuScript"}}
        bindDropdownMenu('admissionEditUserMenuButton', 'userDropdown');
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
        {{template "dropdownBaseCSS"}}
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
    {{template "appHeader" (dict "Title" "准入技能详情" "Active" "admission" "Username" .Username "HasPersonal" .HasPersonal "HasUserMgmt" .HasUserMgmt "HasLogPerm" .HasLogPerm "MenuButtonID" "admissionDetailUserMenuButton" "MenuID" "userDropdown")}}
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
            <div class="meta">修复验证状态: {{.WorkflowStageLabel}}{{if .VerificationRequired}}（存在待验证修复）{{end}}</div>
            <div class="meta">最近修复时间: {{if .LastFixAt}}{{.LastFixAt}}{{else}}-{{end}} | 最近验证时间: {{if .LastVerifiedAt}}{{.LastVerifiedAt}}{{else}}-{{end}}</div>
            <div class="meta">自动复测判断: {{.AutoVerifyResult}}</div>
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
            {{if .RiskHistory.HasHistory}}
            <div class="meta" style="margin-bottom:8px;">
                风险趋势: {{.RiskHistory.TrendText}} ｜ 当前风险总数 {{.RiskHistory.LatestTotalRisk}}（高{{.RiskHistory.LatestHigh}} / 中{{.RiskHistory.LatestMed}} / 低{{.RiskHistory.LatestLow}}）
            </div>
            {{end}}
            {{if .ReviewRecords}}
            <div class="list">
                {{range .ReviewRecords}}
                <div class="list-item">
                    <div><strong>{{.Reviewer}}</strong></div>
                    <div class="meta">结论 {{.Decision}} | 时间 {{.CreatedAt}}</div>
                    <div class="meta">风险计数 高{{.HighRisk}} / 中{{.MedRisk}} / 低{{.LowRisk}} ｜ 总计 {{.TotalRisk}} ｜ {{.DeltaText}}</div>
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
        {{template "bindDropdownMenuScript"}}
        bindDropdownMenu('admissionDetailUserMenuButton', 'userDropdown');
    </script>
</body>
</html>
`
