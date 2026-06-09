package handler

import "skill-scanner/internal/plugins"

func batchFinding(pluginName, ruleID, severity, title, description, location, snippet string) plugins.Finding {
	return plugins.Finding{
		PluginName:  pluginName,
		RuleID:      ruleID,
		Severity:    severity,
		Title:       title,
		Description: description,
		Location:    location,
		CodeSnippet: snippet,
	}
}
