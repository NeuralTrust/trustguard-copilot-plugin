package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestToolResponseBlocks(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"plain string", `"hello"`, []string{"hello"}},
		{"stringified mcp array", `"[{\"type\":\"text\",\"text\":\"echo: hello probe\"}]"`, []string{"echo: hello probe"}},
		{"stringified content object", `"{\"content\":[{\"type\":\"text\",\"text\":\"foo\"},{\"type\":\"text\",\"text\":\"bar\"}]}"`, []string{"foo", "bar"}},
		{"stringified other object keeps the original string", `"{\"query\":\"q\"}"`, []string{`{"query":"q"}`}},
		{"stringified invalid JSON", `"{\"a\":"`, []string{`{"a":`}},
		{"mcp array", `[{"type":"text","text":"a","annotations":{}},{"type":"text","text":"b"}]`, []string{"a", "b"}},
		{"content object", `{"content":[{"type":"text","text":"foo"},{"type":"text","text":"bar"}],"isError":false}`, []string{"foo", "bar"}},
		{"mixed text and image skips image", `[{"type":"text","text":"a"},{"type":"image","data":"AAAA"},{"type":"text","text":"b"}]`, []string{"a", "b"}},
		{"only images falls back compact", `[{"type":"image", "data":"AAAA"}]`, []string{`[{"type":"image","data":"AAAA"}]`}},
		{"other object falls back compact", "{\n  \"matches\": [\"a\"]\n}", []string{`{"matches":["a"]}`}},
		{"array without block types", `[1,2]`, []string{`[1,2]`}},
		{"invalid JSON kept as is", `{"a":`, []string{`{"a":`}},
		{"empty", ``, nil},
		{"blank", `   `, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toolResponseBlocks(json.RawMessage(tt.raw))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("toolResponseBlocks(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestToolResultBlocksNative(t *testing.T) {
	got := toolResultBlocks(hookInput{ToolResult: json.RawMessage(`{"resultType":"success","textResultForLlm":"[{\"type\":\"text\",\"text\":\"kept whole\"}]"}`)})
	want := []string{`[{"type":"text","text":"kept whole"}]`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native result = %q, want %q", got, want)
	}
}

func TestClipIsUTF8Safe(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"fits", "abc", 3, "abc"},
		{"cut inside rune backs off", "aéb", 2, "a"},
		{"cut on rune boundary", "aéb", 3, "aé"},
		{"four byte rune", "😀😀", 5, "😀"},
		{"zero", "abc", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clip(tt.in, tt.n); got != tt.want {
				t.Fatalf("clip(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}

func TestPostToolUsePayloadBlocks(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		maxBytes int
		want     []string
		skipped  bool
	}{
		{"vscode string result is one block", map[string]any{"tool_response": "package main"}, 0, []string{"package main"}, false},
		{"vscode stringified mcp result", map[string]any{"tool_response": `[{"type":"text","text":"foo"},{"type":"text","text":"bar"}]`}, 0, []string{"foo", "bar"}, false},
		{"object response", map[string]any{"tool_response": map[string]any{"content": []any{map[string]any{"type": "text", "text": "x"}, map[string]any{"type": "text", "text": "y"}}}}, 0, []string{"x", "y"}, false},
		{"native result is one block", map[string]any{"tool_result": map[string]any{"textResultForLlm": "native text"}}, 0, []string{"native text"}, false},
		{"budget spans blocks and truncates the last", map[string]any{"tool_response": `[{"type":"text","text":"aaaa"},{"type":"text","text":"bbbb"},{"type":"text","text":"cccc"}]`}, 6, []string{"aaaa", "bb"}, false},
		{"budget exhausted drops later blocks", map[string]any{"tool_response": `[{"type":"text","text":"aaaa"},{"type":"text","text":"bbbb"}]`}, 4, []string{"aaaa"}, false},
		{"clip does not split a rune", map[string]any{"tool_response": `[{"type":"text","text":"ééé"}]`}, 3, []string{"é"}, false},
		{"blank blocks skip the evaluate", map[string]any{"tool_response": `[{"type":"text","text":"  "},{"type":"text","text":""}]`}, 0, nil, true},
		{"empty string skips the evaluate", map[string]any{"tool_response": ""}, 0, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, captured := stubGuard(t, EvaluateResponse{Status: "allow"})
			cfg := testConfig(srv.URL)
			if tt.maxBytes > 0 {
				cfg.MaxContentBytes = tt.maxBytes
			}
			input := map[string]any{"hook_event_name": "PostToolUse", "tool_name": "mcp__echo__echo", "session_id": "thr_1"}
			for k, v := range tt.input {
				input[k] = v
			}
			invokeHook(t, cfg, input)
			if tt.skipped {
				if len(*captured) != 0 {
					t.Fatalf("expected no evaluate, got %v", *captured)
				}
				return
			}
			if (*captured)["direction"] != "output" || (*captured)["protocol"] != "mcp" {
				t.Fatalf("unexpected envelope: %v", *captured)
			}
			content := (*captured)["payload"].(map[string]any)["result"].(map[string]any)["content"].([]any)
			got := make([]string, 0, len(content))
			for _, c := range content {
				block := c.(map[string]any)
				if block["type"] != "text" {
					t.Fatalf("expected text block, got %v", block)
				}
				got = append(got, block["text"].(string))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("blocks = %q, want %q", got, tt.want)
			}
			if total := len(strings.Join(got, "")); tt.maxBytes > 0 && total > tt.maxBytes {
				t.Fatalf("sent %d bytes, budget %d", total, tt.maxBytes)
			}
		})
	}
}

func TestShellToolsSentAsToolsCall(t *testing.T) {
	for _, name := range []string{"Bash", "bash", "powershell", "Shell", "shell"} {
		t.Run(name, func(t *testing.T) {
			srv, captured := stubGuard(t, EvaluateResponse{Status: "allow"})
			invokeHook(t, testConfig(srv.URL), map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       name,
				"tool_input":      `{"command":"rm -rf /"}`,
				"session_id":      "thr_1",
			})
			assertShellToolsCall(t, *captured, name)
		})
	}
}
