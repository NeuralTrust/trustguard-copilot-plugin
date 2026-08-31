package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironmentConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRUSTGUARD_COPILOT_SYSTEM_CONFIG", filepath.Join(dir, "missing-system.json"))
	t.Setenv("TRUSTGUARD_COPILOT_CONFIG", filepath.Join(dir, "missing-user.json"))
	t.Setenv("TRUSTGUARD_API_KEY", "tgk_env")
	t.Setenv("TRUSTGUARD_DATA_URL", "https://env.example")
	t.Setenv("TRUSTGUARD_FAIL_MODE", "closed")

	cfg := loadConfig()
	if cfg.APIKey != "tgk_env" || cfg.DataURL != "https://env.example" || cfg.FailMode != "closed" {
		t.Fatalf("unexpected env config: %+v", cfg)
	}
}

func TestManagedModeLocksCollectorSettings(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "system.json")
	user := filepath.Join(dir, "user.json")
	if err := os.WriteFile(system, []byte(`{"api_key":"tgk_managed","data_url":"https://managed.example","fail_mode":"closed","transform_action":"deny","events":{"preToolUse":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte(`{"api_key":"tgk_user","data_url":"https://user.example","fail_mode":"open","transform_action":"allow","events":{"preToolUse":false},"timeout_ms":1234}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTGUARD_COPILOT_SYSTEM_CONFIG", system)
	t.Setenv("TRUSTGUARD_COPILOT_CONFIG", user)
	t.Setenv("TRUSTGUARD_API_KEY", "tgk_env")
	t.Setenv("TRUSTGUARD_TRANSFORM_ACTION", "allow")

	cfg := loadConfig()
	if cfg.APIKey != "tgk_managed" || cfg.DataURL != "https://managed.example" || cfg.FailMode != "closed" {
		t.Fatalf("managed fields were overridden: %+v", cfg)
	}
	if cfg.TimeoutMS != 1234 {
		t.Fatalf("soft preference should overlay managed config: %+v", cfg)
	}
	if cfg.TransformAction != "deny" || !cfg.eventEnabled("PreToolUse") {
		t.Fatalf("managed enforcement preferences were weakened: %+v", cfg)
	}
}
