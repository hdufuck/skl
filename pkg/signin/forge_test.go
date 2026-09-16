package signin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hdufuck/skl"
)

func TestForgeCaptchaParamUsesSampleLengths(t *testing.T) {
	t.Parallel()

	sample := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2FiMDM0","data":"JRMlgg1EZm9v"}`

	got := ForgeCaptchaParam(sample)

	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("伪造值不是合法 JSON: %v (%s)", err, got)
	}
	if parsed.SceneID != "2q42bw25" {
		t.Fatalf("sceneId = %q, want 2q42bw25", parsed.SceneID)
	}
	if len(parsed.CertifyID) != 10 || len(parsed.DeviceToken) != 12 || len(parsed.Data) != 12 {
		t.Fatalf("字段长度未沿用样本: %+v", parsed)
	}
	if strings.Trim(parsed.CertifyID+parsed.DeviceToken+parsed.Data, "A") != "" {
		t.Fatalf("伪造内容应为等长占位符: %+v", parsed)
	}
}

func TestForgeCaptchaParamWithoutSampleUsesDefaults(t *testing.T) {
	t.Parallel()

	got := ForgeCaptchaParam("")

	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("伪造值不是合法 JSON: %v", err)
	}
	if parsed.SceneID != skl.DefaultCaptchaSceneID {
		t.Fatalf("sceneId = %q, want %q", parsed.SceneID, skl.DefaultCaptchaSceneID)
	}
	if len(parsed.CertifyID) != ForgeDefaults.CertifyIDLen {
		t.Fatalf("certifyId 长度 = %d, want %d", len(parsed.CertifyID), ForgeDefaults.CertifyIDLen)
	}
	if len(parsed.DeviceToken) != ForgeDefaults.DeviceTokenLen {
		t.Fatalf("deviceToken 长度 = %d, want %d", len(parsed.DeviceToken), ForgeDefaults.DeviceTokenLen)
	}
	if len(parsed.Data) != ForgeDefaults.DataLen {
		t.Fatalf("data 长度 = %d, want %d", len(parsed.Data), ForgeDefaults.DataLen)
	}
}
