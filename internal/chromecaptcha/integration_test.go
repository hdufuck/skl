//go:build integration

// 真·取参体检：会真实访问阿里云验证码 CDN、真实初始化官方 SDK、并用受信任点击
// 触发一次验证码。演练前先跑它，确认「本机此刻能拿到 captchaVerifyParam」：
//
//	go test -tags integration ./internal/chromecaptcha/ -run Integration -v
//
// 它不登录、不碰 skl 的任何接口，只回答一个问题：真值档的浏览器取参链路是否活着。
// 失败常见的三个原因：CDN 不通、风控把 TRACELESS 降级成需人工交互的形态、
// 自动化指纹命中 F024；逃生舱（--headed + 持久化 profile）见 docs/signin-probe.md 附录 A。
package chromecaptcha

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/hdufuck/skl"
)

func TestIntegrationRealCaptchaParam(t *testing.T) {
	src, err := New(context.Background(), Options{
		ChromePath:     testChromePath(t),
		Headless:       true,
		UserDataDir:    filepath.Join(t.TempDir(), "chrome-profile"),
		StartupTimeout: 60 * time.Second,
		Logf:           t.Logf,
	})
	if err != nil {
		t.Fatalf("预热失败: %v", err)
	}
	defer func() { _ = src.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	param, err := src.Param(ctx)
	if err != nil {
		t.Fatalf("真实取参失败（演练时真值档会拿不到 HTTP 状态）: %v", err)
	}
	t.Logf("captchaVerifyParam len=%d 用时=%s", len(param), time.Since(start).Round(time.Millisecond))

	var env struct {
		SceneID   string `json:"sceneId"`
		CertifyID string `json:"certifyId"`
		DeviceTok string `json:"deviceToken"`
		Data      string `json:"data"`
	}
	if err := json.Unmarshal([]byte(param), &env); err != nil {
		t.Fatalf("参数不是 JSON 文本: %v（首段 %q）", err, head(param, 80))
	}
	if env.SceneID != skl.DefaultCaptchaSceneID {
		t.Fatalf("sceneId = %q, want %q", env.SceneID, skl.DefaultCaptchaSceneID)
	}

	// 参数是一次性的（重放会拿到 F008），所以必须是本次现取的。打印指纹，
	// 多次运行时对比就能看出它没被缓存/复用；参数本体不落盘（见 §4.4 脱敏规则）。
	sum := sha256.Sum256([]byte(param))
	t.Logf("指纹=%x certifyId=%s deviceToken=%d字节 data=%d字节",
		sum[:6], env.CertifyID, len(env.DeviceTok), len(env.Data))
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
