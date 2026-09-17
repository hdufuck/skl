//go:build integration

// 端到端演练：**真浏览器取参 + 假服务端**，验收标准就是演练里那一格
// 「真值档拿到 HTTP 状态」——它不再是 `-` / `transport_error`。
//
//	go test -tags integration ./internal/probe/ -run Integration -v
//
// 需要本机能跑 Chrome、且能访问阿里云验证码 CDN。不登录、不碰 skl 的任何真接口，
// 所以随时可跑。它同时回答两个问题：真值档会不会退回 transport_error（取参链路），
// 以及库的 SignIn 封装路径能不能把参数送出去。
package probe

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hdufuck/skl/internal/chromecaptcha"
)

func TestIntegrationGenuineRungReachesServer(t *testing.T) {
	var sent []string
	backend := &fakeBackend{
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(param, _ string) (int, string, bool) {
			if param != "" {
				sent = append(sent, param)
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	src, err := chromecaptcha.New(context.Background(), chromecaptcha.Options{
		Headless:       true,
		UserDataDir:    filepath.Join(t.TempDir(), "chrome-profile"),
		StartupTimeout: 90 * time.Second,
		Logf:           t.Logf,
	})
	if err != nil {
		t.Fatalf("浏览器预热失败（真值档需要 Chrome + 阿里云 CDN）: %v", err)
	}
	defer func() { _ = src.Close() }()

	cfg := baseConfig(client, rec)
	cfg.Code = "0000"
	cfg.Captcha = src

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var genuine *Entry
	for i := range rep.Entries {
		if rep.Entries[i].Rung == RungCaptchaGenuine {
			genuine = &rep.Entries[i]
		}
	}
	if genuine == nil {
		t.Fatal("报告里没有真值档记录")
	}
	if genuine.Status != 401 {
		t.Fatalf("真值档应拿到 401 签到码不存在：status=%d body=%s err=%s",
			genuine.Status, genuine.Body, genuine.Err)
	}
	if !strings.Contains(genuine.Body, "签到码") {
		t.Fatalf("真值档响应体应含「签到码」：%s", genuine.Body)
	}
	if rep.GenuineUnproven() {
		t.Fatal("拿到了 HTTP 状态，就不应再报「真值档未验证」")
	}

	// 伪造档与真值档各带一个非空参数：两个都结构合法，但必须来自不同来源
	// （真值那个由浏览器现取，见 internal/chromecaptcha 的 integration 用例）。
	if len(sent) != 2 {
		t.Fatalf("应收到 2 个 captchaVerifyParam（伪造 + 真值），实际 %d 个", len(sent))
	}
	if sent[0] == sent[1] {
		t.Fatalf("真值参数与伪造参数相同（%d 字节），说明真值档没走浏览器", len(sent[1]))
	}
	var env struct {
		SceneID   string `json:"sceneId"`
		CertifyID string `json:"certifyId"`
	}
	if err := json.Unmarshal([]byte(sent[1]), &env); err != nil {
		t.Fatalf("真值参数不是 JSON 文本: %v", err)
	}
	if env.SceneID == "" || env.CertifyID == "" {
		t.Fatalf("真值参数缺少 sceneId/certifyId: sceneId=%q certifyId=%q", env.SceneID, env.CertifyID)
	}
	t.Logf("真值档：HTTP %d，参数 %d 字节，certifyId=%s", genuine.Status, len(sent[1]), env.CertifyID)
}
