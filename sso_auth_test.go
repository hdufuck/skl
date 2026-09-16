package skl

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/U1traVeno/hduwebvpn/pkg/sso"
)

// SSOAuthenticator 的签名必须与 hduwebvpn/pkg/sso.Auth 完全对齐 ——
// 一行适配器即可接上，默认实现也是它。
var _ SSOAuthenticator = SSOAuthenticatorFunc(sso.Auth)

// 注入的 SSO 实现必须真的接管登录链：它应收到解析后的 SSO 登录地址与
// 账号密码，并通过 skl 的 client 走完登录链（token 仍从 fragment 提取）。
//
// stub 必须自己驱动 CAS 回调，正如 sso.Auth 那样 —— skl 只负责在
// trace 层记录整条链，不消费 Authenticate 的返回值。
func TestWithSSOAuthenticatorInjectsStub(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)

	var (
		calls   int
		gotURL  string
		gotUser string
		gotPass string
	)
	stub := SSOAuthenticatorFunc(func(ctx context.Context, hc *http.Client, loginURL, username, password string) (string, error) {
		calls++
		gotURL, gotUser, gotPass = loginURL, username, password

		// 模拟 sso.Auth 的最后一步：带着 ticket 走 skl 的 CAS 回调，
		// 让 fragment 里的 session token 被 trace 层捕获。
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			m.server.URL+"/api/cas/login?state=STATE1&ticket=ST-STUB", nil)
		if err != nil {
			return "", err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return "ST-STUB", nil
	})

	c := newMockClient(t, m, WithSSOAuthenticator(stub))
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if calls != 1 {
		t.Fatalf("stub 被调用 %d 次, want 1", calls)
	}
	if !strings.Contains(gotURL, "/sso/login") {
		t.Fatalf("loginURL = %q, want 解析后的 SSO 地址（含 /sso/login）", gotURL)
	}
	if gotUser != "24000000" || gotPass != "secret" {
		t.Fatalf("凭据 = %q/%q, want 24000000/secret", gotUser, gotPass)
	}
	if got := c.Token(); got != m.Token {
		t.Fatalf("Token() = %q, want %q", got, m.Token)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ssoLoginHits != 0 {
		t.Fatalf("SSO 登录页被访问 %d 次, want 0（stub 应替换掉真实实现）", m.ssoLoginHits)
	}
}
