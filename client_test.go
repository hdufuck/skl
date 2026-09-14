package skl

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// mockSkl 是一个模拟 skl 站点的最小实现，覆盖：
// CAS 转发、SSO 登录页、CAS 回调、session token 下发，以及需要鉴权的 API。
//
// 它让登录链这个最高风险的代码路径可以在离线状态下被完整测试。
type mockSkl struct {
	// Token 是登录成功后下发的 session token。
	Token string
	// Business401Body 是业务性质 401 的响应体（不带 url 字段）。
	Business401Body string

	// JsapiTicketBody 为 /api/dingtalk/jsapi_ticket 的响应体。
	// 留空则模拟抓包中观察到的 200 + 空 body。
	JsapiTicketBody string

	// AnalyzeJSONP 为 check-code-analyze 的 JSONP 响应模板（%s 替换为回调名）。
	AnalyzeJSONP string

	// lastAnalyzeQuery / lastCodeCheckInQuery / lastCaptchaVerifyQuery 记录签到类接口
	// 收到的 query，用于断言参数集不变式。
	lastAnalyzeQuery     url.Values
	lastCodeCheckInQuery url.Values
	// lastCaptchaVerifyQuery 记录 ★ 接口 POST /api/ali-nvc/captcha-verify 的 query。
	lastCaptchaVerifyQuery url.Values

	server *httptest.Server

	mu           sync.Mutex
	userinfoHits int
	logins       int
	// issuedTickets 记录 /api/userinfo 与其它请求携带的 skl-ticket。
	tickets []string
	// ssoLoginHits 记录被请求的 SSO 登录次数。
	ssoLoginHits int
}

func newMockSkl(t *testing.T) *mockSkl {
	t.Helper()

	m := &mockSkl{Token: "token-from-fragment"}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/userinfo", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.userinfoHits++
		m.tickets = append(m.tickets, r.Header.Get(HeaderTicket))
		m.mu.Unlock()

		if r.Header.Get(HeaderAuthToken) == m.Token {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"24000000","userName":"测试用户","userType":1}`)
			return
		}

		// 无 token：返回 CAS 登录地址，附带 state。
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w,
			`{"url":"%s/cas/login?state=STATE1&service=%s"}`,
			m.server.URL, url.QueryEscape(m.server.URL+"/api/cas/login?state=STATE1&index=index.html"))
	})

	// cas.hdu.edu.cn 只是个 302 转发壳。
	mux.HandleFunc("/cas/login", func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, r0(), m.server.URL+"/sso/login?service=whatever&state=STATE1", http.StatusFound)
	})

	// 新 SSO 登录页：必须带 flowkey / croypto 两个元素。
	mux.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><body>
<span id="login-page-flowkey">FLOWKEY-1</span>
<span id="login-croypto">`+testCryptoKey()+`</span>
</body></html>`)
			return
		}

		m.mu.Lock()
		m.ssoLoginHits++
		m.mu.Unlock()

		http.Redirect(w, r, m.server.URL+"/api/cas/login?state=STATE1&ticket=ST-1-mockticket", http.StatusFound)
	})

	// CAS 回调：校验 ticket 后把 session token 放在 fragment 里下发。
	mux.HandleFunc("/api/cas/login", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.logins++
		m.mu.Unlock()

		if r.URL.Query().Get("ticket") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":0,"msg":"Required request parameter 'ticket' for method parameter type String is not present"}`)
			return
		}
		http.Redirect(w, r, m.server.URL+"/index.html#?token="+m.Token+"&t=1700000000001", http.StatusFound)
	})

	mux.HandleFunc("/index.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html></html>")
	})

	// 业务接口：用于测试 401 语义与 ticket 生成。
	mux.HandleFunc("/api/business-401", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.tickets = append(m.tickets, r.Header.Get(HeaderTicket))
		m.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, m.Business401Body)
	})

	mux.HandleFunc("/api/empty", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/dingtalk/jsapi_ticket", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if m.JsapiTicketBody == "" {
			// 与 HAR#2 一致：200 + 0 字节。
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, m.JsapiTicketBody)
	})

	// ★ 学生签到接口。真实的无效签到码会得到 401 业务错误。
	mux.HandleFunc("/api/ali-nvc/captcha-verify", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.lastCaptchaVerifyQuery = r.URL.Query()
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":0,"msg":"签到码不存在，不要玩我"}`)
	})

	mux.HandleFunc("/api/ali-nvc/check-code-analyze", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.lastAnalyzeQuery = r.URL.Query()
		m.mu.Unlock()

		tpl := m.AnalyzeJSONP
		if tpl == "" {
			tpl = `%s({"result":{"code":800}})`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, tpl, r.URL.Query().Get("callback"))
	})

	mux.HandleFunc("/api/checkIn/code-check-in", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.lastCodeCheckInQuery = r.URL.Query()
		m.mu.Unlock()

		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":0,"msg":"签到码不存在，不要玩我"}`)
	})

	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.tickets = append(m.tickets, r.Header.Get(HeaderTicket))
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":  r.Header.Get(HeaderAuthToken),
			"ticket": r.Header.Get(HeaderTicket),
		})
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// r0 返回一个纯 GET 请求，仅用于 http.Redirect。
func r0() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	return req
}

// testCryptoKey 返回一个合法的 AES 密钥（Base64）。
func testCryptoKey() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
}

func newMockClient(t *testing.T, m *mockSkl, opts ...Option) *Client {
	t.Helper()

	all := append([]Option{
		WithBaseURL(m.server.URL),
		WithCredentials("24000000", "secret"),
	}, opts...)

	c, err := NewClient(all...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestLoginCapturesTokenFromRedirectFragment(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m)

	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if got := c.Token(); got != m.Token {
		t.Fatalf("Token() = %q, want %q", got, m.Token)
	}

	// 登录后应能直接拿到用户信息，且不再触发二次登录。
	user, err := c.UserInfo(t.Context())
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if user.ID != "24000000" {
		t.Fatalf("UserInfo().ID = %q, want 24000000", user.ID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logins != 1 {
		t.Fatalf("CAS 回调次数 = %d, want 1", m.logins)
	}
}

func TestLoginIsIdempotentWhenTokenStillValid(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m)

	for i := range 3 {
		if err := c.Login(t.Context()); err != nil {
			t.Fatalf("Login #%d: %v", i, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logins != 1 {
		t.Fatalf("重复 Login 触发了 %d 次 CAS 登录，want 1", m.logins)
	}
}

func TestLoginWithoutCredentials(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c, err := NewClient(WithBaseURL(m.server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.Login(t.Context()); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Login() = %v, want ErrNoCredentials", err)
	}
}

func TestDoAutoReloginOnAuthURL401(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken("stale-token"))

	// 带过期 token 请求 -> 401 带 url -> 自动重登 -> 重放成功。
	user, err := c.UserInfo(t.Context())
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if user.ID != "24000000" {
		t.Fatalf("UserInfo().ID = %q", user.ID)
	}
	if got := c.Token(); got != m.Token {
		t.Fatalf("重登后 Token() = %q, want %q", got, m.Token)
	}
}

// 这是最关键的一条不变式：业务性质的 401（例如「签到码不存在」）不带 url 字段，
// 绝不能触发重登重放 —— 否则一次失败的签到会被当成会话失效，
// 白白跑一遍 CAS 登录并把签到请求重放一次。
func TestDoDoesNotReloginOnBusiness401(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	m.Business401Body = `{"code":0,"msg":"签到码不存在，不要玩我"}`
	c := newMockClient(t, m, WithToken("whatever"))

	resp, err := c.Get(t.Context(), "/api/business-401", nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Msg != "签到码不存在，不要玩我" {
		t.Fatalf("APIError.Msg = %q", apiErr.Msg)
	}
	if apiErr.NeedLogin() {
		t.Fatal("业务 401 被误判为需要重新登录")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("resp = %+v, want 401 response returned alongside the error", resp)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("errors.Is(err, ErrUnauthorized) = false; err = %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logins != 0 {
		t.Fatalf("业务 401 触发了 %d 次登录，want 0", m.logins)
	}
}

func TestDoNoReloginWhenDisabled(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithAutoLogin(false), WithToken("stale"))

	_, err := c.Get(t.Context(), "/api/userinfo", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.AuthURL == "" {
		t.Fatalf("err = %v, want *APIError with AuthURL", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logins != 0 {
		t.Fatalf("WithAutoLogin(false) 仍然登录了 %d 次", m.logins)
	}
}

// skl-ticket 是一次性 nonce：每个请求都必须是新值，
// 否则服务端会以 200 + 空 body 的形式静默拒绝。
func TestDoSendsFreshTicketPerRequest(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	const n = 5
	for range n {
		if _, err := c.Get(t.Context(), "/api/echo", nil); err != nil {
			t.Fatalf("echo: %v", err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.tickets) != n {
		t.Fatalf("记录到 %d 个 skl-ticket, want %d", len(m.tickets), n)
	}
	seen := make(map[string]struct{}, n)
	for _, tk := range m.tickets {
		if len(tk) != TicketSize {
			t.Fatalf("skl-ticket = %q, 长度 %d, want %d", tk, len(tk), TicketSize)
		}
		if _, dup := seen[tk]; dup {
			t.Fatalf("skl-ticket 出现重复值 %q", tk)
		}
		seen[tk] = struct{}{}
	}
}

func TestDoEmptyBodyIsAnError(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	_, err := c.Get(t.Context(), "/api/empty", nil)
	if !errors.Is(err, ErrEmptyBody) {
		t.Fatalf("err = %v, want ErrEmptyBody", err)
	}
}

func TestDoAllowEmptyBody(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	resp, err := c.Do(t.Context(), &Request{
		Method:         http.MethodGet,
		Path:           "/api/empty",
		AllowEmptyBody: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.IsEmpty() {
		t.Fatalf("resp.Body = %q, want empty", resp.Body)
	}
}

func TestDoSendsAuthTokenOnlyWhenPresent(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)

	// 无 token：不应发送 X-Auth-Token 头。
	c := newMockClient(t, m)
	resp, err := c.Get(t.Context(), "/api/echo", nil)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	var first map[string]string
	if err := resp.JSON(&first); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if first["token"] != "" {
		t.Fatalf("无 token 时仍发送了 X-Auth-Token=%q", first["token"])
	}

	// 有 token：应发送。
	c.SetToken("abc")
	resp, err = c.Get(t.Context(), "/api/echo", nil)
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	var second map[string]string
	if err := resp.JSON(&second); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if second["token"] != "abc" {
		t.Fatalf("X-Auth-Token = %q, want abc", second["token"])
	}
}

func TestSetTokenFiresCallback(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	var got []string
	c := newMockClient(t, m, WithOnToken(func(tk string) { got = append(got, tk) }))

	c.SetToken("first")
	c.SetToken("second")
	c.SetToken("") // 空值不回调

	want := []string{"first", "second"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("onToken 回调 = %v, want %v", got, want)
	}
}

func TestResolveURLEscapesAndMergesQuery(t *testing.T) {
	t.Parallel()

	c, err := NewClient(WithBaseURL("https://skl.hdu.edu.cn/"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := c.resolveURL("/api/course?startTime=2026-09-14", url.Values{
		"extra": {"a b"},
	})
	if err != nil {
		t.Fatalf("resolveURL: %v", err)
	}

	if !strings.HasPrefix(got.String(), "https://skl.hdu.edu.cn/api/course?") {
		t.Fatalf("resolveURL = %q", got.String())
	}
	q := got.Query()
	if q.Get("startTime") != "2026-09-14" {
		t.Fatalf("startTime = %q", q.Get("startTime"))
	}
	if q.Get("extra") != "a b" {
		t.Fatalf("extra = %q", q.Get("extra"))
	}
}

func TestResolveURLErrorsOnEmptyPath(t *testing.T) {
	t.Parallel()

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.resolveURL("", nil); err == nil {
		t.Fatal("resolveURL(\"\") = nil error, want error")
	}
}

func TestAPIErrorFromSuccessIsNil(t *testing.T) {
	t.Parallel()

	if e := apiErrorFrom(&Response{StatusCode: http.StatusOK}); e != nil {
		t.Fatalf("apiErrorFrom(200) = %v, want nil", e)
	}
}

func TestAPIErrorParsesEnvelope(t *testing.T) {
	t.Parallel()

	resp := &Response{
		StatusCode: http.StatusUnauthorized,
		Body:       []byte(`{"code":0,"msg":"签到码不存在，不要玩我"}`),
	}
	e := apiErrorFrom(resp)
	if e == nil {
		t.Fatal("apiErrorFrom = nil")
	}
	if e.AuthURL != "" {
		t.Fatalf("AuthURL = %q, want empty", e.AuthURL)
	}
	if e.Msg != "签到码不存在，不要玩我" {
		t.Fatalf("Msg = %q", e.Msg)
	}
	if e.NeedLogin() {
		t.Fatal("不带 url 的 401 不应 NeedLogin()=true")
	}
	if !errors.Is(e, ErrUnauthorized) {
		t.Fatal("401 应满足 errors.Is(err, ErrUnauthorized)")
	}
}

func TestAPIErrorNonJSONBody(t *testing.T) {
	t.Parallel()

	e := apiErrorFrom(&Response{StatusCode: http.StatusInternalServerError, Body: []byte("<html>boom</html>")})
	if e == nil {
		t.Fatal("apiErrorFrom = nil")
	}
	if !strings.Contains(e.Error(), "boom") {
		t.Fatalf("Error() = %q, want it to include the body", e.Error())
	}
}
