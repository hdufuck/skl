package skl

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// roundTripFunc 把函数适配成 http.RoundTripper，用于在测试里观察请求。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// countingJar 记录 SetCookies 调用次数的 cookie jar，内嵌一只真 jar。
type countingJar struct {
	inner *cookiejar.Jar

	mu  sync.Mutex
	set int
}

func newCountingJar(t *testing.T) *countingJar {
	t.Helper()
	inner, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &countingJar{inner: inner}
}

func (j *countingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	j.set++
	j.mu.Unlock()
	j.inner.SetCookies(u, cookies)
}

func (j *countingJar) Cookies(u *url.URL) []*http.Cookie { return j.inner.Cookies(u) }

func (j *countingJar) setCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.set
}

// WithHTTPClient 必须真正采纳调用方的 Transport 与 Jar，
// 否则「把带代理/隧道的 client 交给 skl」这件事没有意义。
func TestWithHTTPClientAdoptsTransportAndJar(t *testing.T) {
	t.Parallel()

	jar := newCountingJar(t)
	var (
		mu    sync.Mutex
		paths []string
		cooks []string
	)
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, req.URL.Path)
		cooks = append(cooks, req.Header.Get("Cookie"))
		mu.Unlock()
		return http.DefaultTransport.RoundTrip(req)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cookie" {
			http.SetCookie(w, &http.Cookie{Name: "sess", Value: "abc", Path: "/"})
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	// 预置一个 cookie：它必须真的在后续请求里被发出去。
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar.inner.SetCookies(u, []*http.Cookie{{Name: "seed", Value: "1", Path: "/"}})

	c, err := NewClient(
		WithBaseURL(srv.URL),
		WithToken("t"),
		WithHTTPClient(&http.Client{Transport: rt, Jar: jar}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Get(t.Context(), "/api/cookie", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	gotCooks := append([]string(nil), cooks...)
	mu.Unlock()
	if len(gotPaths) != 1 || gotPaths[0] != "/api/cookie" {
		t.Fatalf("自定义 Transport 观察到的请求 = %v, want [/api/cookie]", gotPaths)
	}
	if len(gotCooks) != 1 || !strings.Contains(gotCooks[0], "seed=1") {
		t.Fatalf("自定义 Jar 里预置的 cookie 未被发送，实际 Cookie 头 = %v", gotCooks)
	}
	if jar.setCount() == 0 {
		t.Fatal("自定义 Jar 未收到 SetCookies：Jar 没有被采纳")
	}
}

// Transport 仍必须被 traceTransport 包裹：会话 token 只在 CAS 重定向链
// 末尾 URL 的 fragment 里，绕过 trace 层登录就取不到 token。
func TestWithHTTPClientStillExtractsTokenFromFragment(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return http.DefaultTransport.RoundTrip(req)
	})

	c := newMockClient(t, m, WithHTTPClient(&http.Client{Transport: rt}))
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := c.Token(); got != m.Token {
		t.Fatalf("Token() = %q, want %q（token 仍应从 fragment 提取）", got, m.Token)
	}
}

// 调用方在 Jar 里预置的 cookie（例如自己维护的 SSO 会话）必须在**登录链**里
// 继续生效，而不只是普通请求。
func TestWithHTTPClientReusesJarCookiesInLoginChain(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	jar := newCountingJar(t)

	u, err := url.Parse(m.server.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar.inner.SetCookies(u, []*http.Cookie{{Name: "seed", Value: "1", Path: "/"}})

	var (
		mu    sync.Mutex
		cooks []string
	)
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		cooks = append(cooks, req.Header.Get("Cookie"))
		mu.Unlock()
		return http.DefaultTransport.RoundTrip(req)
	})

	c := newMockClient(t, m, WithHTTPClient(&http.Client{Transport: rt, Jar: jar}))
	if err := c.Login(t.Context()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := c.Token(); got != m.Token {
		t.Fatalf("Token() = %q, want %q", got, m.Token)
	}

	mu.Lock()
	gotCooks := append([]string(nil), cooks...)
	mu.Unlock()

	carried := false
	for _, c := range gotCooks {
		if strings.Contains(c, "seed=1") {
			carried = true
			break
		}
	}
	if !carried {
		t.Fatalf("登录链的请求里没有带上预置 cookie，实际 Cookie 头 = %v", gotCooks)
	}
}

// 逐请求预算与重定向上限是 skl 的策略：WithHTTPClient 不采纳 client 自己的
// Timeout 与 CheckRedirect。断言在 HTTP 边界上做：若采纳了那只 client，
// 1ns 的 Timeout 会让请求直接超时，而「总是报错」的 CheckRedirect
// 会让一次 302 也跟随不了。
func TestWithHTTPClientIgnoresTimeoutAndCheckRedirect(t *testing.T) {
	t.Parallel()

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/redirect":
			http.Redirect(w, r, "/api/ok", http.StatusFound)
		case "/api/ok":
			hits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(
		WithBaseURL(srv.URL),
		WithToken("t"),
		WithHTTPClient(&http.Client{
			Timeout: time.Nanosecond,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("custom redirect policy")
			},
		}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := c.Get(t.Context(), "/api/redirect", nil); err != nil {
		t.Fatalf("Get: %v（只有采纳了调用方的 Timeout/CheckRedirect 才会失败）", err)
	}
	if hits != 1 {
		t.Fatalf("重定向后的端点命中 %d 次, want 1", hits)
	}
}
