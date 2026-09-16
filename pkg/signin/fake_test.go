package signin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/hdufuck/skl"
)

// recordedRequest 是一次假服务器收到的请求，用于在 HTTP 边界上做断言。
type recordedRequest struct {
	method      string
	path        string
	query       url.Values
	contentType string
	bodyLen     int64
}

// fakeSkl 是 skl 站点在测试里的最小替身，覆盖签到涉及的四个端点。
type fakeSkl struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest

	userinfo string
	// analyzeJSONP 是 check-code-analyze 的响应模板（%s 替换为回调名）。
	analyzeJSONP  string
	captchaStatus int
	captchaBody   string
	legacyStatus  int
	legacyBody    string
}

func newFakeSkl(t *testing.T) *fakeSkl {
	t.Helper()

	f := &fakeSkl{
		userinfo:      `{"id":"24000000","userName":"测试用户","userType":1}`,
		analyzeJSONP:  `%s({"result":{"code":800}})`,
		captchaStatus: http.StatusUnauthorized,
		captchaBody:   `{"code":0,"msg":"签到码不存在，不要玩我"}`,
		legacyStatus:  http.StatusUnauthorized,
		legacyBody:    `{"code":0,"msg":"签到码不存在，不要玩我"}`,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(skl.PathUserInfo, func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, f.userinfo)
	})
	mux.HandleFunc(skl.PathSignInCaptchaVerify, func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.captchaStatus)
		_, _ = io.WriteString(w, f.captchaBody)
	})
	mux.HandleFunc(skl.PathSignInLegacy, func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.legacyStatus)
		_, _ = io.WriteString(w, f.legacyBody)
	})
	mux.HandleFunc(skl.PathSignInAnalyze, func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, f.analyzeJSONP, r.URL.Query().Get("callback"))
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSkl) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, recordedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		query:       r.URL.Query(),
		contentType: r.Header.Get("Content-Type"),
		bodyLen:     r.ContentLength,
	})
}

func (f *fakeSkl) lastRequest(t *testing.T) recordedRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("假服务器没有收到任何请求")
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeSkl) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// newTestClient 造一只指向假服务器的 skl.Client（已注入 token）。
func newTestClient(t *testing.T, f *fakeSkl, opts ...skl.Option) *skl.Client {
	t.Helper()

	all := append([]skl.Option{
		skl.WithBaseURL(f.server.URL),
		skl.WithToken("test-token"),
	}, opts...)

	c, err := skl.NewClient(all...)
	if err != nil {
		t.Fatalf("skl.NewClient: %v", err)
	}
	return c
}

// newTestSignin 是 newTestClient 的签到门面封装。
func newTestSignin(t *testing.T, f *fakeSkl, opts ...skl.Option) *Client {
	t.Helper()
	return New(newTestClient(t, f, opts...))
}
