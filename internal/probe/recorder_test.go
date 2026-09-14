package probe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecorderCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"msg":"hi"}`)
	}))
	defer srv.Close()

	rec := NewRecorder(nil)

	// Recorder 放行后，调用方仍要能读到 body。
	resp, err := rec.RoundTrip(mustRequest(t, http.MethodGet, srv.URL+"/x?a=1"))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = resp.Body.Close()
	if string(body) != `{"msg":"hi"}` {
		t.Fatalf("调用方读到的 body = %q", body)
	}

	ex := rec.Last()
	if ex == nil {
		t.Fatal("Last() = nil")
	}
	if ex.Method != http.MethodGet || !strings.HasSuffix(ex.URL, "/x?a=1") {
		t.Fatalf("请求未记录: %+v", ex)
	}
	if ex.Status != http.StatusTeapot || string(ex.Body) != `{"msg":"hi"}` {
		t.Fatalf("响应未记录: %+v", ex)
	}

	rec.Reset()
	if rec.Last() != nil {
		t.Fatal("Reset 后 Last() 应为 nil")
	}
}

func TestRecorderRecordsTransportError(t *testing.T) {
	rec := NewRecorder(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}))

	_, err := rec.RoundTrip(mustRequest(t, http.MethodGet, "https://example.invalid/"))
	if err == nil {
		t.Fatal("应返回错误")
	}
	ex := rec.Last()
	if ex == nil || ex.Err == nil {
		t.Fatalf("传输错误未记录: %+v", ex)
	}
}

func mustRequest(t *testing.T, method, rawurl string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
