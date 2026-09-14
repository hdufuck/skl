package probe

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// Exchange 是一次 HTTP 往返的原始观测。
type Exchange struct {
	Method string
	// URL 是未脱敏的完整请求 URL（仅内存中使用，落盘前一律走 RedactURL）。
	URL    string
	Status int
	Header http.Header
	Body   []byte
	// Err 非空表示请求根本没有得到响应。
	Err error
}

// Recorder 是一个记录最近一次 HTTP 往返的 RoundTripper。
//
// 它被包在 skl.Client 的最内层（`skl.WithTransport`），因此库内部的所有
// 请求（含 CAS 登录）都会经过它；调用方只需在调用库方法后读取 Last()，
// 就能拿到原始 URL / 状态码 / 响应体，用于写报告与判读。
type Recorder struct {
	base http.RoundTripper

	mu   sync.Mutex
	last *Exchange
}

// NewRecorder 创建 Recorder；base 为 nil 时用 http.DefaultTransport。
func NewRecorder(base http.RoundTripper) *Recorder {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Recorder{base: base}
}

// RoundTrip 实现 http.RoundTripper。
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	ex := &Exchange{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: http.Header{},
	}

	resp, err := r.base.RoundTrip(req)
	if err != nil {
		ex.Err = err
		r.store(ex)
		return nil, err
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		ex.Err = readErr
		r.store(ex)
		return nil, readErr
	}

	ex.Status = resp.StatusCode
	ex.Header = resp.Header.Clone()
	ex.Body = body
	r.store(ex)

	// 把 body 放回去，供调用方正常读取。
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func (r *Recorder) store(ex *Exchange) {
	r.mu.Lock()
	r.last = ex
	r.mu.Unlock()
}

// Last 返回最近一次往返的深拷贝；没有记录时返回 nil。
func (r *Recorder) Last() *Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return nil
	}
	cp := *r.last
	cp.Header = r.last.Header.Clone()
	cp.Body = bytes.Clone(r.last.Body)
	return &cp
}

// Reset 清空记录。
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.last = nil
	r.mu.Unlock()
}
