package skl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultBaseURL 是 skl 站点根地址。
	//
	// 注意：skl.hdu.edu.cn 在公网上可直接访问（无需 WebVPN），
	// 抓包也证实钉钉容器里走的就是直连，因此本包不依赖 webvpn 隧道。
	DefaultBaseURL = "https://skl.hdu.edu.cn"

	// DefaultIndex 是登录握手时上报的 index 参数。
	DefaultIndex = "index.html"

	// DefaultTimeout 是单次请求默认超时。
	DefaultTimeout = 30 * time.Second

	// HeaderAuthToken 是承载会话凭据的请求头。
	//
	// 取值来自浏览器 localStorage 的 sessionId，也就是 CAS 回调 URL
	// fragment 里的 token 参数。服务端**不使用 cookie** 维持会话。
	HeaderAuthToken = "X-Auth-Token"

	// HeaderTicket 是一次性防重放 nonce 请求头。
	HeaderTicket = "skl-ticket"

	// ContentTypeFormURLEncoded 是 skl 沿用 form 编码的那批请求的 Content-Type。
	//
	// 注意：官方签到接口（`POST /api/ali-nvc/captcha-verify`）把参数全放在
	// query 里、body 为空，但**仍然**带这个头（`har#3` 抓包第 101 条）。
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

	// defaultUserAgent 是本包默认上报的 User-Agent：项目自报名。
	//
	// 它也可以用 WithUserAgent / SetUserAgent 换掉：签到那条请求
	// （`POST /api/ali-nvc/captcha-verify`）承载的 captchaVerifyParam 是浏览器里
	// 铸出来的，想让它与「铸造参数的浏览器」看起来是同一个客户端时就改它。
	defaultUserAgent = "hdufuck/skl (+https://github.com/hdufuck/skl)"

	// maxResponseBytes 限制单次响应体大小，避免异常响应打爆内存。
	maxResponseBytes = 8 << 20
)

// Request 描述一次 skl API 调用。
type Request struct {
	Method string
	// Path 是 API 路径，例如 "/userinfo" 或 "/course?startTime=`har#1`/`har#2`"。
	Path string
	// Query 会合并进 Path 自带的 query。
	Query url.Values
	Body  []byte
	// Header 是附加请求头。
	Header http.Header
	// ContentType 显式指定 Content-Type，**空 body 时也生效**。
	//
	// 留空时沿用默认行为（仅当 body 非空才补 form 头）；签到这类
	// 「参数在 query、body 为空」的接口必须显式给出，才能与官方请求逐字节一致。
	ContentType string

	// Timeout 覆盖 Client 的默认超时。
	Timeout time.Duration

	// NoAuth 不附带 X-Auth-Token，用于登录握手。
	NoAuth bool
	// NoRelogin 禁止在收到「需要重新登录」的响应后自动重登重放。
	NoRelogin bool
	// AllowEmptyBody 允许 200 + 空响应体（默认视为异常，见 ErrEmptyBody）。
	AllowEmptyBody bool
}

// Response 是一次 skl API 调用的原始结果。
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	// URL 是实际请求的地址（含 query），便于排查。
	URL string
	// Ticket 是本次请求使用的 skl-ticket，便于定位「重放被拒」类问题。
	Ticket string
}

// JSON 把响应体解析到 v。
func (r *Response) JSON(v any) error {
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("skl: 解析 %s 响应失败: %w (body=%s)", r.URL, err, truncate(r.Body, 256))
	}
	return nil
}

// IsEmpty 报告响应体是否为空。
func (r *Response) IsEmpty() bool { return r == nil || len(r.Body) == 0 }

// Client 是 skl 的 API 客户端。
//
// 职责：
//   - 维护会话（X-Auth-Token）与自动登录/重登；
//   - 为每个请求生成一次性的 skl-ticket；
//   - 把「200 + 空 body」「401 + url」这类 skl 特有的失败模式翻译成 Go 错误。
//
// Client 可并发使用。
type Client struct {
	baseURL       string
	index         string
	username      string
	password      string
	baseTransport http.RoundTripper
	jar           http.CookieJar
	timeout       time.Duration
	autoLogin     bool
	captcha       CaptchaProvider
	ssoAuth       SSOAuthenticator
	logger        *slog.Logger
	onToken       func(string)

	http  *http.Client
	trace *traceTransport

	// loginMu 串行化登录流程，避免并发 401 时打出一串重复登录。
	loginMu sync.Mutex

	mu        sync.RWMutex
	token     string
	user      *UserInfo
	userAgent string
}

// NewClient 创建一个 Client。
//
// 默认不会立即登录：调用 Login 或直接发起需要鉴权的请求，
// 后者会在拿到「需要重新登录」的 401 时自动登录（前提是配置了账号密码）。
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:   DefaultBaseURL,
		index:     DefaultIndex,
		timeout:   DefaultTimeout,
		autoLogin: true,
		logger:    slog.New(slog.DiscardHandler),
		ssoAuth:   defaultSSOAuthenticator,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	if c.jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("skl: 创建 cookie jar: %w", err)
		}
		c.jar = jar
	}

	base := c.baseTransport
	if base == nil {
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			base = t.Clone()
		} else {
			base = http.DefaultTransport
		}
	}
	c.trace = &traceTransport{base: base}
	c.http = &http.Client{
		Transport: c.trace,
		Jar:       c.jar,
		// 不用 http.Client.Timeout：改由每次请求的 context 控制，
		// 这样登录链（较长）与普通接口可以有不同的预算。
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 15 {
				return fmt.Errorf("skl: 重定向次数超过 15 次")
			}
			return nil
		},
	}

	return c, nil
}

// BaseURL 返回站点根地址。
func (c *Client) BaseURL() string { return c.baseURL }

// HTTPClient 返回底层的 *http.Client。
//
// 仅供需要的调用方自建请求（例如下载二进制资源）时复用其连接池与 cookie jar。
func (c *Client) HTTPClient() *http.Client { return c.http }

// Token 返回当前 session token，未登录时为空串。
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// SetToken 注入一个外部获取的 session token。
//
// 会清空缓存的用户信息，并触发 WithOnToken 回调。
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	c.token = token
	c.user = nil
	cb := c.onToken
	c.mu.Unlock()
	if cb != nil && token != "" {
		cb(token)
	}
}

// SetUserAgent 换掉后续请求上报的 User-Agent（空串恢复默认的项目自报名）。
//
// 用途：签到（`captcha-verify`）那条请求要拿浏览器铸出来的 captchaVerifyParam
// 去提交，而「铸造参数的浏览器」与「提交参数的客户端」自称不一致时，风控侧能否看见
// 这个差异是未知的 —— 想对齐时用它，例如
// `c.SetUserAgent(captchaSource.UserAgent())`。
func (c *Client) SetUserAgent(ua string) {
	c.mu.Lock()
	c.userAgent = strings.TrimSpace(ua)
	c.mu.Unlock()
}

// UserAgent 返回当前上报的 User-Agent（未覆盖时是默认的项目自报名）。
func (c *Client) UserAgent() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.userAgent == "" {
		return defaultUserAgent
	}
	return c.userAgent
}

// HasCredentials 报告是否配置了账号密码。
func (c *Client) HasCredentials() bool {
	return c.username != "" && c.password != ""
}

// Get 发起一次 GET 请求。
func (c *Client) Get(ctx context.Context, path string, query url.Values) (*Response, error) {
	return c.Do(ctx, &Request{Method: http.MethodGet, Path: path, Query: query})
}

// Post 发起一次 POST 请求。
func (c *Client) Post(ctx context.Context, path string, query url.Values, body []byte) (*Response, error) {
	return c.Do(ctx, &Request{Method: http.MethodPost, Path: path, Query: query, Body: body})
}

// Do 执行一次 skl API 调用。
//
// 返回的错误可能是 *APIError（服务端业务错误）、ErrEmptyBody
// （200 但响应体为空）或网络/解析错误。发生业务错误时 Response 依然会返回，
// 便于调用方检查状态码与 body。
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, errors.New("skl: nil request")
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// allowRelogin 同时门控「是否尝试第二次」和「是否允许触发重登」：
	// 两者必须是同一个判断，否则 NoRelogin 的请求虽然只有一次机会，
	// attempt 仍为 0，会误入重登分支 —— 而登录握手本身就是用 NoRelogin
	// 调用的，重入 loginMu 会直接死锁。
	allowRelogin := c.autoLogin && !req.NoRelogin
	attempts := 1
	if allowRelogin {
		attempts = 2
	}

	var last *Response
	for attempt := range attempts {
		failedWith := c.Token()

		resp, err := c.execute(ctx, method, req)
		if err != nil {
			return nil, err
		}
		last = resp

		apiErr := apiErrorFrom(resp)
		if apiErr == nil {
			if resp.IsEmpty() && !req.AllowEmptyBody {
				return resp, ErrEmptyBody
			}
			return resp, nil
		}

		// 只有携带 `url` 的 401 才代表会话失效；业务校验失败（例如
		// 「签到码不存在」）也会返回 401，但绝不能触发重登重放。
		if attempt == 0 && allowRelogin && apiErr.AuthURL != "" && c.HasCredentials() {
			if err := c.relogin(ctx, failedWith); err != nil {
				return resp, fmt.Errorf("skl: 会话失效且自动重登失败: %w", err)
			}
			continue
		}
		return resp, apiErr
	}

	return last, nil
}

// execute 构造并发送单次 HTTP 请求。
func (c *Client) execute(ctx context.Context, method string, req *Request) (*Response, error) {
	target, err := c.resolveURL(req.Path, req.Query)
	if err != nil {
		return nil, err
	}

	ticket, err := NewTicket()
	if err != nil {
		return nil, fmt.Errorf("skl: 生成 skl-ticket: %w", err)
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}

	hreq, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("skl: 构造请求 %s %s: %w", method, target.Redacted(), err)
	}

	for key, values := range req.Header {
		for _, v := range values {
			hreq.Header.Add(key, v)
		}
	}
	if hreq.Header.Get("Accept") == "" {
		hreq.Header.Set("Accept", "application/json, text/plain, */*")
	}
	if hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", c.UserAgent())
	}
	if hreq.Header.Get("Referer") == "" {
		hreq.Header.Set("Referer", c.baseURL+"/"+c.index)
	}
	if req.ContentType != "" {
		// 显式指定：空 body 时也生效（官方签到请求就是这个形态）。
		hreq.Header.Set("Content-Type", req.ContentType)
	} else if len(req.Body) > 0 && hreq.Header.Get("Content-Type") == "" {
		hreq.Header.Set("Content-Type", ContentTypeFormURLEncoded)
	}
	// 每个请求一个全新的 nonce：服务端按一次性值校验，重放会返回
	// 200 + 空 body。
	hreq.Header.Set(HeaderTicket, ticket)

	if !req.NoAuth {
		if token := c.Token(); token != "" {
			hreq.Header.Set(HeaderAuthToken, token)
		}
	}

	resp, err := c.http.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("skl: %s %s: %w", method, target.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("skl: 读取 %s 响应失败: %w", target.Redacted(), err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		URL:        target.String(),
		Ticket:     ticket,
	}, nil
}

// resolveURL 把 API 路径拼到 baseURL 上，并合并额外 query。
func (c *Client) resolveURL(path string, extra url.Values) (*url.URL, error) {
	if path == "" {
		return nil, errors.New("skl: 空的请求路径")
	}

	raw := c.baseURL + "/" + strings.TrimPrefix(path, "/")
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("skl: 非法请求路径 %q: %w", path, err)
	}

	if len(extra) > 0 {
		query := target.Query()
		for key, values := range extra {
			for _, v := range values {
				query.Add(key, v)
			}
		}
		target.RawQuery = query.Encode()
	}
	return target, nil
}

// trimTrailingSlash 去掉结尾的 `/`。
func trimTrailingSlash(s string) string { return strings.TrimSuffix(s, "/") }

// truncate 截断过长的 body 用于错误信息。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// apiErrorFrom 把非 2xx 响应翻译成 *APIError，2xx 返回 nil。
func apiErrorFrom(resp *Response) *APIError {
	if resp.StatusCode < 400 {
		return nil
	}

	var envelope struct {
		Code *int   `json:"code"`
		Msg  string `json:"msg"`
		URL  string `json:"url"`
	}
	// 解析失败无所谓：下面用原始 body 兜底。
	_ = json.Unmarshal(resp.Body, &envelope)

	e := &APIError{
		StatusCode: resp.StatusCode,
		Msg:        envelope.Msg,
		AuthURL:    envelope.URL,
		Body:       truncate(resp.Body, 512),
	}
	if envelope.Code != nil {
		e.Code = *envelope.Code
	}
	return e
}

// traceTransport 记录经过它的请求 URL 与响应 Location 头。
//
// CAS 登录成功后的 session token 只出现在重定向链末尾的 URL fragment 里
// （`index.html#?token=...`），而 sso.Auth 会把那次跳转的最终 URL 丢掉，
// 所以在 Transport 层把整条链记下来是最稳妥的取法。
type traceTransport struct {
	base http.RoundTripper

	on atomic.Bool

	mu   sync.Mutex
	urls []string
}

func (t *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)

	if t.on.Load() {
		t.mu.Lock()
		t.urls = append(t.urls, req.URL.String())
		if resp != nil {
			if loc := resp.Header.Get("Location"); loc != "" {
				t.urls = append(t.urls, loc)
			}
		}
		t.mu.Unlock()
	}

	return resp, err
}

// start 开始记录。
func (t *traceTransport) start() {
	t.mu.Lock()
	t.urls = nil
	t.mu.Unlock()
	t.on.Store(true)
}

// stop 停止记录并返回按时间顺序捕获的 URL 列表。
func (t *traceTransport) stop() []string {
	t.on.Store(false)
	t.mu.Lock()
	defer t.mu.Unlock()
	out := slices.Clone(t.urls)
	t.urls = nil
	return out
}
