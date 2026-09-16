package skl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/U1traVeno/hduwebvpn/pkg/sso"
)

// SSOAuthenticator 执行一次 SSO 登录并返回服务端下发的 ticket。
//
// 它的签名与 github.com/U1traVeno/hduwebvpn/pkg/sso.Auth 完全一致，
// 因此可以用一行适配器把后者接上（默认实现就是它）：
//
//	skl.WithSSOAuthenticator(skl.SSOAuthenticatorFunc(sso.Auth))
//
// 注入点存在的理由：学校改版 SSO，或调用方要走别的认证通道时，
// 不必等 hduwebvpn 上游升级。
//
// 注意 SSO 认证的用户与签到的用户是同一个人：会话获取只是签到的前置支撑，
// 而不是一条独立的业务能力。
type SSOAuthenticator interface {
	// Authenticate 用 username/password 在 loginURL 完成登录并返回 ticket。
	//
	// client 由 skl 提供（已带 trace 层与 cookie jar）；实现应当在它之上
	// 跟随重定向，因为会话 token 只出现在登录链末尾 URL 的 fragment 里。
	Authenticate(ctx context.Context, client *http.Client, loginURL, username, password string) (ticket string, err error)
}

// SSOAuthenticatorFunc 把函数适配成 SSOAuthenticator。
type SSOAuthenticatorFunc func(ctx context.Context, client *http.Client, loginURL, username, password string) (string, error)

// Authenticate 实现 SSOAuthenticator。
func (f SSOAuthenticatorFunc) Authenticate(ctx context.Context, client *http.Client, loginURL, username, password string) (string, error) {
	return f(ctx, client, loginURL, username, password)
}

// defaultSSOAuthenticator 是未注入时的 SSO 实现：hduwebvpn 是默认依赖，
// 不是唯一依赖。
var defaultSSOAuthenticator SSOAuthenticator = SSOAuthenticatorFunc(sso.Auth)

// Login 执行完整的 CAS/SSO 登录并取得 session token。
//
// # 实测流程（`har#1`/`har#2` + 真机验证）
//
//  1. `GET /api/userinfo?type=&index=<index>`（不带 token）
//     → `401`，响应体 `{"url":"https://cas.hdu.edu.cn/cas/login?state=...&service=..."}`。
//     `state` 由 skl 后端生成并随 `service` 一起回传，是这条链的关联键。
//  2. `GET <cas url>` → `302` 到
//     `https://sso.hdu.edu.cn/login?service=...&state=...`。
//     cas.hdu.edu.cn 只是个转发壳，真正登录在新 SSO 上。
//  3. 在 SSO 登录页抓 `#login-page-flowkey` / `#login-croypto`，
//     用 AES-ECB 加密密码后 POST 表单 → `302` 带 `ticket=ST-...`。
//     这一步复用 hduwebvpn 的 pkg/sso。
//  4. 跟随 `service` 回到 `https://skl.hdu.edu.cn/api/cas/login?...&ticket=ST-...`，
//     服务端校验 ticket 后 `302` 到
//     `https://skl.hdu.edu.cn/index.html#?token=<uuid>&t=<ms>`。
//
// 最终 URL 的 **fragment** 里带着会话 token，前端把它存进 localStorage 的
// `sessionId`，之后每个请求以 `X-Auth-Token` 发出。
//
// Login 是幂等且并发安全的：并发调用只会真正登录一次，
// 已经拿到有效 token 时不会重复登录。
func (c *Client) Login(ctx context.Context) error {
	if !c.HasCredentials() {
		return ErrNoCredentials
	}

	c.loginMu.Lock()
	defer c.loginMu.Unlock()

	// 已有 token 且仍然有效时不重复登录。
	if token := c.Token(); token != "" {
		if err := c.probeToken(ctx, token); err == nil {
			return nil
		}
	}

	return c.loginLocked(ctx)
}

// relogin 在会话失效后重新登录。
//
// failedWith 是失败请求当时使用的 token：如果在此期间别的 goroutine
// 已经换过 token，就说明重登已经发生过，这里直接复用、避免登录风暴。
func (c *Client) relogin(ctx context.Context, failedWith string) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()

	if token := c.Token(); token != "" && token != failedWith {
		return nil
	}
	if !c.HasCredentials() {
		return ErrNoCredentials
	}
	return c.loginLocked(ctx)
}

// loginChainTimeoutFactor 把单次请求超时放大成整条登录链的预算。
//
// 登录链实际要走 4 跳（skl -> cas -> sso -> skl），每一跳都不应该挤在
// 单次请求的超时里；但也不能不设上限：sso.Auth 用的是调用方的 ctx，
// 若调用方传进来的是 context.Background()，卡住的 SSO 会永久挂起。
const loginChainTimeoutFactor = 4

// loginLocked 执行一次真实登录。调用方必须持有 loginMu。
func (c *Client) loginLocked(ctx context.Context) error {
	casURL, err := c.requestLoginURL(ctx)
	if err != nil {
		return err
	}

	ssoURL, err := c.resolveSSOLoginURL(ctx, casURL)
	if err != nil {
		return err
	}

	// SSO 实现（默认 sso.Auth）内部直接用传入的 httpClient 跟随重定向，
	// 且不走 Do 的 per-request 超时，所以这里必须自己给整条链设一个上限。
	loginCtx := ctx
	if c.timeout > 0 {
		var cancel context.CancelFunc
		loginCtx, cancel = context.WithTimeout(ctx, loginChainTimeoutFactor*c.timeout)
		defer cancel()
	}

	c.trace.start()
	_, err = c.ssoAuth.Authenticate(loginCtx, c.http, ssoURL, c.username, c.password)
	chain := c.trace.stop()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLoginFailed, err)
	}

	token := extractSessionToken(chain)
	if token == "" {
		return fmt.Errorf("%w: 登录链中未找到 token 参数（已记录 %d 个跳转）", ErrLoginFailed, len(chain))
	}

	if err := c.probeToken(ctx, token); err != nil {
		return fmt.Errorf("%w: 取得的 token 无法通过 /api/userinfo 校验: %v", ErrLoginFailed, err)
	}

	c.SetToken(token)
	c.logger.Info("skl: 登录成功", "user", c.username)
	return nil
}

// requestLoginURL 向 skl 索要 CAS 登录地址（同时拿到 state）。
func (c *Client) requestLoginURL(ctx context.Context) (string, error) {
	resp, err := c.Do(ctx, &Request{
		Method:    http.MethodGet,
		Path:      "/api/userinfo",
		Query:     url.Values{"type": {""}, "index": {c.index}},
		NoAuth:    true,
		NoRelogin: true,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.AuthURL != "" {
			return apiErr.AuthURL, nil
		}
		return "", fmt.Errorf("skl: 获取 CAS 登录地址失败: %w", err)
	}

	// 理论上不会走到这里（无 token 时必然 401），但保持健壮。
	var body struct {
		URL string `json:"url"`
	}
	if err := resp.JSON(&body); err != nil {
		return "", err
	}
	if body.URL == "" {
		return "", fmt.Errorf("%w: /api/userinfo 未返回登录地址", ErrLoginFailed)
	}
	return body.URL, nil
}

// resolveSSOLoginURL 解析出最终的新 SSO 登录地址。
//
// cas.hdu.edu.cn 会 302 到 sso.hdu.edu.cn；必须把 POST 直接打到 sso 上，
// 因为 Go 的 http.Client 在 302 时会把 POST 降级成 GET 并丢弃表单。
func (c *Client) resolveSSOLoginURL(ctx context.Context, casURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, casURL, nil)
	if err != nil {
		return "", fmt.Errorf("skl: 构造 CAS 请求失败: %w", err)
	}

	// 单独用一只不跟随重定向的 client，只为了读 Location。
	noRedirect := &http.Client{
		Transport: c.trace,
		Jar:       c.jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", fmt.Errorf("skl: 解析 CAS 登录地址失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	loc := resp.Header.Get("Location")
	if loc == "" {
		// 没有跳转说明 CAS 直接给了登录页，就用原地址。
		return casURL, nil
	}

	target, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("skl: CAS 跳转地址非法 %q: %w", loc, err)
	}
	return target.String(), nil
}

// probeToken 用 /api/userinfo 校验一个 token 是否可用。
//
// 校验成功时顺带刷新用户信息缓存。
func (c *Client) probeToken(ctx context.Context, token string) error {
	previous := c.Token()
	c.setTokenRaw(token)
	defer func() { c.setTokenRaw(previous) }()

	user, err := c.userInfo(ctx, true)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.user = user
	c.mu.Unlock()
	return nil
}

// setTokenRaw 设置 token 但不触发回调、不清空用户缓存。
func (c *Client) setTokenRaw(token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}
