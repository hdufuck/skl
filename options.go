package skl

import (
	"log/slog"
	"net/http"
	"time"
)

// Option 配置 Client。
type Option func(*Client)

// WithBaseURL 覆盖 skl 站点根地址，主要用于测试。
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = trimTrailingSlash(baseURL)
		}
	}
}

// WithCredentials 设置 CAS/SSO 账号密码。
//
// 只有在设置了账号密码之后，Client 才具备自动登录与 401 自动重登能力；
// 否则只能通过 WithToken / SetToken 外部注入会话。
func WithCredentials(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithToken 直接注入一个已有的 session token，跳过登录流程。
//
// token 可以来自浏览器 DevTools 里的 `localStorage.sessionId`，
// 或登录回调 URL fragment 中的 `token` 参数。
func WithToken(token string) Option {
	return func(c *Client) {
		c.token = token
	}
}

// WithIndex 设置登录握手时上报的 `index` 参数（默认 `index.html`）。
//
// 前端把它设为当前路由（去掉前导 `/`），服务端只是回显到登录回调地址里，
// API 客户端保持默认值即可。
func WithIndex(index string) Option {
	return func(c *Client) {
		if index != "" {
			c.index = index
		}
	}
}

// WithTransport 设置底层 RoundTripper。
//
// 注意这里接受的是 Transport 而不是 *http.Client：Client 需要在
// Transport 层记录 CAS 重定向链（session token 是从 URL fragment 里捞出来的），
// 因此不允许替换整只 http.Client。
func WithTransport(rt http.RoundTripper) Option {
	return func(c *Client) {
		if rt != nil {
			c.baseTransport = rt
		}
	}
}

// WithCookieJar 设置 cookie jar。SSO 登录链依赖 cookie，测试时可注入。
func WithCookieJar(jar http.CookieJar) Option {
	return func(c *Client) {
		if jar != nil {
			c.jar = jar
		}
	}
}

// WithTimeout 设置单次请求的默认超时（默认 30s）。
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithAutoLogin 控制是否在检测到会话失效时自动重新登录（默认开启）。
//
// 只有当 Client 同时配置了账号密码时才可能触发。
func WithAutoLogin(enabled bool) Option {
	return func(c *Client) {
		c.autoLogin = enabled
	}
}

// WithLogger 设置日志记录器。
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithOnToken 注册 session token 变更回调。
//
// 用于把 token 持久化到磁盘/数据库，避免每次启动都要走一次 CAS 登录。
// 实测 token 生命周期较长（抓包中的 token 隔夜仍然可用），
// 但服务端未给出过期时间，调用方应自行处理失效重登。
func WithOnToken(fn func(token string)) Option {
	return func(c *Client) {
		if fn != nil {
			c.onToken = fn
		}
	}
}

// WithCaptchaProvider 设置人机验证参数提供者。
//
// 只有签到（captcha-verify）需要它，其余 API 不受影响。
func WithCaptchaProvider(p CaptchaProvider) Option {
	return func(c *Client) {
		if p != nil {
			c.captcha = p
		}
	}
}
