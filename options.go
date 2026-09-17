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
// 因此 Transport 始终会被 traceTransport 包裹，不允许替换整只 http.Client。
// 手上如果是整只 *http.Client，用 WithHTTPClient（它同样只取 Transport 与 Jar）。
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

// WithHTTPClient 采纳调用方传入的 *http.Client 的 Transport 与 Jar。
//
// 用途：把已经配好代理/隧道、连接池与 cookie jar 的 client 交给 skl 复用
// （例如受限网络里的登录链需要那只带隧道的 client）。
//
// 只采纳两样东西：
//
//   - Transport：**仍会被 skl 的 traceTransport 包裹** —— 会话 token 只出现在
//     CAS 登录链末尾 URL 的 fragment 里，绕过 trace 层就登录不成。
//     Transport 为 nil 时沿用默认 Transport（http.DefaultTransport 的克隆）。
//   - Jar：SSO 登录链依赖 cookie，注入自己的 jar 才能让外部会话继续生效。
//     Jar 为 nil 时 skl 仍会创建默认的 cookie jar。
//
// **不**采纳的是：
//
//   - Timeout：逐请求预算由 WithTimeout / Request.Timeout 决定，不是这只 client 的。
//   - CheckRedirect：重定向上限是 skl 的策略（15 跳）。
//
// 与 WithTransport / WithCookieJar 同时使用时，后应用者覆盖前者。
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc == nil {
			return
		}
		if hc.Transport != nil {
			c.baseTransport = hc.Transport
		}
		if hc.Jar != nil {
			c.jar = hc.Jar
		}
	}
}

// WithSSOAuthenticator 注入自定义的 SSO 鉴权实现。
//
// 默认实现是 github.com/U1traVeno/hduwebvpn/pkg/sso.Auth；学校改版或调用方
// 走别的认证通道时可替换。注入 nil 时保持默认实现。
func WithSSOAuthenticator(a SSOAuthenticator) Option {
	return func(c *Client) {
		if a != nil {
			c.ssoAuth = a
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

// WithUserAgent 覆盖所有请求上报的 User-Agent（默认是项目自报名）。
//
// 用途：签到那条请求承载的 `captchaVerifyParam` 由浏览器铸出，想让 HTTP 客户端
// 与那个浏览器自称一致时用它（例如 `WithUserAgent(source.UserAgent())`）。
// 空串恢复默认值；每个请求仍可用 Request.Header 里的 User-Agent 单独覆盖。
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.SetUserAgent(ua)
	}
}
