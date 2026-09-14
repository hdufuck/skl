package skl

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrInvalidTicketSize 表示请求的 skl-ticket 长度非法。
	ErrInvalidTicketSize = errors.New("skl: 非法的 skl-ticket 长度")

	// ErrNoCredentials 表示需要登录但没有配置账号密码。
	ErrNoCredentials = errors.New("skl: 未配置账号密码，无法登录")

	// ErrLoginFailed 表示 CAS/SSO 登录流程结束但未取得可用的 session token。
	ErrLoginFailed = errors.New("skl: CAS 登录失败，未取得可用的 session token")

	// ErrUnauthorized 表示会话失效（401）。调用方通常应先 Login 再重试。
	ErrUnauthorized = errors.New("skl: 会话失效")

	// ErrEmptyBody 表示服务端返回 `HTTP 200` 但响应体为空。
	//
	// 这是 skl 一个非常容易踩坑的失败模式，实测由两类原因触发：
	//  1. skl-ticket 被重放（服务端把它当作一次性 nonce）；
	//  2. 请求被前置 WAF 拦截。
	//
	// 注意它**不是** 4xx/5xx，因此不能靠状态码判断成功。
	ErrEmptyBody = errors.New("skl: 服务端返回 200 但响应体为空（skl-ticket 重放被拒或被 WAF 拦截）")

	// ErrCaptchaRequired 表示服务端要求完成人机验证。
	ErrCaptchaRequired = errors.New("skl: 服务端要求人机验证")

	// ErrNoCaptchaProvider 表示需要 captchaVerifyParam 但未配置 CaptchaProvider。
	ErrNoCaptchaProvider = errors.New("skl: 未配置 CaptchaProvider，无法获取 captchaVerifyParam")
)

// APIError 是 skl 业务层的错误响应。
//
// 服务端用统一的 `{"code":0,"msg":"..."}` 形态表达业务错误，并搭配
// 400/401/403 等状态码。其中 401 既用于「会话失效」，也用于「业务校验失败」
// （例如签到码不存在），二者靠是否携带 `url` 字段区分：
// 携带 `url` 表示需要跳转去 CAS 登录。
type APIError struct {
	StatusCode int
	Code       int
	Msg        string
	// AuthURL 非空表示服务端要求跳转该地址重新登录。
	AuthURL string
	// Body 保存原始响应体，便于排查未被识别的错误形态。
	Body string
}

func (e *APIError) Error() string {
	switch {
	case e.AuthURL != "":
		return fmt.Sprintf("skl: HTTP %d 需要重新登录: %s", e.StatusCode, e.AuthURL)
	case e.Msg != "":
		return fmt.Sprintf("skl: HTTP %d code=%d: %s", e.StatusCode, e.Code, e.Msg)
	default:
		return fmt.Sprintf("skl: HTTP %d: %s", e.StatusCode, e.Body)
	}
}

// Is 让 APIError 可以配合 errors.Is 使用。
//
// 注意 ErrUnauthorized 只表示「HTTP 401」，不代表会话一定失效：
// 会话失效要看 NeedLogin()（即响应是否携带 url 字段）。
//
// 这里比较的是 errors.Is 传入的 target 本身，而非被包装的错误，
// 因此不适用 errors.Is(err, ...) 的写法。
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrCaptchaRequired:
		return e.CaptchaRequired()
	default:
		return false
	}
}

// NeedLogin 报告该错误是否意味着会话失效、需要重新登录。
//
// 判据是服务端是否在 401 响应体里带上 `url` 字段 —— 前端也正是据此
// `window.location.replace(data.url)` 的。裸 401（不带 url）是业务校验
// 失败（例如「签到码不存在」），不应触发重登。
//
// 这里刻意与 Do 的自动重登判据保持一致：两者若不一致，
// 调用方按 NeedLogin 决定重试就会与库内行为相互矛盾。
func (e *APIError) NeedLogin() bool {
	return e.AuthURL != ""
}

// CaptchaRequired 报告该错误是否意味着服务端要求人机验证。
//
// 实测形态：`check-code-analyze` 通过 JSONP 返回 `{"result":{"code":400}}`，
// 前端据此弹出滑块。这里只做保守判断，不猜测其它错误码语义。
func (e *APIError) CaptchaRequired() bool {
	return e.StatusCode == http.StatusBadRequest && e.Msg == captchaRequiredMsg
}

const captchaRequiredMsg = "请完成人机验证"
