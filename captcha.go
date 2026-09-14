package skl

import "context"

// 阿里云验证码场景参数，取自 skl 前端签到页硬编码。
const (
	// DefaultCaptchaSceneID 是 skl 使用的阿里云验证码 SceneId。
	DefaultCaptchaSceneID = "2q42bw25"
	// DefaultCaptchaPrefix 是验证码服务的地域前缀（域名 cr5a57.captcha-open.aliyuncs.com）。
	DefaultCaptchaPrefix = "cr5a57"
	// AliyunCaptchaScriptURL 是阿里云验证码 3.x 前端 SDK。
	AliyunCaptchaScriptURL = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"
)

// CaptchaScene 描述一次人机验证所需的场景上下文。
type CaptchaScene struct {
	// SceneID 默认 DefaultCaptchaSceneID。
	SceneID string
	// Prefix 默认 DefaultCaptchaPrefix。
	Prefix string
	// PageURL 是验证码 SDK 初始化所在页面的 URL，
	// 会参与钉钉 JSAPI 签名（`/api/dingtalk/jsapi_ticket?url=`）。
	PageURL string
}

// withDefaults 补齐默认值。
func (s CaptchaScene) withDefaults(baseURL string) CaptchaScene {
	if s.SceneID == "" {
		s.SceneID = DefaultCaptchaSceneID
	}
	if s.Prefix == "" {
		s.Prefix = DefaultCaptchaPrefix
	}
	if s.PageURL == "" {
		s.PageURL = baseURL + "/sign/in"
	}
	return s
}

// CaptchaProvider 提供签到所需的 `captchaVerifyParam`。
//
// # 为什么需要这个接口
//
// `POST /api/ali-nvc/captcha-verify` 的 `captchaVerifyParam` 由阿里云验证码
// 3.x 前端 SDK 生成（实测版本 3.29.0）。它是一段 JSON 字符串：
//
//	{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2Fi...","data":"JRMlgg1E..."}
//
// 其中 `certifyId` 来自 `cr5a57.captcha-open.aliyuncs.com` 的会话初始化，
// `deviceToken` 来自 `cloudauth-device-dualstack.cn-shanghai.aliyuncs.com`
// 的设备指纹采集，`data` 是 SDK 内部混淆代码加密后的风控载荷。
// 三者都由阿里云侧签名，且与 SceneId、域名绑定，**无法用纯 Go 请求合成**。
//
// 因此本包把这部分隔离成一个接口，由调用方选择实现方式：
//
//  1. 最简单：人在浏览器里触发一次签到，从 DevTools 复制
//     `captchaVerifyParam`，用 StaticCaptchaProvider 注入（一次性，用完即废）。
//  2. 推荐自动化：用无头浏览器（chromedp / playwright-go）打开
//     `https://skl.hdu.edu.cn/sign/in`，先把 session token 写进
//     localStorage 的 `sessionId`，再输入 4 位签到码，让**官方页面自己**完成
//     captcha 与签到；此路径不经过本包的 SignIn。
//  3. 若确实需要在 Go 里拿到参数：在无头浏览器里加载同一页面并调用
//     `window.initAliyunCaptcha(...)`，在 captchaVerifyCallback 里把参数回传，
//     再由 CaptchaProvider 返回。
//
// 详细的可行性边界见包文档的「风险与未解项」。
type CaptchaProvider interface {
	// CaptchaVerifyParam 返回一个一次性的 captchaVerifyParam JSON 字符串。
	CaptchaVerifyParam(ctx context.Context, scene CaptchaScene) (string, error)
}

// CaptchaProviderFunc 把函数适配成 CaptchaProvider。
type CaptchaProviderFunc func(ctx context.Context, scene CaptchaScene) (string, error)

// CaptchaVerifyParam 实现 CaptchaProvider。
func (f CaptchaProviderFunc) CaptchaVerifyParam(ctx context.Context, scene CaptchaScene) (string, error) {
	return f(ctx, scene)
}

// StaticCaptchaProvider 返回一个固定值，适用于人工从浏览器复制参数的一次性签到。
//
// 注意 captchaVerifyParam 是一次性的：复用同一个值会被阿里云侧拒绝。
type StaticCaptchaProvider struct {
	Value string
}

// CaptchaVerifyParam 实现 CaptchaProvider。
func (p StaticCaptchaProvider) CaptchaVerifyParam(context.Context, CaptchaScene) (string, error) {
	if p.Value == "" {
		return "", ErrNoCaptchaProvider
	}
	return p.Value, nil
}

// CaptchaScene 返回当前 Client 的默认验证码场景。
func (c *Client) CaptchaScene() CaptchaScene {
	return CaptchaScene{}.withDefaults(c.baseURL)
}

// CaptchaProvider 返回当前配置的 CaptchaProvider（可能为 nil）。
func (c *Client) CaptchaProvider() CaptchaProvider { return c.captcha }
