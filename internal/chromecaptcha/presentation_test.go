package chromecaptcha

// 自称（presentation）的离线回归护栏。
//
// `har#4` 抓包复盘里唯一能看见的硬缺陷是：探针每次铸造参数（InitCaptcha）和
// 上报设备指纹（cloudauth-device）都带着 `HeadlessChrome/…` 与 headless 默认的
// 800×600 / dpr 1 屏幕，而窗口却是手机尺寸 —— 阿里云把「桌面浏览器模拟移动设备」
// 这类组合点名过（F009）。这些用例把「去掉自相矛盾」钉住，且不碰阿里云 CDN。

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// selfPresentation 是页面自己看到的环境。
type selfPresentation struct {
	UserAgent      string  `json:"userAgent"`
	Platform       string  `json:"platform"`
	Mobile         bool    `json:"mobile"`
	Brands         int     `json:"brands"`
	PlatformHint   string  `json:"platformHint"`
	MaxTouchPoints int     `json:"maxTouchPoints"`
	InnerWidth     int     `json:"innerWidth"`
	InnerHeight    int     `json:"innerHeight"`
	ScreenWidth    int     `json:"screenWidth"`
	ScreenHeight   int     `json:"screenHeight"`
	DPR            float64 `json:"dpr"`
}

const selfPresentationExpr = `JSON.stringify({
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  mobile: !!(navigator.userAgentData && navigator.userAgentData.mobile),
  brands: (navigator.userAgentData ? navigator.userAgentData.brands.length : 0),
  platformHint: (navigator.userAgentData ? navigator.userAgentData.platform : ""),
  maxTouchPoints: navigator.maxTouchPoints,
  innerWidth: window.innerWidth,
  innerHeight: window.innerHeight,
  screenWidth: screen.width,
  screenHeight: screen.height,
  dpr: window.devicePixelRatio
})`

func readSelfPresentation(t *testing.T, src *Source) selfPresentation {
	t.Helper()
	var raw string
	if err := chromedp.Run(src.ctx, chromedp.Evaluate(selfPresentationExpr, &raw)); err != nil {
		t.Fatalf("读取页面自称失败: %v", err)
	}
	var got selfPresentation
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("解析页面自称失败: %v（%s）", err, raw)
	}
	return got
}

// TestDesktopSelfPresentationHasNoHeadlessFingerprint 是主任务的回归护栏：
// 默认（桌面）自称里不许再出现 headless 标记，也不许出现「视口比屏幕还大」这种
// 物理上不可能的组合；同时客户端提示必须还在（只改 UA 字符串会让 Chrome
// **停发全部** `Sec-CH-UA-*`，把一个矛盾换成另一个）。
func TestDesktopSelfPresentationHasNoHeadlessFingerprint(t *testing.T) {
	src := newOfflineSource(t, Options{})
	got := readSelfPresentation(t, src)

	if strings.Contains(strings.ToLower(got.UserAgent), "headless") {
		t.Fatalf("UA 仍带 headless 标记（阿里云 F009 的「虚拟设备环境」特征）: %q", got.UserAgent)
	}
	if !strings.Contains(got.UserAgent, "Chrome/") {
		t.Fatalf("UA 不像 Chrome: %q", got.UserAgent)
	}
	if got.Brands == 0 || got.PlatformHint == "" {
		t.Fatalf("客户端提示没了（Sec-CH-UA-* 会整批消失）: %+v", got)
	}
	if got.Mobile {
		t.Fatalf("桌面自称不该是 mobile: %+v", got)
	}
	if got.MaxTouchPoints != 0 {
		t.Fatalf("桌面自称不该有触摸能力: %d", got.MaxTouchPoints)
	}
	if got.DPR < 1 {
		t.Fatalf("devicePixelRatio 不合理: %v", got.DPR)
	}
	if got.InnerWidth > got.ScreenWidth || got.InnerHeight > got.ScreenHeight {
		t.Fatalf("视口比屏幕还大（headless 默认的 800×600 屏幕就是这样）: inner=%d×%d screen=%d×%d",
			got.InnerWidth, got.InnerHeight, got.ScreenWidth, got.ScreenHeight)
	}
	if src.UserAgent() != got.UserAgent {
		t.Fatalf("Source.UserAgent() = %q，与页面看到的不一致（%q）", src.UserAgent(), got.UserAgent)
	}
}

// TestMobileSelfPresentation 锁住 `Mobile` 选项的四处联动：UA、客户端提示、
// 视口、触摸。只改其中一处都会留下新的矛盾。
func TestMobileSelfPresentation(t *testing.T) {
	src := newOfflineSource(t, Options{Mobile: true})
	got := readSelfPresentation(t, src)

	if !strings.Contains(got.UserAgent, "Android") || !strings.Contains(got.UserAgent, "Mobile Safari") {
		t.Fatalf("UA 不是移动端 Chrome: %q", got.UserAgent)
	}
	if strings.Contains(strings.ToLower(got.UserAgent), "headless") {
		t.Fatalf("UA 仍带 headless 标记: %q", got.UserAgent)
	}
	if !got.Mobile || got.PlatformHint != "Android" {
		t.Fatalf("客户端提示仍是桌面: mobile=%v platform=%q", got.Mobile, got.PlatformHint)
	}
	if got.MaxTouchPoints == 0 {
		t.Fatal("手机自称没有触摸能力")
	}
	if got.InnerWidth != mobileScreenWidth || got.InnerHeight != mobileScreenHeight {
		t.Fatalf("视口 = %d×%d，want %d×%d", got.InnerWidth, got.InnerHeight, mobileScreenWidth, mobileScreenHeight)
	}
	if got.ScreenWidth != mobileScreenWidth || got.ScreenHeight != mobileScreenHeight {
		t.Fatalf("屏幕 = %d×%d，want %d×%d", got.ScreenWidth, got.ScreenHeight, mobileScreenWidth, mobileScreenHeight)
	}
	if got.DPR != mobileScreenScale {
		t.Fatalf("devicePixelRatio = %v，want %v", got.DPR, mobileScreenScale)
	}
	if want := mobilePlatform; got.Platform != want {
		t.Fatalf("navigator.platform = %q，want %q", got.Platform, want)
	}
	if src.UserAgent() != got.UserAgent {
		t.Fatalf("Source.UserAgent() = %q，与页面看到的不一致（%q）", src.UserAgent(), got.UserAgent)
	}
}

// TestSelfPresentationHonoursExplicitOverrides 保证逃生舱还在：
// 调用方可以塞一串现成的 UA（例如手机端钉钉那串）并指定屏幕几何。
func TestSelfPresentationHonoursExplicitOverrides(t *testing.T) {
	const dingtalk = "Mozilla/5.0 (Linux; U; Android 13; zh-CN; 2211133G Build/TKQ1.220905.001) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 " +
		"UWS/5.12.5.0 Mobile Safari/537.36 AliApp(DingTalk/7.6.30)"
	src := newOfflineSource(t, Options{
		UserAgent: dingtalk,
		Mobile:    true,
		Screen:    Screen{Width: 412, Height: 915},
	})
	got := readSelfPresentation(t, src)

	if got.UserAgent != dingtalk {
		t.Fatalf("UA = %q，want %q（显式覆盖必须原样使用）", got.UserAgent, dingtalk)
	}
	if got.ScreenWidth != 412 || got.ScreenHeight != 915 {
		t.Fatalf("屏幕 = %d×%d，want 412×915", got.ScreenWidth, got.ScreenHeight)
	}
	if got.InnerWidth != 412 || got.InnerHeight != 915 {
		t.Fatalf("视口 = %d×%d，want 412×915（手机自称下视口就是屏幕）", got.InnerWidth, got.InnerHeight)
	}
	if got.DPR != mobileScreenScale {
		t.Fatalf("没给的字段应当回落到 Profile 默认值: dpr = %v，want %v", got.DPR, mobileScreenScale)
	}
}

// stubOptions 给离线用例补上「不依赖真阿里云」的默认参数。
func stubOptions(t *testing.T, opts Options) Options {
	t.Helper()
	if opts.ChromePath == "" {
		opts.ChromePath = testChromePath(t)
	}
	if !opts.Headless {
		opts.Headless = true
	}
	if opts.UserDataDir == "" {
		opts.UserDataDir = filepath.Join(t.TempDir(), "chrome-profile")
	}
	if opts.StartupTimeout == 0 {
		opts.StartupTimeout = 60 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = t.Logf
	}
	if opts.Fulfill == nil {
		opts.Fulfill = stubFulfill
	}
	if opts.FingerprintGrace == 0 {
		opts.FingerprintGrace = time.Millisecond
	}
	if opts.FingerprintSettle == 0 {
		opts.FingerprintSettle = time.Millisecond
	}
	return opts
}

// newOfflineSource 用桩 SDK 预热一个浏览器；用完自动关闭。
func newOfflineSource(t *testing.T, opts Options) *Source {
	t.Helper()
	src, err := New(context.Background(), stubOptions(t, opts))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src
}

// stubFulfill 把官方 `AliyunCaptcha.js` 换成桩，其余放行。
func stubFulfill(rawURL string) (string, string, bool) {
	if strings.Contains(rawURL, "AliyunCaptcha") {
		return "application/javascript", stubSDK, true
	}
	return "", "", false
}
