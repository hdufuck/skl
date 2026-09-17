package chromecaptcha

// 浏览器「自称」：让页面与风控看到一台**自洽**的浏览器。
//
// 起因（`har#4` 抓包，真实窗口）：探针每次铸造参数（InitCaptcha）和
// 上报设备指纹（cloudauth-device 的 Log2/Log3）都带着
//
//	user-agent: … HeadlessChrome/153.0.0.0 Safari/537.36
//	sec-ch-ua-platform: "macOS"  sec-ch-ua-mobile: ?0
//
// 而 headless=new 的屏幕是 **800×600 / dpr 1**、窗口是 430×932 ——
// 页面看到「视口（500×789）比屏幕（600）还高」这种物理上不可能的组合。
// 阿里云把这类组合点名过：F009「检测到虚拟设备环境……桌面浏览器模拟移动设备」。
//
// ⚠️ 这不是「已证的充分原因」：`har#3` 里一台真桌面 Edge 也先吃过一次 F001
// 才成功。所以这里只做一件事——**把能看见的自相矛盾去掉**，不去发明一台不存在的
// 硬件（WebGL renderer 依旧如实报 Apple M4）。
//
// 只改 UA 字符串是不行的：Chrome 在 `Emulation.setUserAgentOverride` **没有**
// `userAgentMetadata` 时会**停发全部 `Sec-CH-UA-*`**（本机实测），
// 于是矛盾从「UA 与平台不符」变成「一个现代 Chrome 却没有任何客户端提示」。
// 所以四者必须一起换：UA 字符串、客户端提示、屏幕几何、触摸能力。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Screen 是浏览器向页面自称的屏幕几何（CSS 像素，即 `window.screen` 看到的值）。
//
// 零值字段按 Profile 默认值补齐：桌面 1280×832 @2x（2560×1664 物理，常见
// MacBook 内建屏），手机 360×800 @3x（1080×2400 物理）。
type Screen struct {
	Width  int
	Height int
	// DeviceScaleFactor 是 devicePixelRatio；<= 0 时用 Profile 默认值。
	DeviceScaleFactor float64
}

// 默认自称的屏幕几何。
//
// 桌面取 1280×832（2560×1664 物理）—— 维护者这台机器真实的内建屏尺寸，所以它不是「编」
// 出来的；headless 默认的 800×600 才是假的（且会让视口比屏幕还高）。
// 换机器时改这三个常量即可（另一台机器的屏幕尺寸不同）。
//
// 手机取 430×932（iPhone 14 Pro Max 级别；就是 `har#4` 里探针那个“手机尺寸”窗口）。
// ⚠️ 别改小：本机实测宽度 < 393 时 Chrome 会自己缩视口（360×800 量出来是
// 368×818 / 缩放 0.978），又把 innerWidth 推到 screen.width 之上。
const (
	desktopScreenWidth  = 1280
	desktopScreenHeight = 832
	desktopScreenScale  = 2

	mobileScreenWidth  = 430
	mobileScreenHeight = 932
	mobileScreenScale  = 3
)

// 手机自称里的设备型号与系统版本。
//
// 刻意不用 Pixel / Galaxy：那是所有移动端模拟器的默认型号，反而是个特征。
// 这里用 `har#4` 里那台真正签到成功（T001）的手机。
const (
	mobileDeviceModel     = "2211133G"
	mobilePlatformVersion = "13"
	// mobilePlatform 是 Android Chrome 的 `navigator.platform`。
	mobilePlatform = "Linux armv8l"
	// mobileMaxTouchPoints 是 Android Chrome 的典型 `navigator.maxTouchPoints`。
	mobileMaxTouchPoints = 5
)

// mobileUserAgentTemplate 是内置的「一般移动端 Chrome」UA（%s = 本机 Chrome 主版本号）。
const mobileUserAgentTemplate = "Mozilla/5.0 (Linux; Android " + mobilePlatformVersion + "; " +
	mobileDeviceModel + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Mobile Safari/537.36"

// browserIdentity 是从真实浏览器里读出来的自称（覆盖**之前**）。
type browserIdentity struct {
	UserAgent   string `json:"userAgent"`
	Platform    string `json:"platform"` // navigator.platform
	InnerWidth  int    `json:"innerWidth"`
	InnerHeight int    `json:"innerHeight"`
	// Metadata 是 `navigator.userAgentData` 的高熵值；读不到时为 nil。
	Metadata *emulation.UserAgentMetadata `json:"metadata"`
}

// identityExpr 一次读出我们需要的真实自称。
//
// `getHighEntropyValues` 是异步的，调用方必须 await promise（见 identify）。
const identityExpr = `(async () => {
  const md = (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues)
    ? await navigator.userAgentData.getHighEntropyValues(
        ["platformVersion", "architecture", "model", "fullVersionList", "bitness", "wow64"])
    : null;
  return JSON.stringify({
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    metadata: md
  });
})()`

// identify 读出浏览器当前的真实自称。
//
// 必须先读再覆盖：覆盖时要把客户端提示原样给回去。
func identify(ctx context.Context) (browserIdentity, error) {
	var raw string
	awaitPromise := func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		return p.WithAwaitPromise(true)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(identityExpr, &raw, awaitPromise)); err != nil {
		return browserIdentity{}, fmt.Errorf("chromecaptcha: 读取浏览器自称失败: %w", err)
	}

	var got browserIdentity
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return browserIdentity{}, fmt.Errorf("chromecaptcha: 解析浏览器自称失败: %w", err)
	}
	return got, nil
}

// applyPresentation 把浏览器自称换成 Options 指定的形态，返回最终使用的 UA。
//
// 顺序无关紧要，但四件事必须一起做（见本文件开头）：UA、客户端提示、屏幕几何、触摸。
func applyPresentation(ctx context.Context, ident browserIdentity, opts Options) (string, error) {
	if ident.Metadata == nil {
		// 宁可什么都不做，也不要只改 UA 字符串：那会让 Chrome 停发全部
		// `Sec-CH-UA-*`，把一个矛盾换成另一个。现代 Chrome 不会走到这里。
		opts.Logf("chromecaptcha: 读不到 navigator.userAgentData，跳过自称覆盖（保持真实自称）")
		return ident.UserAgent, nil
	}

	ua := opts.UserAgent
	switch {
	case ua != "":
		// 调用方显式指定（例如仿钉钉那串 UA）。
	case opts.Mobile:
		major := chromeMajorVersion(ident.UserAgent, ident.Metadata)
		if major == "" {
			return "", fmt.Errorf("chromecaptcha: 无法从 UA %q 里解出 Chrome 主版本号，无法生成手机自称", ident.UserAgent)
		}
		ua = fmt.Sprintf(mobileUserAgentTemplate, major)
	default:
		ua = strings.ReplaceAll(ident.UserAgent, "HeadlessChrome", "Chrome")
	}

	platform := ident.Platform
	metadata := ident.Metadata
	if opts.Mobile {
		platform = mobilePlatform
		metadata = androidMetadata(ident.Metadata)
	}

	err := emulation.SetUserAgentOverride(ua).
		WithPlatform(platform).
		WithUserAgentMetadata(metadata).
		Do(ctx)
	if err != nil {
		return "", fmt.Errorf("chromecaptcha: 覆盖 UA 失败: %w", err)
	}

	screen := desktopScreen()
	if opts.Mobile {
		screen = mobileScreen()
	}
	screen = withScreenDefaults(screen, opts.Screen)

	viewportWidth, viewportHeight := int64(ident.InnerWidth), int64(ident.InnerHeight)
	if opts.Mobile {
		// 手机自称下视口就是屏幕：430×932 这种「窗口比屏幕大」的组合正是要避免的。
		viewportWidth, viewportHeight = int64(screen.Width), int64(screen.Height)
	}
	err = emulation.SetDeviceMetricsOverride(viewportWidth, viewportHeight,
		screen.DeviceScaleFactor, opts.Mobile).
		WithScreenWidth(int64(screen.Width)).
		WithScreenHeight(int64(screen.Height)).
		Do(ctx)
	if err != nil {
		return "", fmt.Errorf("chromecaptcha: 覆盖屏幕几何失败: %w", err)
	}

	if opts.Mobile {
		err = emulation.SetTouchEmulationEnabled(true).
			WithMaxTouchPoints(mobileMaxTouchPoints).
			Do(ctx)
		if err != nil {
			return "", fmt.Errorf("chromecaptcha: 打开触摸模拟失败: %w", err)
		}
	}
	return ua, nil
}

func desktopScreen() Screen {
	return Screen{Width: desktopScreenWidth, Height: desktopScreenHeight, DeviceScaleFactor: desktopScreenScale}
}

func mobileScreen() Screen {
	return Screen{Width: mobileScreenWidth, Height: mobileScreenHeight, DeviceScaleFactor: mobileScreenScale}
}

// withScreenDefaults 用 `fallback` 补齐 `want` 里没给的字段。
func withScreenDefaults(fallback, want Screen) Screen {
	out := fallback
	if want.Width > 0 {
		out.Width = want.Width
	}
	if want.Height > 0 {
		out.Height = want.Height
	}
	if want.DeviceScaleFactor > 0 {
		out.DeviceScaleFactor = want.DeviceScaleFactor
	}
	return out
}

// androidMetadata 把桌面自称的客户端提示改写成 Android 手机的。
//
// 品牌与版本列表原样保留（同一个 Chrome 版本在 Android 上发的就是同一组，
// 只有 GREASE 品牌的写法偶尔不同，属于噪声）；只换平台、型号与 mobile。
// architecture / bitness 在 Android 上本来就不上报，所以清空。
func androidMetadata(real *emulation.UserAgentMetadata) *emulation.UserAgentMetadata {
	out := *real
	out.Platform = "Android"
	out.PlatformVersion = mobilePlatformVersion
	out.Model = mobileDeviceModel
	out.Mobile = true
	out.Architecture = ""
	out.Bitness = ""
	out.Wow64 = false
	return &out
}

// chromeMajorVersion 取 Chrome 主版本号（「153」），优先从 UA 里解，其次看客户端提示。
func chromeMajorVersion(ua string, md *emulation.UserAgentMetadata) string {
	if _, rest, ok := strings.Cut(ua, "Chrome/"); ok {
		end := 0
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if major, _, ok := strings.Cut(rest[:end], "."); ok && major != "" {
			return major
		}
	}
	for _, b := range md.Brands {
		if b.Brand == "Google Chrome" || b.Brand == "Chromium" {
			return b.Version
		}
	}
	return ""
}
