package chromecaptcha

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// stubSDK 是官方 `AliyunCaptcha.js` 的桩：只保留「初始化 → 交回实例 → 点触发
// 按钮才回调」三个被我们用到的契约（见 docs/signin-probe.md 附录 A）。
//
// 关键是**忠实复刻官方 SDK 的异步时序**：`initAliyunCaptcha` 返回时点击处理
// 还没绑上，SDK 要过一会儿才通过 `getInstance` 把构造完成的实例交回。
// 就绪信号必须挂在这一刻，挂早了点击就会被丢掉。
//
// 有了它，`New` → `Param` 这条真实链路可以完全离线跑：不碰阿里云 CDN，也不依赖
// skl 站点。参数串内容不重要，重要的是它来自 callback。
// 桩把「绑定点击处理」拖到 stubSDKBindDelay，就是为了让「New 提前返回」暴露出来：
// 延迟必须大于浏览器启动时间（实测 ~1.2s），否则同步置的就绪标志也能蒙混过关。
const stubSDKBindDelay = 3 * time.Second

var stubSDK = fmt.Sprintf(`
window.initAliyunCaptcha = function (opts) {
  window.__initOpts = opts;
  setTimeout(function () {
    var btn = document.querySelector(opts.button);
    btn.addEventListener("click", function () {
      opts.captchaVerifyCallback("STUB-CAPTCHA-PARAM");
    });
    if (opts.getInstance) {
      opts.getInstance({ stub: true });
    }
  }, %d);
};
`, stubSDKBindDelay/time.Millisecond)

// testChromePath 返回可用的 Chrome；没有就跳过（浏览器用例不是所有环境都能跑）。
func testChromePath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("CHROME")
	if path == "" {
		path = defaultChromePath
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("找不到 Chrome（%v），跳过浏览器用例", err)
	}
	return path
}

// TestNewKeepsBrowserAliveUntilParam 锁死两个曾经让真值档恒为 transport_error 的
// 回归，它们都会让演练表格里那一格变成一个「-」：
//
//  1. **浏览器生命周期**：chromedp 用 `exec.CommandContext(ctx)` 启动 Chrome，
//     **首次 Run 的 ctx 就是浏览器的生命周期**。旧实现把首次 Run 挂在一个带启动
//     预算的子 ctx 上、并在 New 返回时 `defer cancelReady()`，于是浏览器在 New
//     一返回就被杀，档 5 随后只能拿到「触发验证码失败: context canceled」。
//  2. **就绪信号是假的**：旧实现把 `window.__sdkReady` 同步设在
//     `initAliyunCaptcha` 返回之后，而 SDK 要等 `init`/`bindEvents` 跑完、通过
//     `getInstance` 交回实例（实测 300–550ms）才真正绑上点击处理。挂早了就等于
//     New 假装预热好了，T0 后的第一次点击落在空处。
//
// 这里刻意在 New 与 Param 之间留一段间隔，模拟「T0 前预热、T0 后才取参」的真实
// 时序；并用桩 SDK 的绑定延迟断言 New 确实等到了实例。
func TestNewKeepsBrowserAliveUntilParam(t *testing.T) {
	src, err := New(context.Background(), Options{
		ChromePath:     testChromePath(t),
		Headless:       true,
		UserDataDir:    filepath.Join(t.TempDir(), "chrome-profile"),
		StartupTimeout: 60 * time.Second,
		Logf:           t.Logf,
		Fulfill: func(rawURL string) (string, string, bool) {
			if strings.Contains(rawURL, "AliyunCaptcha") {
				return "application/javascript", stubSDK, true
			}
			return "", "", false
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = src.Close() }()

	// 就绪信号必须是 getInstance（SDK 交回实例）那一刻：New 返回时实例就该在页面上。
	// 桩刻意把绑定拖到 stubSDKBindDelay，Old 实现（同步置位）会在这里先红。
	var hasInstance bool
	if err := chromedp.Run(src.ctx, chromedp.Evaluate(`!!window.__captchaInstance`, &hasInstance)); err != nil {
		t.Fatalf("读取实例状态: %v", err)
	}
	if !hasInstance {
		t.Fatal("New 返回时 SDK 还没交回实例（就绪信号是假的，T0 后第一次点击会落空）")
	}

	// 真实时序：预热发生在 T0 之前，取参发生在 T0 之后。
	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := src.Param(ctx)
	if err != nil {
		t.Fatalf("Param 在 New 返回后失败（真值档会退化成 transport_error）: %v", err)
	}
	if got != "STUB-CAPTCHA-PARAM" {
		t.Fatalf("captchaVerifyParam = %q, want %q", got, "STUB-CAPTCHA-PARAM")
	}
}

// TestNewStartupBudgetStillApplies 保证修掉生命周期问题之后，启动预算本身没有失效：
// 页面卡住时必须让 New 报错返回，而不是无限期挂着（窗口内挂死 = 白丢一次机会）。
func TestNewStartupBudgetStillApplies(t *testing.T) {
	// 桩 SDK 永久占住渲染线程：页面永远到不了「SDK 已就绪」，waitReady 会一直
	// 阻塞在自己的 Evaluate 上。只有看门狗能把它救出来。
	start := time.Now()
	src, err := New(context.Background(), Options{
		ChromePath:     testChromePath(t),
		Headless:       true,
		UserDataDir:    filepath.Join(t.TempDir(), "chrome-profile"),
		StartupTimeout: 2 * time.Second,
		Logf:           t.Logf,
		Fulfill: func(rawURL string) (string, string, bool) {
			if strings.Contains(rawURL, "AliyunCaptcha") {
				return "application/javascript", "for(;;){}", true
			}
			return "", "", false
		},
	})
	if err == nil {
		_ = src.Close()
		t.Fatal("页面卡死时 New 应当报错")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("启动预算失效：New 用了 %s 才返回（预算是 2s）", elapsed)
	}
	t.Logf("New 按预算返回: %v（用时 %s）", err, time.Since(start).Round(time.Millisecond))
}
