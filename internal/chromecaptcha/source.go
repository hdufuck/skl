// Package chromecaptcha 用浏览器自动化驱动阿里云验证码官方 SDK，产出一个真实的
// captchaVerifyParam。
//
// 它不重实现任何风控协议：页面加载的是官方 `AliyunCaptcha.js`，参数由 SDK 在
// `captchaVerifyCallback` 里透出。页面内容是我们自己写的极简页，但通过
// CDP `Fetch.fulfillRequest` 交付在**真实源** `https://skl.hdu.edu.cn/index.html`
// 下，以满足 SDK 的场景/域名绑定。
//
// 触发用的是 CDP 输入事件（受信任点击），而不是 JS 的 `el.click()`，
// 以降低被风控判为「自动化脚本模拟点击」的风险。
package chromecaptcha

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/hdufuck/skl"
)

// pageURL 是我们在真实源上交付极简页的地址。
const pageURL = "https://skl.hdu.edu.cn/index.html"

// defaultChromePath 是 macOS 上 Chrome 的常见位置。
const defaultChromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

// clickRetryAfter 是「点了没反应就补点一次」的等待阈值。
//
// 正常情况点击后 100–200ms 就有参数，所以 3s 还没出基本等于这次点击丢了。
const clickRetryAfter = 3 * time.Second

// Options 配置浏览器来源。
type Options struct {
	// ChromePath 是浏览器可执行文件；为空时依次尝试 $CHROME、常见路径。
	ChromePath string
	// Headless 为 true 时用 headless=new（默认）。
	Headless bool
	// UserDataDir 复用持久化 profile，让设备指纹「热」起来。
	UserDataDir string
	// SceneID / Prefix 默认取 skl 的硬编码值。
	SceneID string
	Prefix  string
	// StartupTimeout 是等待 SDK 初始化完成的预算（默认 60s）。
	StartupTimeout time.Duration
	// Logf 是可选的日志输出。
	Logf func(format string, args ...any)

	// Fulfill 让调用方在真实源下额外接管某些 URL 的响应体（返回 false 表示放行）。
	//
	// 生产路径不需要它。离线测试用它把官方 SDK 脚本换成桩，从而不依赖阿里云 CDN
	// 也能走完「预热 → 点触发 → 取参」的真实链路。返回值是明文，内部按 CDP 要求
	// 做 base64。
	Fulfill func(rawURL string) (contentType, body string, ok bool)
}

// Source 是一个已预热、随时可取参的浏览器来源。
type Source struct {
	cancelPage  context.CancelFunc
	cancelAlloc context.CancelFunc
	ctx         context.Context

	trigger string
	timeout time.Duration
	logf    func(format string, args ...any)
	fulfill func(rawURL string) (contentType, body string, ok bool)

	mu        sync.Mutex
	fromNet   string
	pageReady bool
}

// New 启动浏览器、交付极简页并等待 SDK 初始化完成。返回的 Source 已经是
// 「预热好但还没点触发」的状态，真正取参发生在 Param。
func New(ctx context.Context, opts Options) (*Source, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.StartupTimeout <= 0 {
		opts.StartupTimeout = 60 * time.Second
	}
	if opts.SceneID == "" {
		opts.SceneID = skl.DefaultCaptchaSceneID
	}
	if opts.Prefix == "" {
		opts.Prefix = skl.DefaultCaptchaPrefix
	}

	chrome := opts.ChromePath
	if chrome == "" {
		chrome = os.Getenv("CHROME")
	}
	if chrome == "" {
		chrome = defaultChromePath
	}
	if _, err := os.Stat(chrome); err != nil {
		return nil, fmt.Errorf("chromecaptcha: 找不到浏览器 %q: %w", chrome, err)
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chrome),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("excludeSwitches", "enable-automation"),
		chromedp.WindowSize(430, 932),
	)
	if opts.Headless {
		allocOpts = append(allocOpts, chromedp.Flag("headless", "new"))
	} else {
		allocOpts = append(allocOpts, chromedp.Flag("headless", false))
	}
	if opts.UserDataDir != "" {
		allocOpts = append(allocOpts, chromedp.UserDataDir(opts.UserDataDir))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	pageCtx, cancelPage := chromedp.NewContext(allocCtx)

	s := &Source{
		cancelPage:  cancelPage,
		cancelAlloc: cancelAlloc,
		ctx:         pageCtx,
		trigger:     "#captcha-trigger-btn",
		timeout:     opts.StartupTimeout,
		logf:        opts.Logf,
	}

	html := renderPage(opts.SceneID, opts.Prefix)
	body := base64.StdEncoding.EncodeToString([]byte(html))
	s.fulfill = opts.Fulfill

	chromedp.ListenTarget(pageCtx, func(ev any) {
		switch e := ev.(type) {
		case *fetch.EventRequestPaused:
			s.handlePaused(e, body)
		case *network.EventRequestWillBeSent:
			if !strings.Contains(e.Request.URL, skl.PathSignInCaptchaVerify) {
				return
			}
			u, err := url.Parse(e.Request.URL)
			if err != nil {
				return
			}
			if p := u.Query().Get("captchaVerifyParam"); p != "" {
				s.mu.Lock()
				s.fromNet = p
				s.mu.Unlock()
			}
		}
	})

	// 首次 Run 必须直接跑在 pageCtx（浏览器自己的生命周期 ctx）上。
	//
	// chromedp 用 exec.CommandContext(ctx) 启动 Chrome：谁取消了这个 ctx，谁就杀掉
	// 整个浏览器。所以启动预算**不能**表达成「挂在首次 Run 上的子 ctx」——那样
	// New 一返回（defer cancel 释放预算）浏览器就没了，之后每一档都只能拿到
	// context canceled（真值档恒为 transport_error）。
	//
	// 预算改由看门狗施加：超时才 Close，让 Run 以 ctx 取消的方式结束。
	watchdog := time.AfterFunc(opts.StartupTimeout, func() {
		opts.Logf("chromecaptcha: 启动预算 %s 用尽，关闭浏览器", opts.StartupTimeout)
		_ = s.Close()
	})
	defer watchdog.Stop()

	if err := chromedp.Run(pageCtx,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
		}),
		chromedp.Navigate(pageURL),
	); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("chromecaptcha: 加载极简页失败: %w", err)
	}

	if err := s.waitReady(pageCtx); err != nil {
		_ = s.Close()
		return nil, err
	}
	watchdog.Stop()
	opts.Logf("chromecaptcha: 官方验证码 SDK 已就绪（sceneId=%s prefix=%s）", opts.SceneID, opts.Prefix)
	return s, nil
}

// handlePaused 在真实源下交付我们的极简页，其余请求一律放行。
//
// ListenTarget 的回调是同步执行的，所以这里必须另起 goroutine 发 CDP 命令，
// 否则会死锁。
func (s *Source) handlePaused(e *fetch.EventRequestPaused, body string) {
	target := chromedp.FromContext(s.ctx)
	if target == nil || target.Target == nil {
		s.logf("chromecaptcha: 尚无 target，无法处理暂停请求 %s", e.Request.URL)
		return
	}
	exec := cdp.WithExecutor(s.ctx, target.Target)

	if strings.HasPrefix(e.Request.URL, pageURL) {
		s.fulfillAsync(exec, e.Request.URL, e.RequestID, "text/html; charset=utf-8", body)
		return
	}

	if s.fulfill != nil {
		if contentType, raw, ok := s.fulfill(e.Request.URL); ok {
			s.fulfillAsync(exec, e.Request.URL, e.RequestID, contentType,
				base64.StdEncoding.EncodeToString([]byte(raw)))
			return
		}
	}

	rid := e.RequestID
	go func() { _ = fetch.ContinueRequest(rid).Do(exec) }()
}

// fulfillAsync 交付一个响应体。body 需已 base64 编码（CDP 的要求）。
func (s *Source) fulfillAsync(ctx context.Context, rawURL string, rid fetch.RequestID, contentType, body string) {
	go func() {
		err := fetch.FulfillRequest(rid, 200).
			WithResponseHeaders([]*fetch.HeaderEntry{
				{Name: "Content-Type", Value: contentType},
			}).
			WithBody(body).
			Do(ctx)
		if err != nil {
			s.logf("chromecaptcha: 交付 %s 失败: %v", rawURL, err)
		}
	}()
}

// waitReady 等待页面上的就绪标志（由 `getInstance` 置位）：等到它才算「可以点了」。
func (s *Source) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(s.timeout)
	for {
		var ready bool
		err := chromedp.Run(ctx, chromedp.Evaluate(`!!window.__sdkReady`, &ready))
		if err == nil && ready {
			s.mu.Lock()
			s.pageReady = true
			s.mu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			var sdkErr string
			_ = chromedp.Run(ctx, chromedp.Evaluate(`window.__sdkErr || ""`, &sdkErr))
			if sdkErr != "" {
				return fmt.Errorf("chromecaptcha: SDK 初始化失败: %s", sdkErr)
			}
			return errors.New("chromecaptcha: 等待 SDK 初始化超时")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("chromecaptcha: 等待 SDK 初始化被取消: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Param 点击触发按钮，等 SDK 静默完成验证后返回一个真值 captchaVerifyParam。
//
// ctx 的 deadline 决定等待预算；参数是一次性的，拿到后应立刻使用。
func (s *Source) Param(ctx context.Context) (string, error) {
	s.mu.Lock()
	s.fromNet = ""
	ready := s.pageReady
	s.mu.Unlock()
	if !ready {
		return "", errors.New("chromecaptcha: 页面尚未就绪")
	}

	// 关键：chromedp 的 action 必须跑在**浏览器自己的 context**（New 时创建）上，
	// 不能直接用调用方的 context，否则 chromedp 会报 invalid context。
	// 这里把调用方的 deadline / 取消叠加上去。
	bctx, cancel := s.browserContext(ctx)
	defer cancel()

	// 清掉上一轮的值，避免拿到旧参数。
	_ = chromedp.Run(bctx, chromedp.Evaluate(`window.__captchaVerifyParam = ""; true`, nil))

	// 受信任点击（Input.dispatchMouseEvent），不是 JS 合成事件。
	if err := s.click(bctx); err != nil {
		return "", fmt.Errorf("chromecaptcha: 触发验证码失败: %w", err)
	}

	// 实测：就绪之后点击 → 100–200ms 出参。若过了 clickRetryAfter 还没出，多半是
	// 这一次点击落在 SDK 绑定处理器之前被杀掉了（风控 SDK 的初始化是异步的），
	// 补点一次。只补一次：既不把预算耗在连点上，也少一分被判 F024 的风险。
	retryAt := time.Now().Add(clickRetryAfter)
	retried := false

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if p := s.readParam(bctx); p != "" {
			return p, nil
		}
		if !retried && time.Now().After(retryAt) {
			retried = true
			s.logf("chromecaptcha: 点击后 %s 仍未出参，补点一次", clickRetryAfter)
			if err := s.click(bctx); err != nil {
				return "", fmt.Errorf("chromecaptcha: 触发验证码失败: %w", err)
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("chromecaptcha: 等待 captchaVerifyParam 超时: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// click 用受信任的 CDP 输入事件点一次触发按钮。
func (s *Source) click(ctx context.Context) error {
	return chromedp.Run(ctx, chromedp.Click(s.trigger, chromedp.ByQuery))
}

// browserContext 把调用方的 deadline / 取消叠加到浏览器 context 上。
func (s *Source) browserContext(ctx context.Context) (context.Context, context.CancelFunc) {
	var (
		bctx   context.Context
		cancel context.CancelFunc
	)
	if deadline, ok := ctx.Deadline(); ok {
		bctx, cancel = context.WithDeadline(s.ctx, deadline)
	} else {
		bctx, cancel = context.WithCancel(s.ctx)
	}
	stop := context.AfterFunc(ctx, cancel)
	return bctx, func() {
		stop()
		cancel()
	}
}

func (s *Source) readParam(ctx context.Context) string {
	s.mu.Lock()
	fromNet := s.fromNet
	s.mu.Unlock()
	if fromNet != "" {
		return fromNet
	}
	var v string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`window.__captchaVerifyParam || ""`, &v)); err != nil {
		return ""
	}
	return v
}

// Close 关闭浏览器。
func (s *Source) Close() error {
	if s.cancelPage != nil {
		s.cancelPage()
	}
	if s.cancelAlloc != nil {
		s.cancelAlloc()
	}
	return nil
}

// renderPage 生成极简验证码页：加载官方 SDK，回调里把参数存到全局变量。
func renderPage(sceneID, prefix string) string {
	return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>skl</title></head>
<body>
<div id="captcha-container"></div>
<button id="captcha-trigger-btn" style="width:360px;height:50px">verify</button>
<script src="` + skl.AliyunCaptchaScriptURL + `"></script>
<script>
(function () {
  try {
    window.initAliyunCaptcha({
      SceneId: "` + sceneID + `",
      prefix: "` + prefix + `",
      mode: "popup",
      element: "#captcha-container",
      button: "#captcha-trigger-btn",
      captchaVerifyCallback: function (captchaVerifyParam) {
        window.__captchaVerifyParam = captchaVerifyParam;
        window.__captchaAt = Date.now();
        return { captchaResult: true, bizResult: true };
      },
      onBizResultCallback: function () { window.__bizResult = true; },
      // getInstance 是 SDK 把「构造完成的实例」交回来的时刻：它在 init / bindEvents
      // 之后才回调（实测 init 后 300–550ms）。**只有到这时触发按钮才真正绑上点击
      // 处理**，更早的点击会被直接丢掉（表现为点了没反应、取参一路超时，真值档
      // 于是退化成 transport_error）。就绪标志必须在这里置位，不能像以前那样在
      // initAliyunCaptcha 返回后同步置位。
      getInstance: function (instance) {
        window.__captchaInstance = instance;
        window.__sdkReady = true;
      },
      slideStyle: { width: 360, height: 50 },
      language: "cn"
    });
  } catch (e) { window.__sdkErr = "" + e; }
})();
</script>
</body></html>`
}
