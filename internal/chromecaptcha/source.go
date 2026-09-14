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
}

// Source 是一个已预热、随时可取参的浏览器来源。
type Source struct {
	cancelPage  context.CancelFunc
	cancelAlloc context.CancelFunc
	ctx         context.Context

	trigger string
	timeout time.Duration
	logf    func(format string, args ...any)

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

	readyCtx, cancelReady := context.WithTimeout(pageCtx, opts.StartupTimeout)
	defer cancelReady()

	if err := chromedp.Run(readyCtx,
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
		}),
		chromedp.Navigate(pageURL),
	); err != nil {
		s.Close()
		return nil, fmt.Errorf("chromecaptcha: 加载极简页失败: %w", err)
	}

	if err := s.waitReady(readyCtx); err != nil {
		s.Close()
		return nil, err
	}
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
		rid := e.RequestID
		go func() {
			err := fetch.FulfillRequest(rid, 200).
				WithResponseHeaders([]*fetch.HeaderEntry{
					{Name: "Content-Type", Value: "text/html; charset=utf-8"},
				}).
				WithBody(body).
				Do(exec)
			if err != nil {
				s.logf("chromecaptcha: 交付极简页失败: %v", err)
			}
		}()
		return
	}

	rid := e.RequestID
	go func() { _ = fetch.ContinueRequest(rid).Do(exec) }()
}

// waitReady 等待页面上的 SDK 初始化标志。
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

	// 清掉上一轮的值，避免拿到旧参数。
	_ = chromedp.Run(ctx, chromedp.Evaluate(`window.__captchaVerifyParam = ""; true`, nil))

	// 受信任点击（Input.dispatchMouseEvent），不是 JS 合成事件。
	if err := chromedp.Run(ctx, chromedp.Click(s.trigger, chromedp.ByQuery)); err != nil {
		return "", fmt.Errorf("chromecaptcha: 触发验证码失败: %w", err)
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if p := s.readParam(ctx); p != "" {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("chromecaptcha: 等待 captchaVerifyParam 超时: %w", ctx.Err())
		case <-ticker.C:
		}
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
      getInstance: function () { window.__instance = true; },
      slideStyle: { width: 360, height: 50 },
      language: "cn"
    });
    window.__sdkReady = true;
  } catch (e) { window.__sdkErr = "" + e; }
})();
</script>
</body></html>`
}
