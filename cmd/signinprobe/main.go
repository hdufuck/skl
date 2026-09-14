// Command signinprobe 是一次性签到探针：在真实有效的签到码窗口内，按
// 「不需要人机验证 → 需要人机验证」的顺序各打一档，尽可能一次拿全结论。
//
// 用法与操作步骤见 docs/signin-probe.md。**不要在窗口之前临时学习它**，
// 所有预置（登录、读回预热、浏览器预热、Reqable 上报）都在 T0 之前完成。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hdufuck/skl"
	"github.com/hdufuck/skl/internal/chromecaptcha"
	"github.com/hdufuck/skl/internal/probe"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "signinprobe:", err)
		os.Exit(1)
	}
}

type options struct {
	user   string
	pass   string
	token  string
	base   string
	lat    float64
	lon    float64
	code   string
	sample string

	headed     bool
	profile    string
	noBrowser  bool
	hookAddr   string
	outDir     string
	keepWrites bool

	ladderDeadline  time.Duration
	captchaDeadline time.Duration
	gateTimeout     time.Duration
	hookWait        time.Duration
}

func run() error {
	var opt options
	fs := flag.NewFlagSet("signinprobe", flag.ContinueOnError)
	fs.StringVar(&opt.user, "user", envOr("HDU_USER", ""), "CAS/SSO 账号（默认 $HDU_USER）")
	fs.StringVar(&opt.pass, "pass", envOr("HDU_PASS", envOr("HDU_PASSWORD", "")), "CAS/SSO 密码（默认 $HDU_PASS）")
	fs.StringVar(&opt.token, "token", os.Getenv("SKL_TOKEN"), "已有的 session token（可跳过登录）")
	fs.StringVar(&opt.base, "base", "", "覆盖站点根地址（默认 https://skl.hdu.edu.cn）")
	fs.Float64Var(&opt.lat, "lat", envFloat("SKL_LAT", 30.313816), "签到定位纬度")
	fs.Float64Var(&opt.lon, "lon", envFloat("SKL_LON", 120.343228), "签到定位经度")
	fs.StringVar(&opt.code, "code", "", "4 位签到码；留空则交互输入")
	fs.StringVar(&opt.sample, "sample-file", "", "含真实 captchaVerifyParam 的 HAR/文本，用于让伪造值等长；留空则自动在 *.har 里找")

	fs.BoolVar(&opt.headed, "headed", false, "用可见窗口跑 Chrome（默认 headless=new）")
	fs.StringVar(&opt.profile, "profile", "", "Chrome 持久化 profile 目录")
	fs.BoolVar(&opt.noBrowser, "no-browser", false, "跳过浏览器真值档（只跑档 1–4）")
	fs.StringVar(&opt.hookAddr, "hook", ":8080", "Reqable 上报服务器监听地址；空串关闭")
	fs.StringVar(&opt.outDir, "out", "probe-results", "报告输出目录")
	fs.BoolVar(&opt.keepWrites, "continue-after-write", false, "检测到写入后不再询问、继续跑完（默认停）")

	fs.DurationVar(&opt.ladderDeadline, "ladder-deadline", 8*time.Second, "档 1–4 的墙钟预算")
	fs.DurationVar(&opt.captchaDeadline, "captcha-deadline", 23*time.Second, "真值档的墙钟预算")
	fs.DurationVar(&opt.gateTimeout, "gate-timeout", 5*time.Second, "写入后交互闸的倒计时")
	fs.DurationVar(&opt.hookWait, "hook-wait", 10*time.Second, "等待手机 HAR 上报的时长")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	ctx := context.Background()
	in := bufio.NewReader(os.Stdin)

	// ---------- 预置（T0 之前全部完成）----------
	rec := probe.NewRecorder(nil)
	clientOpts := []skl.Option{
		skl.WithTransport(rec),
		skl.WithTimeout(20 * time.Second),
	}
	if opt.base != "" {
		clientOpts = append(clientOpts, skl.WithBaseURL(opt.base))
	}
	if opt.token != "" {
		clientOpts = append(clientOpts, skl.WithToken(opt.token))
	}
	if opt.user != "" && opt.pass != "" {
		clientOpts = append(clientOpts, skl.WithCredentials(opt.user, opt.pass))
	}

	client, err := skl.NewClient(clientOpts...)
	if err != nil {
		return err
	}

	loginCtx, cancelLogin := context.WithTimeout(ctx, 3*time.Minute)
	defer cancelLogin()

	if client.HasCredentials() {
		logf("登录中（CAS/SSO）…")
		if err := client.Login(loginCtx); err != nil {
			return fmt.Errorf("登录失败: %w", err)
		}
	}

	user, err := client.UserInfo(loginCtx)
	if err != nil {
		return fmt.Errorf("读取用户信息失败（token 可能已失效，且没有可用的账号密码重新登录）: %w", err)
	}
	logf("已登录：%s（%s）", user.UserName, probe.MaskID(user.ID))

	baseline, err := probe.ReadBackToday(client)(loginCtx)
	if err != nil {
		return fmt.Errorf("读回预热失败（窗口内第一次解析失败就等于浪费机会）: %w", err)
	}
	logf("读回预热成功：今日签到明细 %d 条（基线）", baseline.Count)

	sample := opt.sample
	if sample == "" {
		sample = discoverSampleParam(".")
		if sample != "" {
			logf("已从本地 *.har 找到真实 captchaVerifyParam 样本，伪造值将等长")
		} else {
			logf("未找到真实样本，伪造值将使用内置字段长度")
		}
	} else if !strings.HasPrefix(strings.TrimSpace(sample), "{") {
		data, readErr := os.ReadFile(sample)
		if readErr != nil {
			return fmt.Errorf("读取 sample-file 失败: %w", readErr)
		}
		extracted := extractParam(string(data))
		if extracted == "" {
			return errors.New("sample-file 里没有找到 captchaVerifyParam")
		}
		sample = extracted
	}

	profile := opt.profile
	if profile == "" {
		// 默认复用持久化 profile，让设备指纹「热」起来；--profile 可覆盖。
		if cache, err := os.UserCacheDir(); err == nil {
			profile = filepath.Join(cache, "signinprobe", "chrome-profile")
		}
	}

	var captchaSource probe.CaptchaParamSource
	if !opt.noBrowser {
		browserCtx, cancelBrowser := context.WithCancel(ctx)
		defer cancelBrowser()
		src, err := chromecaptcha.New(browserCtx, chromecaptcha.Options{
			Headless:    !opt.headed,
			UserDataDir: profile,
			Logf:        logf,
		})
		if err != nil {
			return fmt.Errorf("浏览器预热失败: %w", err)
		}
		captchaSource = src
		defer func() { _ = src.Close() }()
	}

	var hookCh chan probe.Entry
	if opt.hookAddr != "" {
		ln, err := net.Listen("tcp", opt.hookAddr)
		if err != nil {
			return fmt.Errorf("hook 监听 %s 失败（用 --hook \"\" 关闭）: %w", opt.hookAddr, err)
		}
		hookCh = make(chan probe.Entry, 4)
		srv := &http.Server{Handler: probe.NewHookHandler(hookCh, logf), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()

		addr := opt.hookAddr
		_, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			port = "8080"
		}
		fmt.Fprintf(os.Stderr, "[probe] Reqable 上报服务器地址（按你的抓包模式二选一）：\n")
		fmt.Fprintf(os.Stderr, "[probe]   协同模式（配在电脑端 Reqable）: http://127.0.0.1:%s/hook\n", port)
		fmt.Fprintf(os.Stderr, "[probe]   独立模式（配在手机端 Reqable）: http://%s:%s/hook\n", lanIP(), port)
		fmt.Fprintf(os.Stderr, "[probe]   配置步骤见 docs/signin-probe.md §4.3\n")
	}

	// ---------- T0 ----------
	code := strings.TrimSpace(opt.code)
	if code == "" {
		code, err = promptCode(in, os.Stderr)
		if err != nil {
			return err
		}
	}
	if !isFourDigits(code) {
		return fmt.Errorf("签到码 %q 不是 4 位数字", code)
	}

	logf("T0=%s 开始阶梯（Ladder≤%s / 真值≤%s）", time.Now().Format("15:04:05"),
		opt.ladderDeadline, opt.captchaDeadline)

	prompter := &cliPrompter{in: in, out: os.Stderr}
	rep, err := probe.Run(ctx, probe.Config{
		Client:             client,
		Recorder:           rec,
		Code:               code,
		UserID:             user.ID,
		Coord:              probe.Coord{Lat: opt.lat, Lon: opt.lon},
		Sample:             sample,
		Captcha:            captchaSource,
		SkipGenuine:        opt.noBrowser,
		Prompter:           prompter,
		Logf:               logf,
		ReadBack:           probe.ReadBackToday(client),
		Baseline:           &baseline,
		Hook:               hookCh,
		LadderDeadline:     opt.ladderDeadline,
		CaptchaDeadline:    opt.captchaDeadline,
		GateTimeout:        opt.gateTimeout,
		HookWait:           opt.hookWait,
		ContinueAfterWrite: opt.keepWrites,
	})
	if err != nil {
		return err
	}

	// ---------- 落盘 ----------
	if err := os.MkdirAll(opt.outDir, 0o755); err != nil {
		return err
	}
	stamp := time.Now().Format("20060102-150405")
	jsonPath := filepath.Join(opt.outDir, stamp+".json")
	mdPath := filepath.Join(opt.outDir, stamp+".md")

	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, raw, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(mdPath, []byte(rep.Markdown()), 0o600); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, rep.Summary())
	fmt.Fprintf(os.Stderr, "\n原始报告（含未脱敏 body，已 gitignore）: %s\n", jsonPath)
	fmt.Fprintf(os.Stderr, "脱敏草稿（人工确认后并入 docs/）: %s\n", mdPath)
	if rep.WrittenWithoutCaptcha() {
		fmt.Fprintln(os.Stderr, "结论：出现了「未用真凭证却写入记录」的档位 ⟹ 该路径不强制人机验证。")
	}
	if rep.HookMissing {
		fmt.Fprintln(os.Stderr, "提示：未收到手机 HAR 上报。检查手机 Reqable 的上报服务器配置与局域网连通性；原始抓包仍可在 Reqable 里人工补。")
	}
	fmt.Fprintln(os.Stderr, "手机端操作步骤见 docs/signin-probe.md「手机端要做什么」。")
	return nil
}

// cliPrompter 是命令行的交互实现。注意：只用文字提示，不响铃。
type cliPrompter struct {
	in   *bufio.Reader
	out  *os.File
	once sync.Once
	// lines 只由一个常驻 goroutine 写，避免每次 Gate 都新起一个读 stdin 的
	// goroutine、在超时后互相抢输入。
	lines chan string
}

func (p *cliPrompter) line() chan string {
	p.once.Do(func() {
		p.lines = make(chan string, 8)
		go func() {
			for {
				s, err := p.in.ReadString('\n')
				p.lines <- s
				if err != nil {
					return
				}
			}
		}()
	})
	return p.lines
}

func (p *cliPrompter) Gate(ctx context.Context, entry probe.Entry, timeout time.Duration) (bool, error) {
	fmt.Fprintf(p.out, "\n⚠ %s 写入了 %d 条新记录（%s）。\n",
		entry.Rung, len(entry.NewKeys), strings.Join(entry.NewKeys, ", "))
	fmt.Fprintf(p.out, "  %s 内按 c 回车继续跑后续档位；直接回车或超时则停止：", timeout)

	select {
	case line := <-p.line():
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "c"), nil
	case <-time.After(timeout):
		fmt.Fprintln(p.out)
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *cliPrompter) Notify(format string, args ...any) {
	fmt.Fprintf(p.out, "[probe] "+format+"\n", args...)
}

func promptCode(in *bufio.Reader, out *os.File) (string, error) {
	for {
		fmt.Fprint(out, "请输入老师公布的 4 位签到码（输入后立即开始计时）: ")
		line, err := in.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("读取签到码失败: %w", err)
		}
		code := strings.TrimSpace(line)
		if isFourDigits(code) {
			return code, nil
		}
		fmt.Fprintln(out, "必须是 4 位数字，请重试。")
	}
}

func isFourDigits(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// discoverSampleParam 从当前目录的 *.har 里找一份真实 captchaVerifyParam。
func discoverSampleParam(dir string) string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.har"))
	if err != nil {
		return ""
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if p := extractParam(string(data)); p != "" {
			return p
		}
	}
	return ""
}

// extractParam 从任意文本里提取 captchaVerifyParam 的值（自动 URL 解码）。
func extractParam(text string) string {
	const marker = "captchaVerifyParam="
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	rest := text[idx+len(marker):]
	if end := strings.IndexAny(rest, "&\"' \n\r\t"); end >= 0 {
		rest = rest[:end]
	}
	if decoded, err := url.QueryUnescape(rest); err == nil && strings.HasPrefix(decoded, "{") {
		return decoded
	}
	return ""
}

func lanIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "<本机局域网IP>"
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "<本机局域网IP>"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var f float64
	if _, err := fmt.Sscanf(v, "%g", &f); err != nil {
		return fallback
	}
	return f
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[probe] "+format+"\n", args...)
}
