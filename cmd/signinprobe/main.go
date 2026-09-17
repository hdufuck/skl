// Command signinprobe 是一次性签到探针：在真实有效的签到码窗口内，用浏览器里的
// 官方 SDK 现场取一个真值 captchaVerifyParam，交给库的 SignIn 封装路径发出去，
// 一次拿到「库的封装路径可用」＋一条活路径成功样本。
//
// 为什么只做这一件事（不再探测「人机是否强制」）：见 ADR 0004。
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
	"os"
	"path/filepath"
	"strings"
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
	user  string
	pass  string
	token string
	base  string
	lat   float64
	lon   float64
	code  string

	headed   bool
	profile  string
	hookAddr string
	outDir   string

	// 浏览器自称。
	mobile    bool
	userAgent string
	clientUA  string

	captchaDeadline time.Duration
	hookWait        time.Duration
	genuineAttempts int
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

	fs.BoolVar(&opt.headed, "headed", false, "用可见窗口跑 Chrome（默认 headless=new）")
	fs.StringVar(&opt.profile, "profile", "", "Chrome 持久化 profile 目录")
	fs.StringVar(&opt.hookAddr, "hook", ":8080", "Reqable 上报服务器监听地址；空串关闭")
	fs.StringVar(&opt.outDir, "out", "probe-results", "报告输出目录")

	fs.BoolVar(&opt.mobile, "mobile", false,
		"浏览器自称 Android 手机（UA、客户端提示、430×932 视口、触摸一起换；默认自称真实桌面 Chrome）")
	fs.StringVar(&opt.userAgent, "ua", "",
		"浏览器自称的 UA；留空 = 桌面用真实 UA 去掉 headless 标记、手机用内置 Android 模板（可粘钉钉那串）")
	fs.StringVar(&opt.clientUA, "client-ua", "",
		"skl HTTP 客户端的 User-Agent：留空 = 项目自报名；browser = 与浏览器自称一致；其它 = 原样使用")

	fs.DurationVar(&opt.captchaDeadline, "captcha-deadline", 23*time.Second, "真值档的墙钟预算")
	fs.DurationVar(&opt.hookWait, "hook-wait", 10*time.Second, "等待手机 HAR 上报的时长")
	fs.IntVar(&opt.genuineAttempts, "genuine-attempts", 3,
		"真值档最多跑几次（每次重取一个新 captchaVerifyParam；har#3 抓包里三次提交才成功一次）")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	ctx := context.Background()
	in := bufio.NewReader(os.Stdin)

	// 终端输出**不**打码：当场核对「是不是本人、是不是本次窗口」需要真值。
	// 要往仓库里带的东西只有两份落盘报告，它们的脱敏规则见
	// docs/signin-probe.md §4.4（判据：会进 git 的内容才需要打码）。
	fmt.Fprintln(os.Stderr, "[probe] ⚠ 本行以下的终端输出**未打码**（含真实姓名/学号）：")
	fmt.Fprintln(os.Stderr, "[probe]    它只给你自己看，不要整段复制到 issue / 文档 / 群里。")
	fmt.Fprintln(os.Stderr, "[probe]    落盘的 .md 草稿已按 §4.4 打码；.json 是原始证据（已 gitignore）。")

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
	// 终端不打码，所以这里直接打真名与真学号（见文件开头的提示）。
	logf("已登录：%s（%s）", user.UserName, user.ID)

	baseline, err := probe.ReadBackToday(client)(loginCtx)
	if err != nil {
		return fmt.Errorf("读回预热失败（窗口内第一次读取失败就等于浪费机会）: %w", err)
	}
	logf("读回预热成功：今日考勤记录 %d 条（基线）", len(baseline))

	profile := opt.profile
	if profile == "" {
		// 默认复用持久化 profile，让设备指纹「热」起来；--profile 可覆盖。
		if cache, err := os.UserCacheDir(); err == nil {
			profile = filepath.Join(cache, "signinprobe", "chrome-profile")
		}
	}

	// 浏览器预热总是要跑的：它产出的真值 captchaVerifyParam 就是整个工具的目的。
	var captchaSource probe.CaptchaParamSource
	browserCtx, cancelBrowser := context.WithCancel(ctx)
	defer cancelBrowser()
	src, err := chromecaptcha.New(browserCtx, chromecaptcha.Options{
		Headless:    !opt.headed,
		UserDataDir: profile,
		Logf:        logf,
		Mobile:      opt.mobile,
		UserAgent:   opt.userAgent,
	})
	if err != nil {
		return fmt.Errorf("浏览器预热失败: %w", err)
	}
	captchaSource = src
	defer func() { _ = src.Close() }()

	// 可选：让 skl HTTP 客户端与浏览器自称一致（默认保持项目自报名）。
	switch {
	case opt.clientUA == "browser":
		// 预热总是会跑完才会走到这里，所以 UA 为空只可能是预热没正常完成。
		browserUA := src.UserAgent()
		if browserUA == "" {
			return errors.New("--client-ua browser：浏览器预热的自称为空，无法对齐")
		}
		client.SetUserAgent(browserUA)
	case opt.clientUA != "":
		client.SetUserAgent(opt.clientUA)
	}
	if opt.clientUA != "" {
		logf("skl 客户端 User-Agent = %s", client.UserAgent())
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

	logf("T0=%s 开始探针（真值档≤%s，最多 %d 次）", time.Now().Format("15:04:05"),
		opt.captchaDeadline, opt.genuineAttempts)

	prompter := &cliPrompter{out: os.Stderr}
	rep, err := probe.Run(ctx, probe.Config{
		Client:          client,
		Recorder:        rec,
		Code:            code,
		UserID:          user.ID,
		Coord:           probe.Coord{Lat: opt.lat, Lon: opt.lon},
		Captcha:         captchaSource,
		Prompter:        prompter,
		ReadBack:        probe.ReadBackToday(client),
		Baseline:        baseline,
		Hook:            hookCh,
		CaptchaDeadline: opt.captchaDeadline,
		HookWait:        opt.hookWait,
		GenuineAttempts: opt.genuineAttempts,
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
	if len(rep.Notes) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, note := range rep.Notes {
			fmt.Fprintf(os.Stderr, "备注：%s\n", note)
		}
	}
	fmt.Fprintf(os.Stderr, "\n原始报告（**未打码**，含真实 body；已 gitignore，不外传）: %s\n", jsonPath)
	fmt.Fprintf(os.Stderr, "脱敏草稿（已按 §4.4 打码；人工确认后并入 docs/）: %s\n", mdPath)
	fmt.Fprintln(os.Stderr, "提醒：上面这些终端输出未打码，不要整段复制出去；要带走就带走 md 草稿。")
	if rep.GenuineUnproven() {
		fmt.Fprintln(os.Stderr, "⚠ 真值档根本没拿到 HTTP 状态：浏览器取参链路未走通。"+
			"不要采信它的任何结论；先用无效码重跑演练（可加 --headed）把链路跑通。")
	}
	if rep.HookMissing {
		fmt.Fprintln(os.Stderr, "提示：未收到手机 HAR 上报。检查手机 Reqable 的上报服务器配置与局域网连通性；原始抓包仍可在 Reqable 里人工补。")
	}
	fmt.Fprintln(os.Stderr, "手机端操作步骤见 docs/signin-probe.md「手机端要做什么」。")
	return nil
}

// cliPrompter 是命令行的提示实现。注意：只用文字提示，不响铃。
type cliPrompter struct {
	out *os.File
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

// lanIP 选一个真正的局域网 IPv4（优先 192.168.*，其次 10.* / 172.16-31.*）。
//
// 不用 `net.Dial("udp", "8.8.8.8:80")` 那个技巧：在开了 VPN/tun 的机器上它
// 常会选中 198.18.0.0/15 这类非局域网地址，手机根本连不上。
func lanIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "<本机局域网IP>"
	}
	best, bestRank := "", 0
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := ifi.Addrs()
		if addrErr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			rank := 0
			switch {
			case v4[0] == 192 && v4[1] == 168:
				rank = 3
			case v4[0] == 10:
				rank = 2
			case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
				rank = 2
			}
			if rank > bestRank {
				best, bestRank = v4.String(), rank
			}
		}
	}
	if best == "" {
		return "<本机局域网IP>"
	}
	return best
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
