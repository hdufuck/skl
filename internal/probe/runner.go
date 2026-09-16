package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hdufuck/skl"
)

// Coord 是一次签到使用的定位。
type Coord struct {
	Lat float64
	Lon float64
}

// CaptchaParamSource 产出一个由官方 SDK 生成的真值 captchaVerifyParam。
//
// 实现是浏览器自动化（internal/chromecaptcha）；单测用 fake。
type CaptchaParamSource interface {
	Param(ctx context.Context) (string, error)
	Close() error
}

// Prompter 是交互接口，便于测试时替换成脚本化实现。
type Prompter interface {
	// Gate 在检测到写入后询问是否继续；返回 true 表示继续跑后续档位。
	// 实现应在 timeout 内未收到输入时返回默认动作（false = 停）。
	Gate(ctx context.Context, entry Entry, timeout time.Duration) (bool, error)
	// Notify 输出一行提示。
	Notify(format string, args ...any)
}

// Config 是一次探针运行的全部输入。
type Config struct {
	Client   *skl.Client
	Recorder *Recorder

	Code   string
	UserID string
	Coord  Coord

	// Sample 是一份真实 captchaVerifyParam（可为空），用于让伪造值等长。
	Sample string

	// Captcha 是真值来源；为 nil 或 SkipGenuine 时跳过第 5 档。
	Captcha     CaptchaParamSource
	SkipGenuine bool

	Prompter Prompter
	Logf     func(format string, args ...any)
	Now      func() time.Time

	// ReadBack 读取今日签到明细快照；为 nil 时报错。
	ReadBack func(ctx context.Context) (Snapshot, error)
	// Baseline 是 T0 前的读回基线；为 nil 时在 Run 开始时现读一次。
	Baseline *Snapshot

	// Hook 是手机端 Reqable 上报服务器送来的条目（可为 nil）。
	Hook <-chan Entry

	// 以下均为可选覆盖，0 表示用默认值。
	LadderDeadline     time.Duration
	CaptchaDeadline    time.Duration
	GateTimeout        time.Duration
	HookWait           time.Duration
	ContinueAfterWrite bool

	// GenuineAttempts 是真值档最多跑几次（每次重取一个新 captchaVerifyParam）。
	// 0 表示默认值（3）：`har#3` 抓包里三次提交才成功一次。
	GenuineAttempts int
}

const (
	defaultLadderDeadline  = 8 * time.Second
	defaultCaptchaDeadline = 23 * time.Second
	defaultGateTimeout     = 5 * time.Second
	defaultHookWait        = 10 * time.Second
	// defaultGenuineAttempts 默认让真值档最多跑 3 次：`har#3` 抓包里
	// 第 1、2 次都死在网关（414），第 3 次才真正到应用并成功。
	defaultGenuineAttempts = 3
)

func (c Config) ladderDeadline() time.Duration {
	if c.LadderDeadline > 0 {
		return c.LadderDeadline
	}
	return defaultLadderDeadline
}

func (c Config) captchaDeadline() time.Duration {
	if c.CaptchaDeadline > 0 {
		return c.CaptchaDeadline
	}
	return defaultCaptchaDeadline
}

func (c Config) gateTimeout() time.Duration {
	if c.GateTimeout > 0 {
		return c.GateTimeout
	}
	return defaultGateTimeout
}

func (c Config) hookWait() time.Duration {
	if c.HookWait > 0 {
		return c.HookWait
	}
	return defaultHookWait
}

// rungAttempts 返回该档允许的往返次数（含最后一次）。
//
// 只有真值档会「换一个新 captchaVerifyParam 重来」：`har#3` 抓包里三次提交
// 才成功一次，前两次分别是 TRACELESS 的 data 膨胀到 25 KB 被网关判 `414`、
// 以及人机判定 `false`（`F001`）；两种情况换新参数都大概率能过——官方 SDK
// 自己也是这么做的（`F001` 后自动 `reInitCaptcha`，重取参数后一次成功）。
func (c Config) rungAttempts(rung RungID) int {
	if rung != RungCaptchaGenuine {
		return 1
	}
	if c.GenuineAttempts > 0 {
		return c.GenuineAttempts
	}
	return defaultGenuineAttempts
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Run 按阶梯顺序执行探针，返回完整报告。
//
// T0 是 Run 被调用的时刻（即签到码已拿到）；所有 deadline 都相对 T0 计算，
// 保证即使真实窗口只有 30 秒也能在预算内收尾。
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.Client == nil {
		return nil, errors.New("probe: 未提供 skl.Client")
	}
	if cfg.Recorder == nil {
		return nil, errors.New("probe: 未提供 Recorder（无法记录原始请求/响应）")
	}
	if cfg.ReadBack == nil {
		return nil, errors.New("probe: 未提供 ReadBack")
	}

	start := cfg.now()
	rep := &Report{
		Tool:      "signinprobe",
		Version:   ToolVersion,
		StartedAt: start,
		UserID:    cfg.UserID,
		Code:      cfg.Code,
		Lat:       cfg.Coord.Lat,
		Lon:       cfg.Coord.Lon,
	}

	baseline := Snapshot{}
	if cfg.Baseline != nil {
		baseline = *cfg.Baseline
	} else {
		s, err := cfg.ReadBack(ctx)
		if err != nil {
			return nil, fmt.Errorf("probe: 读取基线失败: %w", err)
		}
		baseline = s
	}
	rep.BaselineCount = baseline.Count
	prev := baseline

	ladderDeadline := start.Add(cfg.ladderDeadline())
	captchaDeadline := start.Add(cfg.captchaDeadline())

	for _, rung := range Ladder {
		budget := cfg.ladderDeadline()
		deadline := ladderDeadline
		if rung == RungCaptchaGenuine {
			if cfg.Captcha == nil || cfg.SkipGenuine {
				continue
			}
			budget = cfg.captchaDeadline()
			deadline = captchaDeadline
		}
		if cfg.now().After(deadline) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("跳过 %s：超出 %.0fs 预算", rung, budget.Seconds()))
			continue
		}

		// 给每档一个真实的 ctx deadline，而不是只在起跑前比较时间：
		// 否则一个挂起的请求会直接击穿预算，吃掉留给手机的窗口。
		rungCtx, cancelRung := context.WithDeadline(ctx, deadline)
		entry := cfg.runRung(rungCtx, rung, prev)
		cancelRung()
		rep.Entries = append(rep.Entries, entry)
		if entry.Wrote {
			prev = Snapshot{Count: entry.After, Keys: append(append([]string{}, prev.Keys...), entry.NewKeys...)}
			cfg.logf("⚠ %s 写入了 %d 条新记录（%s）", rung, len(entry.NewKeys), entry.NewKeys)
			if !cfg.ContinueAfterWrite {
				cont := false
				if cfg.Prompter != nil {
					ok, err := cfg.Prompter.Gate(ctx, entry, cfg.gateTimeout())
					if err != nil {
						return rep, err
					}
					cont = ok
				}
				if !cont {
					rep.StoppedAt = rung
					break
				}
			}
		}
	}

	if cfg.Hook != nil {
		if cfg.Prompter != nil {
			cfg.Prompter.Notify("现在请在手机上完成一次官方签到（Reqable 已配置上报服务器）。")
		}
		select {
		case e, ok := <-cfg.Hook:
			if ok {
				phone := e
				phone.FromPhone = true
				rep.PhoneHAR = &phone
				if note := phoneCodeNote(&phone, cfg.Code); note != "" {
					rep.Notes = append(rep.Notes, note)
				}
			} else {
				rep.HookMissing = true
			}
		case <-time.After(cfg.hookWait()):
			rep.HookMissing = true
		case <-ctx.Done():
			rep.HookMissing = true
		}
	}

	return rep, nil
}

// phoneCodeNote 检查手机端上报的签到码与本次是否一致。
//
// 手机端若停在旧签到页（输入框里还是上一个码），它上报回来的 401 与本次窗口无关，
// 拿它当「权威官方样本」作对照就是错的。URL 里的 `code` 不脱敏（见 RedactURL）。
func phoneCodeNote(phone *Entry, want string) string {
	u, err := url.Parse(phone.URL)
	if err != nil {
		return ""
	}
	got := u.Query().Get("code")
	if got == "" || got == want {
		return ""
	}
	return fmt.Sprintf("手机端上报的签到码是 %s，与本次的 %s 不同 ⟹ 那不是同一个窗口，不能当对照（请在手机签到页重新输入本次的码）", got, want)
}

// runRung 执行一档探针并组装记录。
func (cfg Config) runRung(ctx context.Context, rung RungID, prev Snapshot) Entry {
	entry := Entry{
		Rung:      rung,
		Title:     rung.Title(),
		At:        cfg.now(),
		ParamKind: rung.ParamKind(),
		Before:    prev.Count,
	}

	began := cfg.now()

	max := cfg.rungAttempts(rung)
	var (
		ex     *Exchange
		runErr error
		hints  hintSet
	)
	// lastGood 是最后一次「拿到了真实响应」的往返。重取参数的那次重试如果以
	// 传输错误/超时收场，不能让它盖掉前面那次可判读的结果。
	var (
		lastGood      *Exchange
		lastGoodHints hintSet
	)
	for i := range max {
		if i > 0 && ctx.Err() != nil {
			entry.Note = appendNote(entry.Note, "重取参数的预算已耗尽，停止重试")
			break
		}

		cur, err := cfg.exchange(ctx, rung, &entry.Note)
		body := ""
		if cur != nil {
			body = strings.TrimSpace(string(cur.Body))
		}
		curHints := hintsFrom(rung, body)

		retry := retryWithFreshParamReason(rung, cur, curHints)
		entry.Attempts = append(entry.Attempts, newAttempt(cur, body, retry))

		if cur != nil && cur.Err == nil && cur.Status != 0 {
			lastGood, lastGoodHints = cur, curHints
		}
		ex, runErr, hints = cur, err, curHints

		if retry == "" {
			break
		}
		if i+1 >= max {
			entry.Note = appendNote(entry.Note,
				fmt.Sprintf("本次失败属于「值得换新 captchaVerifyParam 重取」那类，但已用满 %d 次上限，停止重试", max))
			break
		}
		entry.Note = appendNote(entry.Note, retry)
	}
	if lastGood != nil {
		ex, hints = lastGood, lastGoodHints
	}
	entry.Duration = cfg.now().Sub(began).String()

	if ex != nil {
		entry.Method = ex.Method
		entry.URL = RedactURL(ex.URL)
		entry.Status = ex.Status
		entry.RespHeaders = RedactHeaders(ex.Header)
		entry.Body = strings.TrimSpace(string(ex.Body))
		if ex.Err != nil {
			entry.Err = ex.Err.Error()
		}
		if hint := URLTooLongHint(len(ex.URL)); hint != "" {
			entry.Note = appendNote(entry.Note, hint)
		}
	}
	if runErr != nil && entry.Err == "" {
		entry.Err = runErr.Error()
	}
	entry.CaptchaVerifyCode = hints.captchaVerifyCode

	after, rbErr := cfg.ReadBack(ctx)
	if rbErr != nil {
		entry.Note = appendNote(entry.Note, "读回失败: "+rbErr.Error())
	} else {
		entry.After = after.Count
		entry.NewKeys = after.NewKeys(prev)
		entry.Wrote = len(entry.NewKeys) > 0
	}

	entry.Verdict = Classify(ClassifyInput{
		Rung:                rung,
		Status:              entry.Status,
		Body:                []byte(entry.Body),
		Err:                 entry.Err,
		Wrote:               entry.Wrote,
		AnalyzeCode:         hints.analyzeCode,
		HasAnalyzeCode:      hints.hasAnalyzeCode,
		CaptchaVerifyResult: hints.cvr,
		CaptchaVerifyCode:   hints.captchaVerifyCode,
		CheckCodeDtoLen:     hints.dtoLen,
	})
	entry.Evidence = entry.Verdict.Evidence()
	return entry
}

// exchange 发一次请求；`200 + 空 body` 已证实多为 skl-ticket 重放被拒，
// 这种情况换一个新的 ticket 重发一次，不计入真值档的重取预算。
func (cfg Config) exchange(ctx context.Context, rung RungID, note *string) (*Exchange, error) {
	var (
		ex     *Exchange
		runErr error
	)
	for attempt := range 2 {
		cfg.Recorder.Reset()
		runErr = cfg.execute(ctx, rung)
		ex = cfg.Recorder.Last()
		if attempt == 0 && isRetryableEmptyBody(ex) {
			*note = appendNote(*note, "200 空 body：换新 skl-ticket 重发一次（不计入尝试次数）")
			continue
		}
		break
	}
	return ex, runErr
}

// retryWithFreshParamReason 报告是否值得换一个新的 captchaVerifyParam 重来。
//
// 只有真值档才重取：重取要重走一遍浏览器取参，有成本；而其余档的参数本来就
// 是伪造/缺失的，重取没有意义。
func retryWithFreshParamReason(rung RungID, ex *Exchange, hints hintSet) string {
	if rung != RungCaptchaGenuine || ex == nil || ex.Err != nil {
		return ""
	}
	switch {
	case ex.Status == http.StatusRequestEntityTooLarge || ex.Status == http.StatusRequestURITooLong:
		return fmt.Sprintf("HTTP %d：请求行长 %d 字节，被网关拒绝（未达应用）⟹ 换一个新参数重取",
			ex.Status, len(ex.URL))
	case ex.Status == http.StatusOK && isCaptchaRejected(hints):
		return "人机判定为 false ⟹ 换一个新参数重取（官方 SDK 在 F001 后也是这样 reInitCaptcha 的）"
	}
	return ""
}

// isCaptchaRejected 报告这次响应是否明确指向人机层失败。
//
// 直接复用判读层，避免「什么算人机失败」在重试决策与结论两处各写一遍。
func isCaptchaRejected(hints hintSet) bool {
	return Classify(ClassifyInput{
		Rung:                RungCaptchaGenuine,
		Status:              http.StatusOK,
		Body:                []byte("{\"x\":1}"),
		CaptchaVerifyResult: hints.cvr,
		CaptchaVerifyCode:   hints.captchaVerifyCode,
	}) == VerdictCaptchaRejected
}

// newAttempt 把一次往返汇总成报告里的一条记录。
func newAttempt(cur *Exchange, body, retry string) Attempt {
	att := Attempt{Body: body, Retry: retry}
	if cur != nil {
		att.Status = cur.Status
		att.URLLen = len(cur.URL)
	}
	return att
}

// isRetryableEmptyBody 报告一次往返是否是「200 + 空 body」。
func isRetryableEmptyBody(ex *Exchange) bool {
	return ex != nil && ex.Status == http.StatusOK && len(bytes.TrimSpace(ex.Body)) == 0
}

// execute 调用库的封装路径执行一档探针。
func (cfg Config) execute(ctx context.Context, rung RungID) error {
	switch rung {
	case RungAnalyzeA0:
		_, err := cfg.Client.SignInLegacyAnalyze(ctx, skl.AnalyzeRequest{
			Code:   cfg.Code,
			UserID: cfg.UserID,
		})
		return err

	case RungLegacyCheckIn:
		_, err := cfg.Client.SignInLegacy(ctx, skl.SignInRequest{
			Code:      cfg.Code,
			UserID:    cfg.UserID,
			Latitude:  cfg.Coord.Lat,
			Longitude: cfg.Coord.Lon,
		})
		return err

	case RungCaptchaMissing:
		// 库的 SignIn 不允许空 captchaVerifyParam（会返回 ErrNoCaptchaProvider
		// 且不发请求），因此这一档直接用 Do 发出「同形但缺参」的请求。
		// 显式带上 Content-Type，保持与官方请求逐字节一致。
		query := url.Values{
			"userid":    {cfg.UserID},
			"code":      {cfg.Code},
			"latitude":  {formatCoord(cfg.Coord.Lat)},
			"longitude": {formatCoord(cfg.Coord.Lon)},
			"t":         {strconv.FormatInt(cfg.now().UnixMilli(), 10)},
		}
		_, err := cfg.Client.Do(ctx, &skl.Request{
			Method: http.MethodPost,
			Path:   skl.PathSignInCaptchaVerify,
			Query:  query,
			Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		})
		return err

	case RungCaptchaForged:
		_, err := cfg.Client.SignIn(ctx, skl.SignInRequest{
			Code:               cfg.Code,
			UserID:             cfg.UserID,
			Latitude:           cfg.Coord.Lat,
			Longitude:          cfg.Coord.Lon,
			CaptchaVerifyParam: ForgeParam(cfg.Sample),
		})
		return err

	case RungCaptchaGenuine:
		if cfg.Captcha == nil {
			return errors.New("probe: 未配置真值来源")
		}
		param, err := cfg.Captcha.Param(ctx)
		if err != nil {
			return fmt.Errorf("probe: 获取真值 captchaVerifyParam: %w", err)
		}
		_, err = cfg.Client.SignIn(ctx, skl.SignInRequest{
			Code:               cfg.Code,
			UserID:             cfg.UserID,
			Latitude:           cfg.Coord.Lat,
			Longitude:          cfg.Coord.Lon,
			CaptchaVerifyParam: param,
		})
		return err

	default:
		return fmt.Errorf("probe: 未知档位 %q", rung)
	}
}

type hintSet struct {
	analyzeCode       int
	hasAnalyzeCode    bool
	cvr               *bool
	captchaVerifyCode string
	dtoLen            int
}

// hintsFrom 从响应体里提取判读所需的字面量。
func hintsFrom(rung RungID, body string) hintSet {
	var hs hintSet
	payload := []byte(body)
	if rung == RungAnalyzeA0 {
		payload = unwrapJSONP(payload)
		var env struct {
			Result struct {
				Code int `json:"code"`
			} `json:"result"`
		}
		if err := json.Unmarshal(payload, &env); err == nil {
			hs.analyzeCode = env.Result.Code
			hs.hasAnalyzeCode = true
		}
		return hs
	}

	var env struct {
		CVR  json.RawMessage `json:"captchaVerifyResult"`
		Code string          `json:"captchaVerifyCode"`
		DTO  json.RawMessage `json:"checkCodeDto"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return hs
	}
	hs.captchaVerifyCode = env.Code
	if len(env.CVR) > 0 {
		var b bool
		if err := json.Unmarshal(env.CVR, &b); err == nil {
			hs.cvr = &b
		}
	}
	if len(env.DTO) > 0 && string(env.DTO) != "null" {
		hs.dtoLen = len(env.DTO)
	}
	return hs
}

// unwrapJSONP 去掉 `callback({...})` 外壳；已是纯 JSON 时原样返回。
func unwrapJSONP(body []byte) []byte {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return []byte(trimmed)
	}
	if _, after, ok := strings.Cut(trimmed, "("); ok {
		if end := strings.LastIndexByte(after, ')'); end >= 0 {
			return []byte(strings.TrimSpace(after[:end]))
		}
	}
	return []byte(trimmed)
}

func formatCoord(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// ReadBackToday 用今日签到明细构造读回函数。
func ReadBackToday(c *skl.Client) func(ctx context.Context) (Snapshot, error) {
	return func(ctx context.Context) (Snapshot, error) {
		now := time.Now()
		raw, err := c.MyCheckInDetails(ctx, now, now)
		if err != nil {
			return Snapshot{}, err
		}
		return SnapshotFromRaw(raw), nil
	}
}
