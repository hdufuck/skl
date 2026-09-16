package probe

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Attempt 是同一档探针的一次往返。
//
// 大多数档只有一次；真值档会「换一个新的 captchaVerifyParam」重试（见 runner.go
// 的 retryWithFreshParamReason），因此可能有多次。逐次记下来是为了把 `har#3`
// 抓包里那条因果链留痕：请求行越长（`data` 膨胀）→ 越可能被网关判 `414`。
type Attempt struct {
	Status int `json:"status"`
	// URLLen 是未脱敏的完整请求 URL 长度（字节），即请求行的主要部分。
	URLLen int    `json:"urlLen"`
	Body   string `json:"body,omitempty"`
	// Retry 非空表示本次往返的失败属于「值得换一个新 captchaVerifyParam 重来」
	// 那一类（是否真的重来，由 Attempts 长度与重取预算决定）。
	Retry string `json:"retryReason,omitempty"`
}

// Entry 是一档探针的完整记录。
type Entry struct {
	Rung     RungID    `json:"rung"`
	Title    string    `json:"title"`
	At       time.Time `json:"at"`
	Duration string    `json:"duration"`

	Method    string    `json:"method,omitempty"`
	URL       string    `json:"url,omitempty"`
	ParamKind ParamKind `json:"paramKind"`

	Status      int               `json:"status"`
	RespHeaders map[string]string `json:"respHeaders,omitempty"`
	Body        string            `json:"body,omitempty"`
	// CaptchaVerifyCode 是成功响应里的 `captchaVerifyCode`（`T001` 成功 /
	// `F001` 失败），`har#3` 抓包新发现的字段。
	CaptchaVerifyCode string `json:"captchaVerifyCode,omitempty"`

	// Attempts 是本档的全部往返；只有真值档可能多于一次。
	Attempts []Attempt `json:"attempts,omitempty"`

	Wrote     bool     `json:"wroteRecord"`
	Before    int      `json:"readBackBefore"`
	After     int      `json:"readBackAfter"`
	NewKeys   []string `json:"newKeys,omitempty"`
	Verdict   Verdict  `json:"verdict"`
	Evidence  string   `json:"evidence,omitempty"`
	Err       string   `json:"error,omitempty"`
	Note      string   `json:"note,omitempty"`
	FromPhone bool     `json:"fromPhone,omitempty"`
}

// Report 是一次探针运行的完整产物。
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"startedAt"`

	UserID string  `json:"userId"`
	Code   string  `json:"code"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`

	BaselineCount int     `json:"baselineCount"`
	Entries       []Entry `json:"entries"`

	// PhoneHAR 是手机端 Reqable 通过上报服务器送来的那次官方签到；
	// HookMissing 表示在等待窗口内没有收到。
	PhoneHAR    *Entry `json:"phoneHar,omitempty"`
	HookMissing bool   `json:"hookMissing,omitempty"`

	// StoppedAt 非空表示因首个写入而停下，后续档未执行。
	StoppedAt RungID   `json:"stoppedAt,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// WrittenWithoutCaptcha 报告是否出现了「未用真凭证却写入记录」的强证据。
func (r *Report) WrittenWithoutCaptcha() bool {
	for _, e := range r.Entries {
		if e.Verdict == VerdictWrittenNoCaptcha {
			return true
		}
	}
	return false
}

// Successes 返回判读为成功（含真值档）的档位。
func (r *Report) Successes() []RungID {
	var out []RungID
	for _, e := range r.Entries {
		if e.Verdict == VerdictSuccess {
			out = append(out, e.Rung)
		}
	}
	return out
}

// GenuineUnproven 报告真值档是否连请求都没发出去。
//
// 判据就是 transport_error：它说明浏览器取参链路没走通（浏览器/上下文被提前关掉、
// SDK 没出参、点击落空等），此时第 5 档对「库的 SignIn 封装路径能否走通」没给出
// 任何证据——不要把它当成「真值档失败」，它根本没跑起来。
func (r *Report) GenuineUnproven() bool {
	for _, e := range r.Entries {
		if e.Rung == RungCaptchaGenuine {
			return e.Verdict == VerdictTransportError
		}
	}
	return false
}

// maskRecordKeys 把读回 diff 的记录标识打码后再写进草稿。
//
// 标识有两种形态（见 itemKey）：`id:<CheckInRecord 主键>` 与 `sha256:<内容哈希>`。
// 主键能追回那一条考勤记录，所以按学号同样的粒度打码；哈希不指向人，原样保留。
//
// 只作用于落盘的 markdown 草稿；原始 JSON 报告保留原值（已 gitignore）。
func maskRecordKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if id, ok := strings.CutPrefix(k, "id:"); ok {
			out = append(out, "id:"+MaskID(id))
			continue
		}
		out = append(out, k)
	}
	return out
}

// Summary 渲染一张控制台速览表。
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-26s %-8s %-26s %s\n", "档位", "HTTP", "判读", "证据强度")
	for _, e := range r.Entries {
		status := "-"
		if e.Status != 0 {
			status = fmt.Sprintf("%d", e.Status)
		}
		mark := " "
		if e.Wrote {
			mark = "✎"
		}
		fmt.Fprintf(&b, "%-26s %-8s %-26s %s%s\n", e.Rung, status, e.Verdict, e.Evidence, mark)
	}
	if r.PhoneHAR != nil {
		fmt.Fprintf(&b, "%-26s %-8d %-26s %s\n", "phone(Reqable HAR)", r.PhoneHAR.Status, "observed", "手机端官方签到")
	} else if r.HookMissing {
		fmt.Fprintf(&b, "%-26s %-8s %-26s %s\n", "phone(Reqable HAR)", "-", "hook_missing", "未在等待窗口内收到")
	}
	return b.String()
}

// Markdown 渲染一份已脱敏、可直接粘贴进 docs/ 的报告。
func (r *Report) Markdown() string {
	var b strings.Builder
	// 运行时刻就是「哪节课」的一部分，和学号/课程同级，所以草稿里也打码；
	// 要精确时间看文件名（probe-results/<时间戳>.md）或 .json 原始报告。
	fmt.Fprintf(&b, "# 签到探针报告\n\n")
	fmt.Fprintf(&b, "- 运行时间：已打码（精确时间见文件名；原始值在 .json 报告里）\n")
	fmt.Fprintf(&b, "- 工具：`%s`\n", r.Version)
	fmt.Fprintf(&b, "- 账号：`%s`\n", MaskID(r.UserID))
	fmt.Fprintf(&b, "- 签到码：`%s`\n", r.Code)
	fmt.Fprintf(&b, "- 定位：`%.6f, %.6f`\n", r.Lat, r.Lon)
	fmt.Fprintf(&b, "- 读回基线：%d 条\n\n", r.BaselineCount)

	b.WriteString("| 档位 | 凭证 | HTTP | 读回 | 判读 | 证据强度 |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, e := range r.Entries {
		status := "-"
		if e.Status != 0 {
			status = fmt.Sprintf("%d", e.Status)
		}
		readback := "-"
		if e.Before != 0 || e.After != 0 {
			readback = fmt.Sprintf("%d→%d", e.Before, e.After)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | `%s` | %s |\n",
			e.Rung, e.ParamKind, status, readback, e.Verdict, e.Evidence)
	}
	b.WriteString("\n")

	if r.WrittenWithoutCaptcha() {
		b.WriteString("> **强证据**：出现了「未携带真凭证却写入考勤记录」的档位 ⟹ 服务端在该路径上**不强制**人机验证。\n\n")
	}
	if r.GenuineUnproven() {
		b.WriteString("> **真值档未验证**：`captcha-verify-genuine` 判为 `transport_error`，请求根本没发出去 ⟹ 浏览器取参链路未走通，本次**没有**证明库的 `SignIn` 封装路径。修好链路（`--headed` 重跑）再谈结论。\n\n")
	}
	if len(r.Notes) > 0 {
		b.WriteString("备注：\n\n")
		for _, note := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}

	for _, e := range r.Entries {
		fmt.Fprintf(&b, "## `%s`\n\n", e.Rung)
		fmt.Fprintf(&b, "- 请求：`%s %s`\n", e.Method, e.URL)
		fmt.Fprintf(&b, "- 凭证形态：`%s`\n", e.ParamKind)
		fmt.Fprintf(&b, "- 判读：`%s`（%s）\n", e.Verdict, e.Evidence)
		if e.CaptchaVerifyCode != "" {
			fmt.Fprintf(&b, "- `captchaVerifyCode`：`%s`（`T001` 成功 / `F001` 失败）\n", e.CaptchaVerifyCode)
		}
		if len(e.Attempts) > 1 {
			b.WriteString("- 往返明细（换新 `captchaVerifyParam` 重取）：\n\n")
			b.WriteString("  | # | HTTP | URL 长度 | 失败原因 |\n  | --- | --- | --- | --- |\n")
			for i, a := range e.Attempts {
				status := "-"
				if a.Status != 0 {
					status = fmt.Sprintf("%d", a.Status)
				}
				reason := "—"
				if a.Retry != "" {
					reason = a.Retry
				}
				fmt.Fprintf(&b, "  | %d | %s | %d | %s |\n", i+1, status, a.URLLen, reason)
			}
			b.WriteString("\n")
			// 被重试盖掉的那几次响应也要留档：例如「有效签到码 + 人机判 false」
			// 的 `F001` 只出现在第一次往返里。
			for i, a := range e.Attempts {
				if a.Body == "" || a.Body == e.Body {
					continue
				}
				fmt.Fprintf(&b, "  第 %d 次响应：\n\n```json\n%s\n```\n\n", i+1, RedactBody(a.Body))
			}
		}
		if e.Note != "" {
			fmt.Fprintf(&b, "- 备注：%s\n", e.Note)
		}
		if e.Err != "" {
			fmt.Fprintf(&b, "- 错误：`%s`\n", e.Err)
		}
		if len(e.NewKeys) > 0 {
			fmt.Fprintf(&b, "- 新增记录标识：`%s`\n", strings.Join(maskRecordKeys(e.NewKeys), ", "))
		}
		if len(e.RespHeaders) > 0 {
			sortKeys := make([]string, 0, len(e.RespHeaders))
			for k := range e.RespHeaders {
				sortKeys = append(sortKeys, k)
			}
			slices.Sort(sortKeys)
			parts := make([]string, 0, len(sortKeys))
			for _, k := range sortKeys {
				parts = append(parts, fmt.Sprintf("%s: %s", k, e.RespHeaders[k]))
			}
			fmt.Fprintf(&b, "- 响应头：`%s`\n", strings.Join(parts, " | "))
		}
		if e.Body != "" {
			fmt.Fprintf(&b, "\n```json\n%s\n```\n", RedactBody(e.Body))
		}
		b.WriteString("\n")
	}

	if r.PhoneHAR != nil {
		b.WriteString("## 手机端官方签到（Reqable 上报）\n\n")
		fmt.Fprintf(&b, "- 请求：`%s %s`\n", r.PhoneHAR.Method, r.PhoneHAR.URL)
		fmt.Fprintf(&b, "- HTTP：%d\n", r.PhoneHAR.Status)
		if r.PhoneHAR.Body != "" {
			fmt.Fprintf(&b, "\n```json\n%s\n```\n", RedactBody(r.PhoneHAR.Body))
		}
		b.WriteString("\n")
	} else if r.HookMissing {
		b.WriteString("> 未在等待窗口内收到 Reqable 上报服务器的数据（`hookMissing`）。手机端抓包仍在 Reqable 内，可事后人工补。\n\n")
	}

	if r.StoppedAt != "" {
		fmt.Fprintf(&b, "> 在 `%s` 处检测到写入，按「首个写入即停」纪律终止了后续档位。\n\n", r.StoppedAt)
	}
	return b.String()
}
