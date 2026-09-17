package probe

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Attempt 是真值档的一次往返。
//
// 换 skl-ticket 重发记在同一次往返里（见 runner.go 的 exchange）；只有「换一个新的
// captchaVerifyParam」重试才会产生多条，因此逐次记下来能把 `har#3` 抓包里那条因果链
// 留痕：请求行越长（`data` 膨胀）→ 越可能被网关判 `414`。
type Attempt struct {
	Status int `json:"status"`
	// URLLen 是未脱敏的完整请求 URL 长度（字节），即请求行的主要部分。
	URLLen int    `json:"urlLen"`
	Body   string `json:"body,omitempty"`
	// Retry 非空表示本次往返的失败属于「值得换一个新 captchaVerifyParam 重来」
	// 那一类（是否真的重来，由 Attempts 长度与重取预算决定）。
	Retry string `json:"retryReason,omitempty"`
}

// Entry 是一次探针的完整记录。
//
// 它只记录事实，不记录判读：请求/响应，以及该请求之后读到的考勤记录。
type Entry struct {
	Rung     RungID    `json:"rung"`
	Title    string    `json:"title"`
	At       time.Time `json:"at"`
	Duration string    `json:"duration"`

	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`

	Status      int               `json:"status"`
	RespHeaders map[string]string `json:"respHeaders,omitempty"`
	Body        string            `json:"body,omitempty"`
	// CaptchaVerifyCode 是响应里的 `captchaVerifyCode`（`T001` / `F001`），
	// 只作留档；成败由人看响应体判断。
	CaptchaVerifyCode string `json:"captchaVerifyCode,omitempty"`

	// Attempts 是本档的全部往返；只有换新参数重取时才会多于一条。
	Attempts []Attempt `json:"attempts,omitempty"`

	// AfterRequest 是本档请求之后读到的今日考勤记录（`/api/check-in-student-detail/my`
	// 的原始 JSON 数组）。元素形态未实测，因此**原样保留**，不解析、不比对。
	AfterRequest []json.RawMessage `json:"afterRequest,omitempty"`
	// ReadBackErr 记录本档之后的考勤记录读取失败（此时 AfterRequest 为空）。
	ReadBackErr string `json:"readBackErr,omitempty"`

	Err       string `json:"error,omitempty"`
	Note      string `json:"note,omitempty"`
	FromPhone bool   `json:"fromPhone,omitempty"`
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

	Notes []string `json:"notes,omitempty"`
}

// GenuineUnproven 报告真值档是否连请求都没发出去。
//
// 判据就是「没有拿到任何 HTTP 状态」：它说明浏览器取参链路没走通
// （浏览器/上下文被提前关掉、SDK 没出参、点击落空等），此时本次运行对
// 「库的 SignIn 封装路径能否走通」没给出任何证据。
func (r *Report) GenuineUnproven() bool {
	for _, e := range r.Entries {
		if e.Rung == RungCaptchaGenuine {
			return e.Status == 0 && e.Err != ""
		}
	}
	return false
}

// Summary 渲染一张控制台速览表。
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-26s %-8s %-12s %s\n", "档位", "HTTP", "请求后记录", "备注")
	for _, e := range r.Entries {
		status := "-"
		if e.Status != 0 {
			status = fmt.Sprintf("%d", e.Status)
		}
		records := "-"
		if e.AfterRequest != nil {
			records = fmt.Sprintf("%d 条", len(e.AfterRequest))
		}
		note := ""
		switch {
		case e.Err != "":
			note = "请求错误"
		case e.ReadBackErr != "":
			note = "读回失败"
		}
		fmt.Fprintf(&b, "%-26s %-8s %-12s %s\n", e.Rung, status, records, note)
	}
	if r.PhoneHAR != nil {
		fmt.Fprintf(&b, "%-26s %-8d %-12s %s\n", "phone(Reqable HAR)", r.PhoneHAR.Status, "-", "手机端官方签到")
	} else if r.HookMissing {
		fmt.Fprintf(&b, "%-26s %-8s %-12s %s\n", "phone(Reqable HAR)", "-", "-", "未在等待窗口内收到")
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
	fmt.Fprintf(&b, "- T0 前考勤记录基线：%d 条\n\n", r.BaselineCount)

	b.WriteString("| 档位 | HTTP | 请求后考勤记录 |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, e := range r.Entries {
		status := "-"
		if e.Status != 0 {
			status = fmt.Sprintf("%d", e.Status)
		}
		records := "-"
		if e.AfterRequest != nil {
			records = fmt.Sprintf("%d 条", len(e.AfterRequest))
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", e.Rung, status, records)
	}
	b.WriteString("\n")

	if r.GenuineUnproven() {
		b.WriteString("> **真值档未验证**：`captcha-verify-genuine` 没拿到任何 HTTP 状态（浏览器取参链路未走通），本次**没有**证明库的 `SignIn` 封装路径。修好链路（`--headed` 重跑）再谈结论。\n\n")
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
		if e.ReadBackErr != "" {
			fmt.Fprintf(&b, "- 读回失败：`%s`\n", e.ReadBackErr)
		}
		if len(e.AfterRequest) > 0 {
			b.WriteString("- 请求之后的考勤记录（原样，已按 §4.4 打码）：\n\n```json\n")
			raw, err := json.Marshal(e.AfterRequest)
			if err != nil {
				// 不静默丢：读回记录是这份报告的主要证据之一。
				fmt.Fprintf(&b, "<原始记录无法序列化：%s>", err)
			} else {
				b.WriteString(RedactBody(string(raw)))
			}
			b.WriteString("\n```\n")
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

	return b.String()
}
