package probe

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

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
	fmt.Fprintf(&b, "# 签到探针报告（%s）\n\n", r.StartedAt.Format(time.RFC3339))
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

	for _, e := range r.Entries {
		fmt.Fprintf(&b, "## `%s`\n\n", e.Rung)
		fmt.Fprintf(&b, "- 请求：`%s %s`\n", e.Method, e.URL)
		fmt.Fprintf(&b, "- 凭证形态：`%s`\n", e.ParamKind)
		fmt.Fprintf(&b, "- 判读：`%s`（%s）\n", e.Verdict, e.Evidence)
		if e.Note != "" {
			fmt.Fprintf(&b, "- 备注：%s\n", e.Note)
		}
		if e.Err != "" {
			fmt.Fprintf(&b, "- 错误：`%s`\n", e.Err)
		}
		if len(e.NewKeys) > 0 {
			fmt.Fprintf(&b, "- 新增记录标识：`%s`\n", strings.Join(e.NewKeys, ", "))
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
