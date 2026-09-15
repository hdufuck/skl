// Package probe 实现「一次性签到探针」的纯逻辑部分：阶梯定义、请求判读、
// 读回比对、脱敏与报告渲染。
//
// 这里的代码不直接发起任何网络请求，也不启动浏览器；网络与浏览器行为由
// 调用方（cmd/signinprobe）注入，因此全部可单测。
package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hdufuck/skl"
)

// ToolVersion 是报告里记录的工具版本。
const ToolVersion = "signinprobe/1"

// RungID 标识阶梯上的一档探针。
//
// 顺序即开火顺序：从「不需要人机验证」到「需要人机验证」。
type RungID string

const (
	// RungAnalyzeA0 是遗留 JSONP 端点 `check-code-analyze`，显式上报 `a=0`
	// （表示未做人机验证），且完全不传定位。
	RungAnalyzeA0 RungID = "analyze-a0"
	// RungLegacyCheckIn 是遗留端点 `code-check-in`，不传人机凭证，需要定位。
	RungLegacyCheckIn RungID = "code-check-in"
	// RungCaptchaMissing 是活路径 `captcha-verify`，**缺失** captchaVerifyParam。
	RungCaptchaMissing RungID = "captcha-verify-missing"
	// RungCaptchaForged 是活路径 `captcha-verify`，**伪造** captchaVerifyParam。
	RungCaptchaForged RungID = "captcha-verify-forged"
	// RungCaptchaGenuine 是活路径 `captcha-verify`，**真值** captchaVerifyParam
	// （由浏览器里的官方 SDK 产出），走库的 SignIn 封装。
	RungCaptchaGenuine RungID = "captcha-verify-genuine"
	// RungPhoneCaptcha 不是本机阶梯的一档：它是手机端 Reqable 上报的那次官方签到。
	RungPhoneCaptcha RungID = "phone-captcha-verify"
)

// Ladder 是按开火顺序排列的全部档位。
//
// 不含 RungCaptchaGenuine 时即为「档 1–4」。
var Ladder = []RungID{
	RungAnalyzeA0,
	RungLegacyCheckIn,
	RungCaptchaMissing,
	RungCaptchaForged,
	RungCaptchaGenuine,
}

// ParamKind 描述该档携带的人机凭证形态。
type ParamKind string

const (
	// ParamNone 表示请求里根本没有 captchaVerifyParam。
	ParamNone ParamKind = "none"
	// ParamForged 表示结构合法但内容伪造。
	ParamForged ParamKind = "forged"
	// ParamGenuine 表示由官方 SDK 产出的真值。
	ParamGenuine ParamKind = "genuine"
)

// Title 返回档位的中文标题。
func (r RungID) Title() string {
	switch r {
	case RungAnalyzeA0:
		return "遗留 JSONP check-code-analyze（a=0，无人机凭证，无定位）"
	case RungLegacyCheckIn:
		return "遗留 code-check-in（无人机凭证，带定位）"
	case RungCaptchaMissing:
		return "活路径 captcha-verify（缺失 captchaVerifyParam）"
	case RungCaptchaForged:
		return "活路径 captcha-verify（伪造 captchaVerifyParam）"
	case RungCaptchaGenuine:
		return "活路径 captcha-verify（官方 SDK 真值 → 库 SignIn）"
	default:
		return string(r)
	}
}

// ParamKind 返回该档携带的凭证形态。
func (r RungID) ParamKind() ParamKind {
	switch r {
	case RungCaptchaForged:
		return ParamForged
	case RungCaptchaGenuine:
		return ParamGenuine
	default:
		return ParamNone
	}
}

// Verdict 是一档探针的判读结论。
type Verdict string

const (
	// VerdictSuccess：业务层明确成功（或真值档写入了记录）。
	VerdictSuccess Verdict = "success"
	// VerdictWrittenNoCaptcha：该档没带人机凭证/带的是假凭证，却写入了真实
	// 考勤记录 —— 这是「不强制人机验证」的强证据。
	VerdictWrittenNoCaptcha Verdict = "written_without_captcha"
	// VerdictCaptchaRejected：响应明确指向人机层。
	VerdictCaptchaRejected Verdict = "captcha_layer_rejected"
	// VerdictParamRejected：参数层就要求人机凭证（400 + 参数缺失/非法）。
	VerdictParamRejected Verdict = "param_layer_rejected"
	// VerdictCodeRejected：签到码不存在/无效。因为签到码校验先于人机校验，
	// 这条对「是否强制」不构成证据。
	VerdictCodeRejected Verdict = "code_rejected"
	// VerdictEmptyBody：200 但响应体为空（skl-ticket 重放或被 WAF 拦截）。
	VerdictEmptyBody Verdict = "empty_body"
	// VerdictUnattributable：无法归因。
	VerdictUnattributable Verdict = "unattributable"
	// VerdictTransportError：请求根本没发出去或读不到响应。
	VerdictTransportError Verdict = "transport_error"
)

// Evidence 描述该判读结论的证据强度。
func (v Verdict) Evidence() string {
	switch v {
	case VerdictSuccess:
		return "强（业务成功）"
	case VerdictWrittenNoCaptcha:
		return "强（写入记录且未用真凭证）"
	case VerdictCaptchaRejected:
		return "强（指向人机层）"
	case VerdictParamRejected:
		return "强（指向参数层）"
	case VerdictCodeRejected:
		return "无（签到码先于风控校验）"
	case VerdictEmptyBody:
		return "无（工具/网络层）"
	case VerdictTransportError:
		return "无（工具/网络层）"
	default:
		return "无（不可归因）"
	}
}

// ClassifyInput 是判读一档探针所需的全部事实。
//
// 全部是字面量/可序列化值，便于把判读逻辑与 HTTP 客户端解耦。
type ClassifyInput struct {
	Rung   RungID
	Status int
	Body   []byte
	// Err 非空表示传输层错误（此时 Status 通常为 0）。
	Err string
	// Wrote 表示读回端点在本次探针之后出现了新记录。
	Wrote bool

	// AnalyzeCode 是该档为 RungAnalyzeA0 时，JSONP 响应里的 result.code；
	// 非该档时为 0。
	AnalyzeCode int
	// HasAnalyzeCode 区分 AnalyzeCode 的真实值 0 与「不适用」。
	HasAnalyzeCode bool

	// CaptchaVerifyResult 是响应里 captchaVerifyResult 的布尔值；缺失时为 nil。
	CaptchaVerifyResult *bool
	// CheckCodeDtoLen 是响应里 checkCodeDto 序列化后的字节长度。
	CheckCodeDtoLen int
}

// Classify 把一档探针的观测映射成判读结论。
//
// 规则顺序即优先级：先看「有没有写入记录」（最强的行为证据），再看业务码，
// 再看文案。
func Classify(in ClassifyInput) Verdict {
	if in.Err != "" && in.Status == 0 {
		return VerdictTransportError
	}

	if in.Wrote {
		if in.Rung == RungCaptchaGenuine {
			return VerdictSuccess
		}
		return VerdictWrittenNoCaptcha
	}

	if in.Status == 200 && len(strings.TrimSpace(string(in.Body))) == 0 {
		return VerdictEmptyBody
	}

	if in.HasAnalyzeCode {
		switch in.AnalyzeCode {
		case 100, 200:
			return VerdictSuccess
		case 400:
			return VerdictCaptchaRejected
		case 800, 900:
			return VerdictCodeRejected
		}
	}

	if in.CaptchaVerifyResult != nil {
		if !*in.CaptchaVerifyResult {
			return VerdictCaptchaRejected
		}
		if in.CheckCodeDtoLen > 0 {
			return VerdictSuccess
		}
		// captchaVerifyResult=true 但 checkCodeDto 为空：形状未知，不硬判。
		return VerdictUnattributable
	}

	msg := extractMsg(in.Body)
	switch {
	case msg == "":
		// 无 msg 可读时，只有活路径的 400 才敢归因到参数层。
		if in.Status == 400 && isCaptchaRung(in.Rung) {
			return VerdictParamRejected
		}
		return VerdictUnattributable
	case containsAny(msg, "签到码"):
		return VerdictCodeRejected
	case containsAny(msg, "人机", "滑块", "验证码", "captcha", "Captcha"):
		return VerdictCaptchaRejected
	case in.Status == 400 && isCaptchaRung(in.Rung):
		return VerdictParamRejected
	default:
		return VerdictUnattributable
	}
}

func isCaptchaRung(r RungID) bool {
	return r == RungCaptchaMissing || r == RungCaptchaForged || r == RungCaptchaGenuine
}

// extractMsg 从 `{"code":0,"msg":"..."}` 形态里取 msg。
func extractMsg(body []byte) string {
	var envelope struct {
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}
	return envelope.Msg
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Snapshot 是某一时刻读回端点（今日签到明细）的观测。
type Snapshot struct {
	// Count 是明细条数。
	Count int
	// Keys 是每一条明细的稳定标识。
	Keys []string
}

// NewKeys 返回相对 prev 新增的明细标识。
func (s Snapshot) NewKeys(prev Snapshot) []string {
	seen := make(map[string]struct{}, len(prev.Keys))
	for _, k := range prev.Keys {
		seen[k] = struct{}{}
	}
	var out []string
	for _, k := range s.Keys {
		if _, ok := seen[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

// SnapshotFromRaw 从 `/api/check-in-student-detail/my` 的裸数组里构造快照。
//
// 元素形态未实测，所以优先用 `id` 字段做稳定标识；没有 `id` 时退化为
// 内容哈希（同一份内容前后一致即可用于 diff）。
func SnapshotFromRaw(raw []json.RawMessage) Snapshot {
	s := Snapshot{Count: len(raw)}
	for _, item := range raw {
		s.Keys = append(s.Keys, itemKey(item))
	}
	return s
}

func itemKey(item json.RawMessage) string {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(item, &probe); err == nil && len(probe.ID) > 0 {
		if s := strings.Trim(string(probe.ID), `"`); s != "" && s != "null" {
			return "id:" + s
		}
	}
	sum := sha256.Sum256(item)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// ForgeDefaults 是找不到真实样本时，伪造 captchaVerifyParam 所用的字段长度。
//
// 长度取自 2026-09-14 抓包里的真实值量级，目的是让伪造值在长度维度上
// 与真值一致，避免被「长度异常」这一条单独拒掉。
var ForgeDefaults = struct {
	CertifyIDLen   int
	DeviceTokenLen int
	DataLen        int
}{CertifyIDLen: 10, DeviceTokenLen: 220, DataLen: 120}

// ForgeParam 构造一个「结构合法但内容伪造」的 captchaVerifyParam。
//
// sample 是一份真实的 captchaVerifyParam（可为空）。给了样本时逐字段沿用
// 其长度、只把内容换成等长的 'A'；没给样本时用 ForgeDefaults。
// sceneId 始终沿用真值。
func ForgeParam(sample string) string {
	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	_ = json.Unmarshal([]byte(sample), &parsed)

	sceneID := parsed.SceneID
	if sceneID == "" {
		sceneID = skl.DefaultCaptchaSceneID
	}
	certifyLen := len(parsed.CertifyID)
	deviceLen := len(parsed.DeviceToken)
	dataLen := len(parsed.Data)
	if sample == "" || certifyLen == 0 {
		certifyLen = ForgeDefaults.CertifyIDLen
	}
	if sample == "" || deviceLen == 0 {
		deviceLen = ForgeDefaults.DeviceTokenLen
	}
	if sample == "" || dataLen == 0 {
		dataLen = ForgeDefaults.DataLen
	}

	forged := struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}{
		SceneID:     sceneID,
		CertifyID:   strings.Repeat("A", certifyLen),
		DeviceToken: strings.Repeat("A", deviceLen),
		Data:        strings.Repeat("A", dataLen),
	}
	out, err := json.Marshal(forged)
	if err != nil {
		return ""
	}
	return string(out)
}

// RedactCaptchaParam 按文档的脱敏规则处理 captchaVerifyParam：
// 保留 sceneId、certifyId，其余字段只留长度与前 20 字符。
func RedactCaptchaParam(param string) string {
	if param == "" {
		return ""
	}
	parsed := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(param), &parsed); err != nil {
		return truncateRunes(param, 20) + fmt.Sprintf("…(len=%d)", len(param))
	}

	out := make(map[string]any, len(parsed))
	for k, v := range parsed {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			out[k] = "<non-string>"
			continue
		}
		switch k {
		case "sceneId", "certifyId":
			out[k] = s
		default:
			out[k] = truncateRunes(s, 20) + fmt.Sprintf("…(len=%d)", len(s))
		}
	}
	buf, err := json.Marshal(out)
	if err != nil {
		return "<unprintable>"
	}
	return string(buf)
}

// RedactURL 抹掉 URL 里的会话凭据，并对 captchaVerifyParam 做字段级脱敏。
func RedactURL(raw string) string {
	i := strings.IndexByte(raw, '?')
	if i < 0 {
		return raw
	}
	base, query := raw[:i], raw[i+1:]
	parts := strings.Split(query, "&")
	for idx, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "token", "sessionId":
			parts[idx] = key + "=<redacted>"
		case "captchaVerifyParam":
			parts[idx] = key + "=" + RedactCaptchaParam(value)
		}
	}
	return base + "?" + strings.Join(parts, "&")
}

// RedactHeaders 只保留与判读相关的响应头，绝不透出会话凭据。
func RedactHeaders(h map[string][]string) map[string]string {
	keep := []string{"Content-Type", "Content-Encoding", "Content-Length", "Date", "Server"}
	out := make(map[string]string)
	for _, k := range keep {
		for actual, values := range h {
			if strings.EqualFold(actual, k) && len(values) > 0 {
				out[k] = values[0]
			}
		}
	}
	return out
}

// MaskID 保留前 4 位，其余打码。
func MaskID(id string) string {
	if len(id) <= 4 {
		return id
	}
	return id[:4] + strings.Repeat("*", len(id)-4)
}

// MaskName 只留姓氏，其余一律打成两个星号。
//
// 按 rune 处理，不会把中文名字切成乱码；星号数量固定，不额外泄露名字有几个字。
// 脚本只打这一处姓名（登录成功那条日志），报告里本来就只写打码后的学号。
func MaskName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return string([]rune(name)[0]) + "**"
}

var (
	// 会话凭据在响应体里可能以 JSON 字段或 query 形态出现，落盘到 markdown 前一律抹掉。
	redactJSONFieldRe  = regexp.MustCompile(`(?i)("(?:token|sessionid|x-auth-token|skl-ticket)"\s*:\s*")[^"]*(")`)
	redactQueryValueRe = regexp.MustCompile(`(?i)\b(token|sessionId|x-auth-token|skl-ticket)=([^&\s"']+)`)
)

// RedactBody 抹掉响应体里可能出现的会话凭据。
//
// 只用于渲染可提交的 markdown；原始 JSON 报告保留未脱敏 body，且已被 gitignore。
func RedactBody(body string) string {
	out := redactJSONFieldRe.ReplaceAllString(body, "${1}<redacted>${2}")
	return redactQueryValueRe.ReplaceAllString(out, "${1}=<redacted>")
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
