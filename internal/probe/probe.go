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
	"net/http"
	"regexp"
	"strings"

	"github.com/hdufuck/skl/pkg/signin"
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
	// VerdictURITooLong：请求行超长，被网关拒绝（`414` 是 `har#3` 实测；`413` 同类、未实测，一并归到这一类）。
	//
	// `har#3` 抓包第 6/10 条：`TRACELESS` 的 `data` 会膨胀到 25 KB 量级，
	// 整条 URL 超过网关的请求行上限（实测包线：请求行 5615 ≤ L < 27839 字节，即完整 URL 5623 ≤ L < 27847），
	// 服务端返回 `414 URI too long`（`text/plain`、无 CORS、
	// 带 `X-Kong-Response-Latency`）——**应用层根本没收到这个请求**，
	// 因此它既不指向人机层也不指向参数层，必须单独成一类。
	VerdictURITooLong Verdict = "uri_too_long"
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
	case VerdictURITooLong:
		return "强（网关拒绝请求行，未达应用）"
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
	// CaptchaVerifyCode 是响应里 captchaVerifyCode 的值（成功 `T001` /
	// 失败 `F001`）。该字段由 `har#3` 抓包首次观察到；为空串表示缺失。
	CaptchaVerifyCode string
	// CheckCodeDtoLen 是响应里 checkCodeDto 序列化后的字节长度。
	CheckCodeDtoLen int
}

// Classify 把一档探针的观测映射成判读结论。
//
// 规则顺序即优先级：先看「有没有写入记录」（最强的行为证据），再看网关层，
// 再看业务码，最后看文案。
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

	// 网关在请求行阶段就拒了，应用层没有任何参与。
	if in.Status == http.StatusRequestEntityTooLarge || in.Status == http.StatusRequestURITooLong {
		return VerdictURITooLong
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

	// captchaVerifyResult 是主判据；缺失时用 captchaVerifyCode 补充。
	captchaResult := in.CaptchaVerifyResult
	if captchaResult == nil {
		if passed, ok := captchaCodeVerdict(in.CaptchaVerifyCode); ok {
			captchaResult = &passed
		}
	}
	if captchaResult != nil {
		if !*captchaResult {
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

// captchaCodeVerdict 把 captchaVerifyCode 翻译成人机判定。
//
// 只认 `har#3` 抓包里实测到的两个值（成功 `T001` / 失败 `F001`）；
// 其它值一律「没有意见」，交由 captchaVerifyResult 或文案判断。
func captchaCodeVerdict(code string) (bool, bool) {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "T001":
		return true, true
	case "F001":
		return false, true
	default:
		return false, false
	}
}

// LongestAcceptedURLLen 是 `har#3` 采集中**被服务端接受**的最长请求 URL
// （字节，含 `https://skl.hdu.edu.cn` 的 22 字节）。
//
// 同一采集里 27847 字节的同类 URL 被网关以 `414 URI too long` 拒掉。
// 换算成**请求行**（减掉 scheme+host 的 22 字节，加上 `POST ` 与 ` HTTP/1.1`
// 的 14 字节，即整体 −8）就是：实测接受的请求行是 5615，被拒的是 27839。
//
// ⚠️ 这只是**已实测的最长值，不是服务端上限**：真实上限落在
// [5623, 27846] 这个区间里，本采集的 5 个数据点无法把它再收窄
// （nginx 默认的 8k 就落在区间内，但无证据）。所以它只配当预警信号。
const LongestAcceptedURLLen = 5623

// URLTooLongHint 在 URL 超过已实测的接受值时给出预警文案；否则返回空串。
//
// urlLen 是**完整 URL**（含 scheme+host）的字节数，即 `len(ex.URL)`。
func URLTooLongHint(urlLen int) string {
	if urlLen <= LongestAcceptedURLLen {
		return ""
	}
	return fmt.Sprintf("URL 长 %d 字节，超过已实测的接受值（%d）⟹ 大概率被网关判 414（`har#3` 抓包）",
		urlLen, LongestAcceptedURLLen)
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

// ForgeParam 构造一个「结构合法但内容伪造」的 captchaVerifyParam。
//
// sample 是一份真实的 captchaVerifyParam（可为空）。实现委托给
// signin.ForgeCaptchaParam，保证探针与库只有一份伪造实现、不会漂移。
func ForgeParam(sample string) string {
	return signin.ForgeCaptchaParam(sample)
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

// MaskID 是**持久化草稿**里学号的打码形式：只留前 2 位与最后 1 位。
//
// 例：`24000000` → `24*****0`。
//
// 终端输出**不**打码（方便当场核对是谁、是不是本次窗口），所以这里只服务
// 「落盘的 markdown 草稿」这一条路径 —— 那份草稿是往 docs/ 抄的原料。
func MaskID(id string) string {
	r := []rune(id)
	if len(r) <= 3 {
		return id
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-3) + string(r[len(r)-1:])
}

// MaskedName 是持久化草稿里替掉真实姓名的占位名。
//
// 只留姓氏（`张**`）也会泄露「是哪个姓的老师/同学」，所以一位都不留。
const MaskedName = "张三"

var (
	// 会话凭据在响应体里可能以 JSON 字段或 query 形态出现，落盘到 markdown 前一律抹掉。
	redactJSONFieldRe  = regexp.MustCompile(`(?i)("(?:token|sessionid|x-auth-token|skl-ticket)"\s*:\s*")[^"]*(")`)
	redactQueryValueRe = regexp.MustCompile(`(?i)\b(token|sessionId|x-auth-token|skl-ticket)=([^&\s"']+)`)
	// 响应体里形如 "key":"value" 的字符串字段，用于按字段名挑出要打码的那些。
	bodyStringFieldRe = regexp.MustCompile(`"(?i)([a-z]+)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
)

// RedactBody 打码响应体里会随草稿持久化的敏感内容：会话凭据，以及指向
// 「人 / 课程 / 考勤记录 / 时刻」的字段。
//
// 打码方式与 docs/signin-success-sample.md 第 8 节一致：学号只留前 2 后 1、
// 人名换占位名、课程与记录标识换占位符、时间值换 Go 参考时间格式。
//
// 只用于渲染落盘的 markdown 草稿；原始 JSON 报告保留未脱敏 body（已 gitignore），
// 终端输出**完全不经过**这里。
func RedactBody(body string) string {
	out := redactJSONFieldRe.ReplaceAllString(body, "${1}<redacted>${2}")
	out = redactQueryValueRe.ReplaceAllString(out, "${1}=<redacted>")
	return bodyStringFieldRe.ReplaceAllStringFunc(out, func(match string) string {
		sub := bodyStringFieldRe.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		masked, ok := maskBodyValue(strings.ToLower(sub[1]), sub[2])
		if !ok {
			return match
		}
		return `"` + sub[1] + `":"` + masked + `"`
	})
}

// maskBodyValue 给出某个响应体字段的打码结果；第二个返回值表示是否认识这个字段。
//
// 不认识的字段原样保留：签到码本身无隐私（见 CONTEXT.md 与探针手册 §4.2），
// 纬度、周次这类协议字段也不指向人。
func maskBodyValue(key, value string) (string, bool) {
	switch key {
	case "studentid":
		return MaskID(value), true
	case "teachname", "teachername":
		return MaskedName, true
	case "teacherid":
		return "<教师工号，已打码>", true
	case "coursename":
		return "<课程名，已打码>", true
	case "courseid":
		return "<课程 ID，已打码>", true
	case "courseschemaid":
		return "<课程 schema ID，已打码>", true
	case "id":
		// CheckInRecord 主键：能追回那一条考勤记录。
		return "<记录主键，已打码>", true
	case "expiresdate":
		return "2006-01-02T15:04:05.000Z", true
	case "recorddate":
		return "2006-01-02T00:00:00.000Z", true
	default:
		return "", false
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
