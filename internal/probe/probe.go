// Package probe 实现「一次性签到探针」的纯逻辑部分：阶梯定义、请求之后的
// 考勤记录读回、脱敏与报告渲染。
//
// 它**不做判读**：只把每档的请求/响应，以及该档之后读到的考勤记录原样记下来，
// 由人去看。这里的代码不直接发起任何网络请求，也不启动浏览器；网络与浏览器行为由
// 调用方（cmd/signinprobe）注入，因此全部可单测。
package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
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
// 不含 RungCaptchaGenuine 时即为「档 1–3」。
var Ladder = []RungID{
	RungLegacyCheckIn,
	RungCaptchaMissing,
	RungCaptchaForged,
	RungCaptchaGenuine,
}

// ParseLadder 把命令行给出的阶梯规格解析成开火顺序。
//
// 接受的写法（大小写不敏感、首尾空格忽略）：
//
//	"" / "all"          → (nil, nil)：不覆盖，Run 回落到包级 Ladder 的默认顺序
//	"genuine"            → 只跑真值档
//	"junk"（别名 "pre"） → 三档非真值档，默认顺序
//	逗号分隔的档位 ID     → 严格按给定顺序，如 "captcha-verify-genuine,code-check-in"
//
// 为什么需要「只跑真值档 / 把真值档排最前」：前置三档会在真值档之前几秒，
// 对同一个 userid+scene 打出失败的（缺失/伪造）人机提交——这是真值档 F001
// 判读的混淆项。真实窗口昂贵且一次性，操作者必须能排除这个先验污染，
// 单独跑一次真值档来回答「库的 SignIn 路径能否走通」。
//
// 未识别的档位 ID、空的列表元素都返回错误，并在错误里列出合法档位。
func ParseLadder(spec string) ([]RungID, error) {
	s := strings.TrimSpace(spec)
	switch strings.ToLower(s) {
	case "", "all":
		// 刻意返回 nil 而不是 Ladder 的副本：nil 表示「未覆盖」，
		// 保证 Config.Ladder 与 Ladder 之间的默认语义只有一处。
		return nil, nil
	case "genuine":
		return []RungID{RungCaptchaGenuine}, nil
	case "junk", "pre":
		return []RungID{RungLegacyCheckIn, RungCaptchaMissing, RungCaptchaForged}, nil
	}

	parts := strings.Split(s, ",")
	out := make([]RungID, 0, len(parts))
	for _, part := range parts {
		id := RungID(strings.ToLower(strings.TrimSpace(part)))
		if id == "" {
			return nil, fmt.Errorf("probe: 阶梯规格 %q 里有空的档位 ID；合法档位：%s，或 all / genuine / junk",
				spec, strings.Join(ladderIDs(), ", "))
		}
		if !slices.Contains(Ladder, id) {
			return nil, fmt.Errorf("probe: 未知档位 %q；合法档位：%s，或 all / genuine / junk",
				id, strings.Join(ladderIDs(), ", "))
		}
		out = append(out, id)
	}
	return out, nil
}

// ladderIDs 返回 Ladder 上各档的 ID 字符串，用于错误提示。
func ladderIDs() []string {
	ids := make([]string, len(Ladder))
	for i, r := range Ladder {
		ids[i] = string(r)
	}
	return ids
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
