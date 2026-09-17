// Package probe 实现「一次性签到探针」的纯逻辑部分：档位定义、请求之后的
// 考勤记录读回、脱敏与报告渲染。
//
// 一次窗口只做一件事：验证库的 `SignIn` 封装路径可用，并取回一条活路径成功样本。
// 因此本机只有真值档一档（RungCaptchaGenuine）——由浏览器里的官方 SDK 产出
// captchaVerifyParam，再交给库的 SignIn 送出去。
//
// 为什么不再探测「人机验证是否强制」：
//
//   - 活路径必带参数——现行前端只有 `captcha-verify` 一条活着的签到路径，而它只在
//     阿里云 SDK 出参之后才提交；
//   - 遗留端点 `code-check-in` 在前端构建里零调用者，两份 HAR 里也从未出现；
//   - 本机缺参只能拿到单边结果——签到码校验先于人机校验，缺失/伪造/不传参数都会
//     得到同一个 `401 签到码不存在`，一次失败无法区分「服务端真的不校验」与
//     「校验了但错误不可判读」（依据见 docs/api.md §3.2）。
//
// 三条加起来，前置档给出的信息量低于它们带来的先验污染与窗口成本：在真值档之前
// 对同一个 userid+scene 打几次失败的人机提交，会把 `F001` 的归属搅浑。
// 决策见 ADR 0004。
//
// 它**不做判读**：只把请求/响应，以及请求之后读到的考勤记录原样记下来，
// 由人去看。这里的代码不直接发起任何网络请求，也不启动浏览器；网络与浏览器行为由
// 调用方（cmd/signinprobe）注入，因此全部可单测。
package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ToolVersion 是报告里记录的工具版本。
const ToolVersion = "signinprobe/1"

// RungID 标识一条证据来源。
//
// 不再是「从弱到强的阶梯」：本机只跑真值档，RungPhoneCaptcha 是手机端 Reqable
// 上报回来的那次官方签到，两条来源互相独立。
type RungID string

const (
	// RungCaptchaGenuine 是活路径 `captcha-verify`，**真值** captchaVerifyParam
	// （由浏览器里的官方 SDK 产出），走库的 SignIn 封装。
	RungCaptchaGenuine RungID = "captcha-verify-genuine"
	// RungPhoneCaptcha 不是本机跑的档位：它是手机端 Reqable 上报的那次官方签到。
	RungPhoneCaptcha RungID = "phone-captcha-verify"
)

// Title 返回档位的中文标题。
func (r RungID) Title() string {
	switch r {
	case RungCaptchaGenuine:
		return "活路径 captcha-verify（官方 SDK 真值 → 库 SignIn）"
	case RungPhoneCaptcha:
		return "手机端官方签到（Reqable 上报）"
	default:
		return string(r)
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
