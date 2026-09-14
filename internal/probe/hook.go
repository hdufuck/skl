package probe

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hdufuck/skl"
)

// SignInCaptchaPath 是活路径签到接口，手机 HAR 里用它来定位那条铁证。
const SignInCaptchaPath = skl.PathSignInCaptchaVerify

// maxHookBodyBytes 限制上报体大小，避免异常请求打爆内存。
const maxHookBodyBytes = 32 << 20

type harDoc struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string `json:"startedDateTime"`
	Request         struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response struct {
		Status  int         `json:"status"`
		Headers []harHeader `json:"headers"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParseHARExchange 从 Reqable 上报服务器发来的 HAR 文档里，挑出手机端那次
// `captcha-verify` 请求/响应。
//
// 选择规则：优先取最后一条 HTTP 200 的；没有 200 时取最后一条命中的。
// 这样即使上报里混入了失败的签到，也能拿到成功那条。
func ParseHARExchange(body []byte) (*Entry, error) {
	var doc harDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("probe: 解析 HAR 失败: %w", err)
	}

	var matched []harEntry
	for _, e := range doc.Log.Entries {
		if strings.Contains(e.Request.URL, SignInCaptchaPath) {
			matched = append(matched, e)
		}
	}
	if len(matched) == 0 {
		return nil, errors.New("probe: HAR 里没有 captcha-verify 请求")
	}

	chosen := matched[len(matched)-1]
	for i := len(matched) - 1; i >= 0; i-- {
		if matched[i].Response.Status == http.StatusOK {
			chosen = matched[i]
			break
		}
	}

	respBody := chosen.Response.Content.Text
	if strings.EqualFold(chosen.Response.Content.Encoding, "base64") && respBody != "" {
		decoded, err := base64.StdEncoding.DecodeString(respBody)
		if err == nil {
			respBody = string(decoded)
		}
	}

	entry := &Entry{
		Rung:      RungPhoneCaptcha,
		Title:     "手机端官方签到（Reqable 上报）",
		Method:    chosen.Request.Method,
		URL:       RedactURL(chosen.Request.URL),
		ParamKind: ParamGenuine,
		Status:    chosen.Response.Status,
		Body:      strings.TrimSpace(respBody),
		FromPhone: true,
	}
	if chosen.StartedDateTime != "" {
		if ts, err := time.Parse(time.RFC3339, chosen.StartedDateTime); err == nil {
			entry.At = ts
		}
	}

	headers := map[string][]string{}
	for _, h := range chosen.Response.Headers {
		headers[h.Name] = append(headers[h.Name], h.Value)
	}
	entry.RespHeaders = RedactHeaders(headers)

	hints := hintsFrom(RungCaptchaGenuine, entry.Body)
	entry.Verdict = Classify(ClassifyInput{
		Rung:                RungCaptchaGenuine,
		Status:              entry.Status,
		Body:                []byte(entry.Body),
		CaptchaVerifyResult: hints.cvr,
		CheckCodeDtoLen:     hints.dtoLen,
	})
	entry.Evidence = entry.Verdict.Evidence()
	return entry, nil
}

// NewHookHandler 返回 Reqable「上报服务器」的接收端点。
//
// Reqable 每完成一个会话就 POST 一份 HAR JSON 过来；本 handler 解析出
// captcha-verify 那条并推入 ch（推不进去就丢弃，不阻塞、不影响抓包）。
// 无论解析成败都返回 200，因为 Reqable 不会重试。
func NewHookHandler(ch chan<- Entry, logf func(format string, args ...any)) http.Handler {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxHookBodyBytes))
		if err != nil {
			logf("hook: 读取上报体失败: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		entry, err := ParseHARExchange(body)
		if err != nil {
			// 绝大多数上报（无关请求）都会走到这里，不算错误。
			logf("hook: 忽略一次上报（%v）", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		select {
		case ch <- *entry:
			logf("hook: 收到手机端 captcha-verify（HTTP %d）", entry.Status)
		default:
			logf("hook: 通道已满，丢弃一条上报")
		}
		w.WriteHeader(http.StatusOK)
	})
}
