package probe

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers []harHeader `json:"headers"`
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

// resolvedURL 是这条 HAR 记录里真正被请求的 URL。
//
// 不能直接信 `request.url`：见 authorityFromHost。
func (e harEntry) resolvedURL() string {
	return authorityFromHost(e.Request.URL, hostHeader(e.Request.Headers))
}

// hostHeader 取请求头里的 Host；没有就返回空串（HAR 里 Host 常被写成普通头）。
func hostHeader(hs []harHeader) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, "Host") {
			return h.Value
		}
	}
	return ""
}

// authorityFromHost 用请求的 Host 头改写 URL 的 authority。
//
// 为什么需要：Reqable 有时会把 `request.url` 写成另一个权威——实测一条
// captcha-verify 的 url 是 `https://sso.hdu.edu.cn/...`，而同一条请求的
// `Host` 头是 `skl.hdu.edu.cn`（那是 Reqable 的字段伪影）。照抄 `url` 会把
// 报告里的目标主机写错，进而误导判读，所以只信 Host 头：scheme、path、
// query 原样保留，Host 头自带端口时端口也保留。
//
// host 为空、URL 解析失败/无权威、或与 URL 主机相同时，原样返回 rawURL。
func authorityFromHost(rawURL, host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	if strings.EqualFold(u.Host, host) {
		return rawURL
	}
	u.Host = host
	return u.String()
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
		if strings.Contains(e.resolvedURL(), SignInCaptchaPath) {
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
		URL:       RedactURL(chosen.resolvedURL()),
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

	entry.CaptchaVerifyCode = hintsFrom(entry.Body).captchaVerifyCode
	return entry, nil
}

// decodeHookBody 按 Content-Encoding 解压上报体。
//
// Reqable 的上报服务器支持 gzip / brotli / zstd / none；本实现只支持 gzip 与
// deflate（零额外依赖），其余给出可操作的错误提示。
// 另外兼容「声明没压缩、实际是 gzip」的情况（按魔数识别）。
func decodeHookBody(raw []byte, contentEncoding string) ([]byte, error) {
	switch enc := strings.ToLower(strings.TrimSpace(contentEncoding)); enc {
	case "", "identity":
		if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
			return gunzip(raw)
		}
		return raw, nil
	case "gzip", "x-gzip":
		return gunzip(raw)
	case "deflate":
		zr := flate.NewReader(bytes.NewReader(raw))
		defer func() { _ = zr.Close() }()
		return io.ReadAll(io.LimitReader(zr, maxHookBodyBytes))
	default:
		return nil, fmt.Errorf("不支持的压缩算法 %q", enc)
	}
}

func gunzip(raw []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(io.LimitReader(zr, maxHookBodyBytes))
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

		// Reqable 的上报服务器可选 gzip/brotli/zstd/none；本实现只支持 gzip/deflate。
		body, err = decodeHookBody(body, r.Header.Get("Content-Encoding"))
		if err != nil {
			logf("hook: 解压上报体失败: %v（请把上报服务器的压缩选成 gzip 或 none）", err)
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
