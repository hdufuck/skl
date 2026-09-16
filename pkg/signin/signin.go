// Package signin 把 skl 的几条签到路径暴露成可枚举、可逐个调用的公开 API。
//
// 它**消费调用方传入的 *skl.Client**，自己不拥有会话：登录、token 注入与
// 重登仍由根包 github.com/hdufuck/skl 负责。典型用法：
//
//	client, err := skl.NewClient(
//	    skl.WithHTTPClient(myTunneledHTTPClient),
//	    skl.WithSSOAuthenticator(skl.SSOAuthenticatorFunc(sso.Auth)),
//	    skl.WithCredentials(user, pass),
//	)
//	// ... 会话获取仍走根包
//	s := signin.New(client)
//	out, err := s.Genuine(ctx, signin.Request{
//	    Code: "1212", Latitude: 30.123456, Longitude: 120.654321,
//	})
//
// # 六条路径
//
//	Analyze      GET  /api/ali-nvc/check-code-analyze（JSONP，a=0，无定位）
//	Legacy       GET  /api/checkIn/code-check-in
//	WithoutParam POST /api/ali-nvc/captcha-verify，**缺失** captchaVerifyParam
//	Forged       POST /api/ali-nvc/captcha-verify，结构合法但伪造的凭证
//	WithParam    POST /api/ali-nvc/captcha-verify，强制使用调用方给定的凭证
//	Genuine      POST /api/ali-nvc/captcha-verify，用给定凭证或问 CaptchaProvider
//
// 每条路径都接受 context.Context 并尊重它的超时；Client 可并发使用。
//
// # 这个包刻意不做的事
//
//   - **不判读结果**：Outcome 只装状态码、原始响应与解好的结构，不告诉你
//     「是否强制人机验证」。归因（Verdict）留在 internal/probe 与调用方。
//   - **不在路径之间自动降级**：尝试了哪几条、哪条成功了，是调用方的显式选择。
//   - **不自动重试** `200` + 空 body：SklTicket 是一次性的，退避与重投策略
//     由调用方决定。
//   - 不做读回比对，不具备会话能力。
//
// # ⚠️ 合规与证据强度
//
// WithoutParam / WithParam / Forged / ForgeCaptchaParam 都会向
// `/api/ali-nvc/captcha-verify` 发出**真实请求**：一旦服务端不强制人机验证，
// 它们可能写入真实的 CheckInRecord。这些能力照常公开，只靠文档警告，
// 后果由使用者承担。
//
// 本机发出的**失败**只作弱证据（ADR 0002）：客户端指纹、出口 IP 与 WAF
// 都可能是失败原因，不能据此判定「服务端强制人机验证」。Legacy / Analyze
// 两条遗留路径同理 —— 它们成功即证明不强制，失败则不可解释。
package signin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// Request 描述一次签到调用的输入。
type Request struct {
	// Code 是老师公布的 4 位签到码（SignInCode）。
	Code string
	// Latitude / Longitude 是当前定位；只有带定位的路径读取它们。
	// 坐标系必须与前端一致（WGS-84），否则围栏距离会偏。
	Latitude  float64
	Longitude float64
	// UserID 为空时自动取当前登录用户的 id。
	UserID string

	// CaptchaVerifyParam 是调用方给定的真值/伪造值。
	//
	// 语义随路径而变：WithParam 强制使用它（空则报错）；Genuine 优先用它，
	// 为空时才去问 CaptchaProvider。它是一次性的，复用同一个值会被阿里云侧拒绝。
	CaptchaVerifyParam string

	// ForgeSample 是 Forged 路径的等长样本（一份真实的 CaptchaVerifyParam）。
	// 留空时用 ForgeDefaults 的长度。
	ForgeSample string
}

// Outcome 是一次签到调用的统一结果。
//
// 它**只装事实、不做判读**：是否「未携带真凭证却写入了记录」、是否
// 「指向人机层/参数层」这类归因由调用方决定。SignIn 与 Analyze 互斥，
// 取决于调用的路径。
type Outcome struct {
	// StatusCode 是 HTTP 状态码；传输层失败且读不到响应时为 0。
	StatusCode int
	// Response 是原始响应（可能为 nil，例如请求根本没发出去）。
	Response *skl.Response
	// SignIn 是 captcha-verify / code-check-in 体裁的响应；解析失败或该路径
	// 不解这种体裁时为 nil。
	SignIn *skl.SignInResult
	// Analyze 是 check-code-analyze 的响应；仅 Analyze 路径填充。
	Analyze *skl.AnalyzeResult
}

// Client 是签到 API 的门面，消费调用方传入的 *skl.Client。
//
// 它**不拥有会话**：登录、token 注入与重登都由传入的 client 负责。
// Client 可并发使用（自身不持有可变状态）。
type Client struct {
	client *skl.Client
}

// New 用一只已经构造好的 skl.Client 创建签到门面。
//
// 传入 nil 不 panic：各方法会返回「未提供 skl.Client」错误。
func New(client *skl.Client) *Client { return &Client{client: client} }

var (
	errNoClient = errors.New("signin: 未提供 skl.Client")
	errNoParam  = errors.New("signin: WithParam 需要非空的 CaptchaVerifyParam")
)

// Analyze 走遗留 JSONP 接口 `/api/ali-nvc/check-code-analyze`。
//
// 前端平时直接上报 `a=0`（表示未做人机验证），且完全不传定位；本方法沿用
// 这一形态。它是**最可能绕过人机验证**的路径之一。
//
// 关于 query 里的 `code`：本方法按探针与根包的既有形态传入 `req.Code`；
// 但 CONTEXT.md「定位就绪标志」记载该端点的 `code` 实为布尔标志、与签到码
// 无关（且所在路由不可达）。这里保持既有形态是为了复现探针路径，
// 不是在断言它的语义。
//
// ⚠️ 该接口的语义是「校验并签到」而不是「只校验」：传入有效签到码可能会
// 直接签到成功。失败只作单边弱证据（ADR 0002）。
func (c *Client) Analyze(ctx context.Context, req Request) (*Outcome, error) {
	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(ctx, &skl.Request{
		Method: http.MethodGet,
		Path:   skl.PathSignInAnalyze,
		Query: url.Values{
			"userid":   {userID},
			"code":     {req.Code},
			"token":    {c.client.Token()},
			"a":        {skl.AnalyzeNVCValueNone},
			"callback": {newJSONPCallback()},
		},
	})
	out := newOutcome(resp)
	if err != nil {
		return out, err
	}

	payload, err := unwrapJSONP(resp.Body)
	if err != nil {
		return out, fmt.Errorf("skl: 解析 %s 的 JSONP 响应失败: %w", skl.PathSignInAnalyze, err)
	}

	var envelope struct {
		Result struct {
			Code int `json:"code"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return out, fmt.Errorf("skl: 解析 %s 业务结果失败: %w (body=%s)", skl.PathSignInAnalyze, err, truncate(payload, 256))
	}

	// 提取 result 的原始 JSON（envelope 只解析了 code）。
	var raw struct {
		Result json.RawMessage `json:"result"`
	}
	_ = json.Unmarshal(payload, &raw)

	out.Analyze = &skl.AnalyzeResult{
		Code:     envelope.Result.Code,
		Raw:      raw.Result,
		Response: resp,
	}
	return out, nil
}

// Legacy 走遗留接口 `GET /api/checkIn/code-check-in`。
//
// 不携带人机凭证，带定位；定位只在非零时上报（沿用根包语义）。
//
// ⚠️ 同 Analyze：该接口的语义是「校验并签到」，传入有效签到码可能会直接
// 签到成功；失败只作单边弱证据（ADR 0002）。
func (c *Client) Legacy(ctx context.Context, req Request) (*Outcome, error) {
	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"code": {req.Code},
		"id":   {userID},
	}
	if req.Latitude != 0 || req.Longitude != 0 {
		query.Set("latitude", formatCoordinate(req.Latitude))
		query.Set("longitude", formatCoordinate(req.Longitude))
	}

	resp, err := c.client.Do(ctx, &skl.Request{
		Method: http.MethodGet,
		Path:   skl.PathSignInLegacy,
		Query:  query,
	})
	return c.finishSignIn(resp, err)
}

// WithoutParam 向 `/api/ali-nvc/captcha-verify` 发出「同形但缺
// CaptchaVerifyParam」的请求。
//
// query 只含 userid / code / latitude / longitude / t，**没有**
// captchaVerifyParam 键；body 为空但 Content-Type 仍是
// application/x-www-form-urlencoded —— 与官方请求逐字节同形，只少了那一个键。
// 这是根包 SignIn 拿不到的一档（后者会直接返回 ErrNoCaptchaProvider 且不发请求）。
//
// ⚠️ 一旦服务端不强制人机验证，这个请求可能写入真实 CheckInRecord。
func (c *Client) WithoutParam(ctx context.Context, req Request) (*Outcome, error) {
	return c.signInWithParam(ctx, req, "")
}

// WithParam 强制提交调用方给定的 CaptchaVerifyParam。
//
// 它**不会**落到 CaptchaProvider 上：参数为空时报错且不发请求。这让你可以
// 提交从 DevTools 复制的真值，而不必担心 provider 被意外触发。
//
// ⚠️ 会写入（或尝试写入）真实 CheckInRecord。
func (c *Client) WithParam(ctx context.Context, req Request) (*Outcome, error) {
	if req.CaptchaVerifyParam == "" {
		return nil, errNoParam
	}
	return c.signInWithParam(ctx, req, req.CaptchaVerifyParam)
}

// Forged 提交结构合法但内容伪造的 CaptchaVerifyParam
// （由 ForgeCaptchaParam(req.ForgeSample) 产出）。
//
// 用途是把「参数层拒绝」与「人机层拒绝」分开。
//
// ⚠️ 会写入（或尝试写入）真实 CheckInRecord。
func (c *Client) Forged(ctx context.Context, req Request) (*Outcome, error) {
	return c.signInWithParam(ctx, req, ForgeCaptchaParam(req.ForgeSample))
}

// Genuine 走真值路径：req.CaptchaVerifyParam 非空则直接用，
// 否则问 client 上配置的 CaptchaProvider。
//
// 两者都没有时返回 skl.ErrNoCaptchaProvider 且不发请求。
//
// ⚠️ 会写入（或尝试写入）真实 CheckInRecord。
func (c *Client) Genuine(ctx context.Context, req Request) (*Outcome, error) {
	param := req.CaptchaVerifyParam
	if param == "" {
		if c == nil || c.client == nil {
			return nil, errNoClient
		}
		provider := c.client.CaptchaProvider()
		if provider == nil {
			return nil, skl.ErrNoCaptchaProvider
		}
		var err error
		param, err = provider.CaptchaVerifyParam(ctx, c.client.CaptchaScene())
		if err != nil {
			return nil, fmt.Errorf("skl: 获取 captchaVerifyParam: %w", err)
		}
		if param == "" {
			return nil, skl.ErrNoCaptchaProvider
		}
	}
	return c.signInWithParam(ctx, req, param)
}

// signInWithParam 是所有 captcha-verify 路径共用的实现：
// param 为空即「缺失 captchaVerifyParam」那一档。
func (c *Client) signInWithParam(ctx context.Context, req Request, param string) (*Outcome, error) {
	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(ctx, &skl.Request{
		Method: http.MethodPost,
		Path:   skl.PathSignInCaptchaVerify,
		Query:  captchaVerifyQuery(req, userID, param, time.Now()),
		// 参数全在 query 里、body 为空，但官方请求仍带 form 头
		// （`har#3` 抓包第 101 条）——必须与之逐字节一致。
		ContentType: skl.ContentTypeFormURLEncoded,
	})
	return c.finishSignIn(resp, err)
}

// finishSignIn 把一次 captcha-verify / code-check-in 调用组装成 Outcome。
func (c *Client) finishSignIn(resp *skl.Response, err error) (*Outcome, error) {
	out := newOutcome(resp)
	if err != nil {
		return out, err
	}
	var result skl.SignInResult
	if jerr := resp.JSON(&result); jerr != nil {
		return out, jerr
	}
	result.Response = resp
	out.SignIn = &result
	return out, nil
}

// resolveUserID 返回显式传入的 userID，缺省时取当前登录用户 id。
func (c *Client) resolveUserID(ctx context.Context, userID string) (string, error) {
	if c == nil || c.client == nil {
		return "", errNoClient
	}
	if userID != "" {
		return userID, nil
	}
	user, err := c.client.User(ctx)
	if err != nil {
		return "", fmt.Errorf("skl: 无法确定 userid: %w", err)
	}
	if user.ID == "" {
		return "", errors.New("skl: /api/userinfo 未返回用户 id")
	}
	return user.ID, nil
}

// captchaVerifyQuery 构造 captcha-verify 的 query。
//
// param 为空时**不出现** captchaVerifyParam 键 —— 这正是 WithoutParam 那一档。
func captchaVerifyQuery(req Request, userID, param string, now time.Time) url.Values {
	query := url.Values{
		"userid":    {userID},
		"code":      {req.Code},
		"latitude":  {formatCoordinate(req.Latitude)},
		"longitude": {formatCoordinate(req.Longitude)},
		"t":         {strconv.FormatInt(now.UnixMilli(), 10)},
	}
	if param != "" {
		query.Set("captchaVerifyParam", param)
	}
	return query
}

// newOutcome 组装 Outcome 的公共部分。
func newOutcome(resp *skl.Response) *Outcome {
	out := &Outcome{Response: resp}
	if resp != nil {
		out.StatusCode = resp.StatusCode
	}
	return out
}

// formatCoordinate 把经纬度序列化成服务端可解析的十进制字符串。
//
// 用最短往返表示（-1 位）：前端是把 JS Number 直接序列化过去的，没有做任何
// 补零或截断；固定小数位会引入前端并不存在的舍入。
func formatCoordinate(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// newJSONPCallback 生成 JSONP 回调名。
//
// 用 crypto/rand 而非时间戳：回调名会回显进响应体，可预测的名字没有必要，
// 而且会被静态检查判为不安全随机源。
func newJSONPCallback() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "jsonp_fallback"
	}
	return "jsonp_" + hex.EncodeToString(b[:])
}

// unwrapJSONP 去掉 JSONP 外壳，返回纯 JSON。
//
// 服务端也可能直接返回 JSON（当请求被拒时），两种都能处理。
func unwrapJSONP(body []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, errors.New("响应体为空")
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return []byte(trimmed), nil
	}
	if _, after, ok := strings.Cut(trimmed, "("); ok {
		if end := strings.LastIndexByte(after, ')'); end >= 0 {
			return []byte(strings.TrimSpace(after[:end])), nil
		}
	}
	return nil, fmt.Errorf("无法识别的 JSONP 响应: %s", truncate([]byte(trimmed), 128))
}

// truncate 截断过长的 body 用于错误信息。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
