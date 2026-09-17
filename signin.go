package skl

import (
	"bytes"
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
)

// SignInRequest 描述一次签到。
type SignInRequest struct {
	// Code 是任课老师公布的 4 位签到码。
	Code string
	// Latitude / Longitude 是当前定位。服务端会校验，缺失时签到失败。
	Latitude  float64
	Longitude float64

	// UserID 默认为当前登录用户的 id。
	UserID string

	// CaptchaVerifyParam 是阿里云验证码 SDK 产出的风控参数。
	//
	// 留空时会通过 Client 的 CaptchaProvider 获取；两者都没有则返回
	// ErrNoCaptchaProvider。该参数是一次性的。
	CaptchaVerifyParam string
}

// SignInResult 是 `POST /api/ali-nvc/captcha-verify` 的响应。
//
// 字段名与形态取自 `har#3` 的浏览器抓包（一份**成功**样本，`200`）：
//
//	{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{…17 个字段…}}
//
// 同一个接口还有另外两种结局，都不是 `401`：
//
//	200 {"captchaVerifyResult":false,"captchaVerifyCode":"F001"}  阿里云风控不通过
//	414 text/plain "URI too long"                                   网关拒了超长请求行
//
// `F001` 是阿里云验证码的码，官方定义是「疑似攻击请求，风险策略不通过」——
// 它指向**风控评分**，不是「人机验证层单独拒签」；换一份新 `captchaVerifyParam`
// 就可能变成 `T001`（错误码表见 docs/signin-probe.md §0.1）。
// 因此**不能用状态码判断成败**，用 [SignInResult.OK]。字段值保持 RawMessage /
// 原生类型透出，不做结构性重命名，以保留服务端原始形状。
//
// 前端拿到 `checkCodeDto` 后存进 store 并跳转 `/sign/in/detail`。
type SignInResult struct {
	// CaptchaVerifyResult 是服务端对本次人机凭证的判定，**严格 `true`** 才算过。
	CaptchaVerifyResult json.RawMessage `json:"captchaVerifyResult"`
	// CaptchaVerifyCode 是它的文字版：成功 `T001`，风控不通过 `F001`。
	// 该字段在前端产物里不存在（服务端专有），`har#3` 首次观察到。
	CaptchaVerifyCode string `json:"captchaVerifyCode"`
	// CheckCodeDto 是成功时的考勤记录详情；失败时整个键不存在（nil）。
	CheckCodeDto json.RawMessage `json:"checkCodeDto"`
	Response     *Response       `json:"-"`
}

// OK 报告这次签到是否成功。
//
// 判据是 `har#3` 抓包实测的两条**同时**成立：
//   - `captchaVerifyResult` 严格为 `true`；
//   - `checkCodeDto` 非空（成功才带这个键，人机失败时整个键不存在）。
//
// [SignIn] **不会**把「`200` + `captchaVerifyResult:false`」当错误返回，
// 所以调用方必须靠它（或自己看字段）区分「签到成功」与「人机被拒」。
func (r *SignInResult) OK() bool {
	if r == nil || len(r.CaptchaVerifyResult) == 0 {
		return false
	}
	var passed bool
	if err := json.Unmarshal(r.CaptchaVerifyResult, &passed); err != nil || !passed {
		return false
	}
	dto := bytes.TrimSpace(r.CheckCodeDto)
	return len(dto) > 0 && !bytes.Equal(dto, []byte("null"))
}

// SignIn 通过 `POST /api/ali-nvc/captcha-verify` 完成签到。
//
// 这是当前前端（`/sign/in` 页面）使用的唯一签到路径，**必须**携带
// `captchaVerifyParam`。参数缺失时服务端会先校验签到码，因此
// 「签到码不存在」这类错误并不能说明人机验证是否通过。
//
// 注意：签到失败返回 401，但这是业务错误而非会话失效，
// 不会触发自动重登（Do 只在响应携带 `url` 字段时才重登）。
func (c *Client) SignIn(ctx context.Context, req SignInRequest) (*SignInResult, error) {
	param := req.CaptchaVerifyParam
	if param == "" {
		if c.captcha == nil {
			return nil, ErrNoCaptchaProvider
		}
		var err error
		param, err = c.captcha.CaptchaVerifyParam(ctx, c.CaptchaScene())
		if err != nil {
			return nil, fmt.Errorf("skl: 获取 captchaVerifyParam: %w", err)
		}
	}
	if param == "" {
		return nil, ErrNoCaptchaProvider
	}

	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"captchaVerifyParam": {param},
		"userid":             {userID},
		"code":               {req.Code},
		"latitude":           {formatCoordinate(req.Latitude)},
		"longitude":          {formatCoordinate(req.Longitude)},
		"t":                  {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}

	resp, err := c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   PathSignInCaptchaVerify,
		Query:  query,
		// 参数全在 query 里、body 为空，但官方请求仍带 form 头
		// （`har#3` 抓包第 101 条）——必须与之逐字节一致。
		ContentType: ContentTypeFormURLEncoded,
	})
	if err != nil {
		return nil, err
	}

	result, err := decodeJSON[SignInResult](resp)
	if err != nil {
		return nil, err
	}
	result.Response = resp
	return &result, nil
}

// SignInLegacy 通过遗留接口 `GET /api/checkIn/code-check-in` 签到。
//
// 该接口在抓到的前端构建里已经没有调用方（`index-BjaCUYRh.js` 仍把它注册为
// `signIn()`，但已无页面调用），属于历史遗留。两份 HAR 中也**没有**出现
// 该请求。我们用一个无效签到码实测过它：返回 401「签到码不存在，不要玩我」，
// 说明服务端仍然在路由该接口，且它不需要 captchaVerifyParam。
//
// ⚠️ 风险（必读）：无法在没有人机验证的情况下验证「有效签到码」的语义。
// 用无效签到码探测时它返回与 captcha-verify 完全相同的
// `401 {"code":0,"msg":"签到码不存在，不要玩我"}`，说明签到码校验发生在
// 人机验证之前，因此无法判断它对有效签到码是否也要求人机验证。
// 换句话说：**调用它并传入一个有效签到码，有可能直接签到成功。**
// 只应在确实想签到时调用，不要拿它当「只校验签到码」的探针。
func (c *Client) SignInLegacy(ctx context.Context, req SignInRequest) (*SignInResult, error) {
	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"code": {req.Code},
		"id":   {userID},
	}
	// 定位只在调用方确实提供时上报。
	//
	// 这里的参数集是**推断**的：前端只把该方法注册为
	// `signIn(n){return o.get("/checkIn/code-check-in",{params:n})}`，
	// 没有任何页面调用它，抓包里也没有这个请求，所以无法像 captcha-verify
	// 那样逐字节对齐。已知 code 与 id 能让服务端走到业务校验（实测）。
	if req.Latitude != 0 || req.Longitude != 0 {
		query.Set("latitude", formatCoordinate(req.Latitude))
		query.Set("longitude", formatCoordinate(req.Longitude))
	}

	resp, err := c.Get(ctx, PathSignInLegacy, query)
	if err != nil {
		return nil, err
	}

	result, err := decodeJSON[SignInResult](resp)
	if err != nil {
		return nil, err
	}
	result.Response = resp
	return &result, nil
}

// 遗留 JSONP 接口 `check-code-analyze` 的业务码，取自前端分支判断。
const (
	// AnalyzeCodeSuccess / AnalyzeCodeSuccessAlt 表示签到成功。
	AnalyzeCodeSuccess    = 100
	AnalyzeCodeSuccessAlt = 200
	// AnalyzeCodeCaptcha 表示服务端要求完成滑块人机验证。
	AnalyzeCodeCaptcha = 400
	// AnalyzeCodeRejected / AnalyzeCodeRejectedAlt 表示签到被拒（例如签到码无效）。
	AnalyzeCodeRejected    = 800
	AnalyzeCodeRejectedAlt = 900

	// AnalyzeNVCValueNone 表示「无需人机验证」时前端上报的 a 参数取值。
	AnalyzeNVCValueNone = "0"
)

// AnalyzeRequest 描述一次遗留 JSONP 签到请求。
//
// 注意这里**没有**经纬度：前端 /sign/ali 页在调 check-code-analyze 时
// 只上报 `userid`、`code`、`t`、`token`、`a` 五个参数，完全不传定位。
// 这是该路径与 captcha-verify 的一个实质差别，因此不提供位置字段，
// 以免调用方以为传了会有用。
type AnalyzeRequest struct {
	// Code 是 4 位签到码。
	Code string
	// UserID 默认为当前登录用户的 id。
	UserID string
	// NVCValue 是阿里云 AWSC nvc 的 `getNVCValAsync` 结果。
	// 服务端判定无需二次验证时前端会直接上报 "0"（AnalyzeNVCValueNone）。
	NVCValue string
	// Timestamp 对应前端的 `t` 参数；为 0 时不发送。
	Timestamp int64
}

// AnalyzeResult 是 `GET /api/ali-nvc/check-code-analyze` 的结果。
type AnalyzeResult struct {
	// Code 是业务码，取值见 AnalyzeCode* 常量。
	Code int `json:"code"`
	// Raw 是 `result` 对象的原始 JSON。
	Raw json.RawMessage `json:"-"`
	// Response 是原始 HTTP 响应。
	Response *Response `json:"-"`
}

// OK 报告签到是否成功。
func (r *AnalyzeResult) OK() bool {
	return r != nil && (r.Code == AnalyzeCodeSuccess || r.Code == AnalyzeCodeSuccessAlt)
}

// CaptchaRequired 报告服务端是否要求完成滑块验证。
//
// 判据是 `result.code == 400`。该语义取自前端分支（签到页的 onValid：
// code 为 400 时调 `window.nvc.getNC()` 弹滑块）。
// 注意实测只用无效签到码探测过该接口，得到的是 800，因此 400 分支
// 本身**未经实测**。
func (r *AnalyzeResult) CaptchaRequired() bool { return r != nil && r.Code == AnalyzeCodeCaptcha }

// SignInLegacyAnalyze 通过遗留 JSONP 接口 `/api/ali-nvc/check-code-analyze` 签到。
//
// 与 SignInLegacy 不同，这个接口是阿里云 NVC 的「风险自适应」形态：
// 前端平时直接上报 `a=0`（表示未做人机验证），只有当服务端返回
// AnalyzeCodeCaptcha 时才弹出滑块。这使它成为**最可能绕过人机验证**的路径，
// 但同样无法在拿到有效签到码之前证伪（签到码校验先于风控判定）。
//
// 同 SignInLegacy：该接口在前端构建里已无调用方，两份 HAR 中也没有出现；
// 我们用无效签到码实测过，返回 `{"result":{"code":800}}`。
//
// ⚠️ 同 SignInLegacy：传入有效签到码可能会直接签到成功。
//
// 该接口以 JSONP 形式响应（`callback({...})`），因此本方法会自动解包。
func (c *Client) SignInLegacyAnalyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error) {
	userID, err := c.resolveUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	nvc := req.NVCValue
	if nvc == "" {
		nvc = AnalyzeNVCValueNone
	}

	callback := newJSONPCallback()

	query := url.Values{
		"userid":   {userID},
		"code":     {req.Code},
		"token":    {c.Token()},
		"a":        {nvc},
		"callback": {callback},
	}
	if req.Timestamp != 0 {
		query.Set("t", strconv.FormatInt(req.Timestamp, 10))
	}

	resp, err := c.Get(ctx, PathSignInAnalyze, query)
	if err != nil {
		return nil, err
	}

	payload, err := unwrapJSONP(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("skl: 解析 %s 的 JSONP 响应失败: %w", PathSignInAnalyze, err)
	}

	var envelope struct {
		Result struct {
			Code int `json:"code"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("skl: 解析 %s 业务结果失败: %w (body=%s)", PathSignInAnalyze, err, truncate(payload, 256))
	}

	// 提取 result 原始 JSON（envelope 只解析了 code）。
	var raw struct {
		Result json.RawMessage `json:"result"`
	}
	_ = json.Unmarshal(payload, &raw)

	return &AnalyzeResult{
		Code:     envelope.Result.Code,
		Raw:      raw.Result,
		Response: resp,
	}, nil
}

// CaptchaImage 获取图形验证码图片（遗留 `valid-code` 流程使用）。
//
// 该流程只在服务端已经把 validImgUrl 放进会话时才有意义：
// 对应 `GET /api/checkIn/valid-code?code=&id=`，其中 code 是图中 4 位数字。
func (c *Client) CaptchaImage(ctx context.Context) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:         http.MethodGet,
		Path:           PathCaptchaImage,
		AllowEmptyBody: true,
	})
}

// ValidCode 提交图形验证码（遗留流程）。
//
// 实测在没有先获取图片验证码的会话上直接调用会返回 `400 + 空 body`，
// 因此调用前应先通过 CaptchaImage 建立图片验证码会话。
func (c *Client) ValidCode(ctx context.Context, code, userID string) (*Response, error) {
	id, err := c.resolveUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, &Request{
		Method:         http.MethodGet,
		Path:           PathLegacyValidCode,
		Query:          url.Values{"code": {code}, "id": {id}},
		AllowEmptyBody: true,
		NoRelogin:      true,
	})
}

// resolveUserID 返回显式传入的 userID，缺省时取当前登录用户 id。
func (c *Client) resolveUserID(ctx context.Context, userID string) (string, error) {
	if userID != "" {
		return userID, nil
	}
	user, err := c.User(ctx)
	if err != nil {
		return "", fmt.Errorf("skl: 无法确定 userid: %w", err)
	}
	if user.ID == "" {
		return "", errors.New("skl: /api/userinfo 未返回用户 id")
	}
	return user.ID, nil
}

// formatCoordinate 把经纬度序列化成服务端可解析的十进制字符串。
//
// 用最短往返表示（-1 位）而不是固定小数位：前端是把 axios 的 JS Number
// 直接序列化过去的，没有做任何补零或截断，抓包里的 6 位小数只是那个值
// 本来如此。固定 6 位会引入前端并不存在的舍入。
//
// 坐标系：见 doc.go「定位信息」——前端用的是钉钉 `coordinate: 0`，
// 即**标准坐标（WGS-84）**，因此调用方给的值必须是同一坐标系。
func formatCoordinate(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// newJSONPCallback 生成 JSONP 回调名。
//
// 用 crypto/rand 而非 math/rand：回调名会回显进响应体，
// 可预测的回调名没有必要，而且会被静态检查判为不安全随机源。
func newJSONPCallback() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "jsonp_fallback"
	}
	return "jsonp_" + hex.EncodeToString(b[:])
}

// unwrapJSONP 去掉 JSONP 外壳，返回纯 JSON。
//
// 服务端也可能直接返回 JSON（当请求被拒时），两种都能处理；外壳里的回调名
// 不做校验（服务端可能回一个与请求不同的名字），所以这里不需要它。
func unwrapJSONP(body []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(body))

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
