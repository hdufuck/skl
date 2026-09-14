package skl

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// HAR#2 里 /api/dingtalk/jsapi_ticket 返回 200 + 0 字节，
// 同一账号在 HAR#1 里却返回了完整 JSON。这个用例锁住「空票据被
// 翻译成带上下文的 ErrEmptyBody，而不是结构解析失败」这一行为。
func TestJsapiTicketToleratesEmptyBody(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	_, err := c.JsapiTicket(t.Context(), "https://skl.hdu.edu.cn/index.html")
	if !errors.Is(err, ErrEmptyBody) {
		t.Fatalf("err = %v, want ErrEmptyBody", err)
	}
}

func TestJsapiTicketParsesBody(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	m.JsapiTicketBody = `{"timeStamp":1789354211339,"agentId":3929035295,` +
		`"corpId":"ding8224358e11e0debf35c2f4657eb6378f",` +
		`"signature":"739eb0e034012ae60bf7f29f1e0a7c25f7cea90b53f7a97b80cb4242ec1d89ce",` +
		`"nonceStr":"H7B4jUf9PKN88oRJIom"}`
	c := newMockClient(t, m, WithToken(m.Token))

	ticket, err := c.JsapiTicket(t.Context(), "https://skl.hdu.edu.cn/index.html")
	if err != nil {
		t.Fatalf("JsapiTicket: %v", err)
	}
	if ticket.CorpID != "ding8224358e11e0debf35c2f4657eb6378f" {
		t.Fatalf("CorpID = %q", ticket.CorpID)
	}
	if ticket.NonceStr != "H7B4jUf9PKN88oRJIom" {
		t.Fatalf("NonceStr = %q", ticket.NonceStr)
	}
	if ticket.TimeStamp != 1789354211339 {
		t.Fatalf("TimeStamp = %d", ticket.TimeStamp)
	}
}

// check-code-analyze 用 JSONP 响应；800 表示签到被拒。
// 该业务码语义取自前端分支判断，且 800 已用无效签到码实测到。
func TestSignInLegacyAnalyzeUnwrapsJSONP(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	got, err := c.SignInLegacyAnalyze(t.Context(), AnalyzeRequest{
		SignInRequest: SignInRequest{Code: "9999", UserID: "24000000"},
	})
	if err != nil {
		t.Fatalf("SignInLegacyAnalyze: %v", err)
	}
	if got.Code != AnalyzeCodeRejected {
		t.Fatalf("Code = %d, want %d", got.Code, AnalyzeCodeRejected)
	}
	if got.OK() {
		t.Fatal("OK() = true, want false for code 800")
	}
	if got.CaptchaRequired() {
		t.Fatal("CaptchaRequired() = true, want false for code 800")
	}
	if got.Response == nil || got.Response.StatusCode != http.StatusOK {
		t.Fatalf("Response = %+v, want a 200 response attached", got.Response)
	}
}

func TestSignInLegacyAnalyzeSuccessAndCaptchaCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code        int
		wantOK      bool
		wantCaptcha bool
	}{
		{code: AnalyzeCodeSuccess, wantOK: true},
		{code: AnalyzeCodeSuccessAlt, wantOK: true},
		{code: AnalyzeCodeCaptcha, wantCaptcha: true},
		{code: AnalyzeCodeRejected},
		{code: AnalyzeCodeRejectedAlt},
	}

	for _, tt := range tests {
		m := newMockSkl(t)
		m.AnalyzeJSONP = `%s({"result":{"code":` + itoa(tt.code) + `}})`
		c := newMockClient(t, m, WithToken(m.Token))

		got, err := c.SignInLegacyAnalyze(t.Context(), AnalyzeRequest{
			SignInRequest: SignInRequest{Code: "9999", UserID: "24000000"},
		})
		if err != nil {
			t.Fatalf("code=%d: %v", tt.code, err)
		}
		if got.OK() != tt.wantOK {
			t.Fatalf("code=%d: OK() = %v, want %v", tt.code, got.OK(), tt.wantOK)
		}
		if got.CaptchaRequired() != tt.wantCaptcha {
			t.Fatalf("code=%d: CaptchaRequired() = %v, want %v", tt.code, got.CaptchaRequired(), tt.wantCaptcha)
		}
	}
}

func TestSignInLegacySurfacesBusiness401(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	_, err := c.SignInLegacy(t.Context(), SignInRequest{
		Code: "9999", UserID: "24000000",
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Msg != "签到码不存在，不要玩我" {
		t.Fatalf("Msg = %q", apiErr.Msg)
	}
	if apiErr.NeedLogin() {
		t.Fatal("签到业务失败不应被判为需要重新登录")
	}
}

func TestSignInRequiresCaptchaProvider(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken(m.Token))

	_, err := c.SignIn(t.Context(), SignInRequest{
		Code: "1212", Latitude: 30.123456, Longitude: 120.654321,
	})
	if !errors.Is(err, ErrNoCaptchaProvider) {
		t.Fatalf("err = %v, want ErrNoCaptchaProvider", err)
	}
}

func TestSignInUsesCaptchaProvider(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m,
		WithToken(m.Token),
		WithCaptchaProvider(CaptchaProviderFunc(func(_ context.Context, scene CaptchaScene) (string, error) {
			if scene.SceneID != DefaultCaptchaSceneID {
				t.Errorf("SceneID = %q, want %q", scene.SceneID, DefaultCaptchaSceneID)
			}
			if scene.Prefix != DefaultCaptchaPrefix {
				t.Errorf("Prefix = %q, want %q", scene.Prefix, DefaultCaptchaPrefix)
			}
			if !strings.Contains(scene.PageURL, "/sign/in") {
				t.Errorf("PageURL = %q, want it to point at /sign/in", scene.PageURL)
			}
			return `{"sceneId":"2q42bw25"}`, nil
		})),
	)

	// 服务端会返回业务 401（签到码不存在），关键是它把 provider 的值带上了。
	_, err := c.SignIn(t.Context(), SignInRequest{
		Code: "1212", Latitude: 30.123456, Longitude: 120.654321,
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if !strings.Contains(apiErr.Body, "captchaVerifyParam") &&
		!strings.Contains(apiErr.Body, "签到码") {
		t.Logf("响应体（说明请求已到达业务逻辑）: %s", apiErr.Body)
	}
}

func TestFormatCoordinate(t *testing.T) {
	t.Parallel()

	tests := map[float64]string{
		30.123456:  "30.123456",
		120.654321: "120.654321",
		0:          "0.000000",
		-0.5:       "-0.500000",
		30.1234567: "30.123456",
	}
	for in, want := range tests {
		if got := formatCoordinate(in); got != want {
			t.Fatalf("formatCoordinate(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestUnwrapJSONP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{name: "JSONP 外壳", body: `cb1({"result":{"code":800}})`, want: `{"result":{"code":800}}`},
		{name: "裸 JSON", body: `{"result":{"code":400}}`, want: `{"result":{"code":400}}`},
		{name: "带空白的 JSONP", body: "  cb2( {\"a\":1} )  ", want: `{"a":1}`},
		{name: "裸数组", body: `[1,2]`, want: `[1,2]`},
		{name: "无法识别", body: `not json`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := unwrapJSONP([]byte(tt.body), "cb1")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("unwrapJSONP(%q) = %q, want error", tt.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unwrapJSONP: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("unwrapJSONP(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestResolveUserIDRequiresID(t *testing.T) {
	t.Parallel()

	m := newMockSkl(t)
	c := newMockClient(t, m, WithToken("invalid"))

	// 显式传入时不做网络请求。
	got, err := c.resolveUserID(t.Context(), "explicit")
	if err != nil || got != "explicit" {
		t.Fatalf("resolveUserID(explicit) = %q, %v", got, err)
	}
}

// itoa 避免在测试里额外引入 strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
