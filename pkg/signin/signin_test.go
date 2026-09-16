package signin

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/hdufuck/skl"
)

// WithoutParam 是根包拿不到的那一档：官方 captcha-verify 的 query 里
// **没有** captchaVerifyParam 键，其余 5 个键齐全，body 为空但仍带 form 头。
func TestWithoutParamSendsExactQuerySet(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	out, err := c.WithoutParam(t.Context(), Request{
		Code: "1212", Latitude: 30.123456, Longitude: 120.654321,
	})
	var apiErr *skl.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *skl.APIError（假服务器返回业务 401）", err)
	}
	if out == nil || out.StatusCode != http.StatusUnauthorized || out.Response == nil {
		t.Fatalf("Outcome = %+v, want 401 + 原始响应", out)
	}

	got := f.lastRequest(t)
	if got.method != http.MethodPost || got.path != skl.PathSignInCaptchaVerify {
		t.Fatalf("请求 = %s %s, want POST %s", got.method, got.path, skl.PathSignInCaptchaVerify)
	}
	keys := slices.Sorted(maps.Keys(got.query))
	want := []string{"code", "latitude", "longitude", "t", "userid"}
	if !slices.Equal(keys, want) {
		t.Fatalf("query 键集 = %v, want %v", keys, want)
	}
	if got.query.Has("captchaVerifyParam") {
		t.Fatalf("WithoutParam 不应带 captchaVerifyParam，实际 query=%v", got.query)
	}
	if got.query.Get("userid") != "24000000" {
		t.Fatalf("userid = %q, want 24000000（未显式给出时应自动解析）", got.query.Get("userid"))
	}
	if got.query.Get("code") != "1212" {
		t.Fatalf("code = %q", got.query.Get("code"))
	}
	if got.query.Get("latitude") != "30.123456" || got.query.Get("longitude") != "120.654321" {
		t.Fatalf("定位 = %q,%q", got.query.Get("latitude"), got.query.Get("longitude"))
	}
	if got.query.Get("t") == "" {
		t.Fatal("t 未发送")
	}
	if got.contentType != skl.ContentTypeFormURLEncoded {
		t.Fatalf("Content-Type = %q, want %q", got.contentType, skl.ContentTypeFormURLEncoded)
	}
	if got.bodyLen != 0 {
		t.Fatalf("body 长度 = %d, want 0（参数全在 query 里）", got.bodyLen)
	}
}

func TestWithParamSendsGivenParam(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	param := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt"}`
	out, err := c.WithParam(t.Context(), Request{
		Code: "1212", UserID: "24000000", Latitude: 1, Longitude: 2,
		CaptchaVerifyParam: param,
	})
	var apiErr *skl.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *skl.APIError", err)
	}

	got := f.lastRequest(t)
	if sent := got.query.Get("captchaVerifyParam"); sent != param {
		t.Fatalf("captchaVerifyParam = %q, want %q", sent, param)
	}
	if got.path != skl.PathSignInCaptchaVerify {
		t.Fatalf("path = %q", got.path)
	}
	if out.StatusCode != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d", out.StatusCode)
	}
}

// WithParam 是「强制提交我给定的值」，参数为空时必须报错且不发请求 ——
// 绝不能静默落到 CaptchaProvider 上。
func TestWithParamEmptyParamErrorsWithoutRequest(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	providerCalled := false
	c := newTestSignin(t, f, skl.WithCaptchaProvider(skl.CaptchaProviderFunc(
		func(context.Context, skl.CaptchaScene) (string, error) {
			providerCalled = true
			return `{"sceneId":"x"}`, nil
		})))

	out, err := c.WithParam(t.Context(), Request{Code: "1212", Latitude: 1, Longitude: 2})
	if err == nil {
		t.Fatal("WithParam（空参数）= nil error, want error")
	}
	if out != nil {
		t.Fatalf("Outcome = %+v, want nil", out)
	}
	if providerCalled {
		t.Fatal("WithParam 不应落到 CaptchaProvider 上")
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("发起了 %d 个请求, want 0", n)
	}
}

func TestForgedSendsForgedParamAndKeepsSampleLength(t *testing.T) {
	t.Parallel()

	sample := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2FiMDM0","data":"JRMlgg1EZm9v"}`

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	_, err := c.Forged(t.Context(), Request{
		Code: "1212", UserID: "24000000", Latitude: 1, Longitude: 2,
		ForgeSample: sample,
	})
	var apiErr *skl.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *skl.APIError", err)
	}

	sent := f.lastRequest(t).query.Get("captchaVerifyParam")
	if sent != ForgeCaptchaParam(sample) {
		t.Fatalf("captchaVerifyParam 不是 ForgeCaptchaParam(sample) 的产物:\n got %q\nwant %q", sent, ForgeCaptchaParam(sample))
	}
	if len(sent) != len(sample) {
		t.Fatalf("伪造值与样本不等长：%d vs %d", len(sent), len(sample))
	}
}

// Analyze 走遗留 JSONP：只上报 a=0，完全不传定位，并自动解包 JSONP。
func TestAnalyzeSendsA0WithoutLocationAndUnwrapsJSONP(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	f.analyzeJSONP = `%s({"result":{"code":100}})`
	c := newTestSignin(t, f)

	out, err := c.Analyze(t.Context(), Request{Code: "9999"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if out.Analyze == nil {
		t.Fatal("Outcome.Analyze = nil")
	}
	if out.Analyze.Code != skl.AnalyzeCodeSuccess {
		t.Fatalf("Analyze.Code = %d, want %d", out.Analyze.Code, skl.AnalyzeCodeSuccess)
	}
	if !out.Analyze.OK() {
		t.Fatal("Analyze.OK() = false, want true（code=100）")
	}
	if out.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d", out.StatusCode)
	}

	got := f.lastRequest(t)
	if got.method != http.MethodGet || got.path != skl.PathSignInAnalyze {
		t.Fatalf("请求 = %s %s, want GET %s", got.method, got.path, skl.PathSignInAnalyze)
	}
	if got.query.Get("a") != skl.AnalyzeNVCValueNone {
		t.Fatalf("a = %q, want %q", got.query.Get("a"), skl.AnalyzeNVCValueNone)
	}
	if got.query.Get("token") != "test-token" {
		t.Fatalf("token = %q", got.query.Get("token"))
	}
	if got.query.Get("userid") != "24000000" {
		t.Fatalf("userid = %q", got.query.Get("userid"))
	}
	if got.query.Get("callback") == "" {
		t.Fatal("callback 未发送")
	}
	if got.query.Has("latitude") || got.query.Has("longitude") {
		t.Fatalf("Analyze 不应上报定位，实际 query=%v", got.query)
	}
}

func TestAnalyzeSurfacesAnalyzeResultOnJSONPError(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	f.analyzeJSONP = `%s({"result":{"code":400}})`
	c := newTestSignin(t, f)

	out, err := c.Analyze(t.Context(), Request{Code: "9999"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if out.Analyze == nil || !out.Analyze.CaptchaRequired() {
		t.Fatalf("AnalyzeResult = %+v, want code 400 CaptchaRequired", out.Analyze)
	}
}

// Legacy 的定位是可选上报：不传时不应凭空补 0。
func TestLegacyOmitsLocationWhenUnset(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	if _, err := c.Legacy(t.Context(), Request{Code: "9999", UserID: "24000000"}); err == nil {
		t.Fatal("期望假服务器返回业务错误")
	}

	got := f.lastRequest(t)
	if got.method != http.MethodGet || got.path != skl.PathSignInLegacy {
		t.Fatalf("请求 = %s %s, want GET %s", got.method, got.path, skl.PathSignInLegacy)
	}
	if got.query.Has("latitude") || got.query.Has("longitude") {
		t.Fatalf("未提供定位时不应上报 latitude/longitude，实际 query=%v", got.query)
	}
	if got.query.Get("code") != "9999" || got.query.Get("id") != "24000000" {
		t.Fatalf("code/id 不正确: %v", got.query)
	}
}

func TestLegacySendsLocationWhenSet(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	f.legacyStatus = http.StatusOK
	f.legacyBody = `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{"id":"x"}}`
	c := newTestSignin(t, f)

	out, err := c.Legacy(t.Context(), Request{
		Code: "9999", UserID: "24000000", Latitude: 30.5, Longitude: 120.25,
	})
	if err != nil {
		t.Fatalf("Legacy: %v", err)
	}
	if out.SignIn == nil || !out.SignIn.OK() {
		t.Fatalf("Outcome.SignIn = %+v, want OK", out.SignIn)
	}
	if out.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d", out.StatusCode)
	}

	got := f.lastRequest(t).query
	if got.Get("latitude") != "30.5" || got.Get("longitude") != "120.25" {
		t.Fatalf("定位 = %q,%q", got.Get("latitude"), got.Get("longitude"))
	}
}

func TestGenuineUsesGivenParamWithoutAskingProvider(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	providerCalled := false
	c := newTestSignin(t, f, skl.WithCaptchaProvider(skl.CaptchaProviderFunc(
		func(context.Context, skl.CaptchaScene) (string, error) {
			providerCalled = true
			return `{"sceneId":"from-provider"}`, nil
		})))

	param := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt"}`
	_, err := c.Genuine(t.Context(), Request{
		Code: "1212", UserID: "24000000", Latitude: 1, Longitude: 2,
		CaptchaVerifyParam: param,
	})
	var apiErr *skl.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *skl.APIError", err)
	}
	if providerCalled {
		t.Fatal("Genuine 在 CaptchaVerifyParam 非空时不应询问 provider")
	}
	if sent := f.lastRequest(t).query.Get("captchaVerifyParam"); sent != param {
		t.Fatalf("captchaVerifyParam = %q, want %q", sent, param)
	}
}

func TestGenuineFallsBackToProvider(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	param := `{"sceneId":"from-provider"}`
	c := newTestSignin(t, f, skl.WithCaptchaProvider(skl.StaticCaptchaProvider{Value: param}))

	_, err := c.Genuine(t.Context(), Request{
		Code: "1212", UserID: "24000000", Latitude: 1, Longitude: 2,
	})
	var apiErr *skl.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *skl.APIError", err)
	}
	if sent := f.lastRequest(t).query.Get("captchaVerifyParam"); sent != param {
		t.Fatalf("captchaVerifyParam = %q, want %q", sent, param)
	}
}

func TestGenuineWithoutProviderOrParamErrorsWithoutRequest(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	_, err := c.Genuine(t.Context(), Request{Code: "1212", Latitude: 1, Longitude: 2})
	if !errors.Is(err, skl.ErrNoCaptchaProvider) {
		t.Fatalf("err = %v, want skl.ErrNoCaptchaProvider", err)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("发起了 %d 个请求, want 0", n)
	}
}

// 一只没接 skl.Client 的门面不应 panic，而是返回错误。
func TestNilClientReturnsError(t *testing.T) {
	t.Parallel()

	c := New(nil)

	if _, err := c.WithoutParam(t.Context(), Request{Code: "1212", UserID: "24000000"}); err == nil {
		t.Fatal("WithoutParam（nil client）= nil error, want error")
	}
	if _, err := c.Genuine(t.Context(), Request{Code: "1212", UserID: "24000000"}); err == nil {
		t.Fatal("Genuine（nil client）= nil error, want error")
	}
}
