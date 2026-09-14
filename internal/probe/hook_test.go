package probe

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func harBody(entries string) []byte {
	return []byte(`{"log":{"version":"1.2","entries":[` + entries + `]}}`)
}

func harEntryJSON(method, url string, status int, contentType, respText string) string {
	doc := map[string]any{
		"startedDateTime": "2026-09-15T10:00:00+08:00",
		"request": map[string]any{
			"method": method,
			"url":    url,
		},
		"response": map[string]any{
			"status": status,
			"headers": []map[string]string{
				{"name": "Content-Type", "value": contentType},
				{"name": "X-Auth-Token", "value": "secret"},
			},
			"content": map[string]any{"text": respText},
		},
	}
	buf, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(buf)
}

func TestParseHARExchangePicksSuccessful(t *testing.T) {
	param := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"` + strings.Repeat("D", 30) + `","data":"x"}`
	okURL := "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?captchaVerifyParam=" + param + "&code=1234"
	failURL := "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?captchaVerifyParam=bad&code=1234"

	body := harBody(
		harEntryJSON("POST", failURL, 401, "application/json", `{"code":0}`) + "," +
			harEntryJSON("POST", okURL, 200, "application/json;charset=UTF-8", `{"captchaVerifyResult":true,"checkCodeDto":{"id":"c1"}}`) + "," +
			harEntryJSON("GET", "https://skl.hdu.edu.cn/api/userinfo", 200, "application/json", `{}`),
	)

	entry, err := ParseHARExchange(body)
	if err != nil {
		t.Fatalf("ParseHARExchange: %v", err)
	}
	if entry.Status != 200 {
		t.Fatalf("应优先挑 200 的那条，实际 %d", entry.Status)
	}
	if entry.Verdict != VerdictSuccess {
		t.Fatalf("判读 = %s, want success", entry.Verdict)
	}
	if entry.RespHeaders["Content-Type"] == "" {
		t.Fatalf("响应头未提取: %v", entry.RespHeaders)
	}
	if _, ok := entry.RespHeaders["X-Auth-Token"]; ok {
		t.Fatal("会话凭据不应出现在报告里")
	}
	if strings.Contains(entry.URL, strings.Repeat("D", 21)) {
		t.Fatalf("URL 未脱敏: %s", entry.URL)
	}
	if !entry.FromPhone {
		t.Fatal("应标记来自手机")
	}
}

func TestParseHARExchangeFallsBackToLast(t *testing.T) {
	body := harBody(
		harEntryJSON("POST", "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?code=1", 401, "application/json", `{"code":0,"msg":"签到码不存在"}`) + "," +
			harEntryJSON("POST", "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?code=2", 500, "application/json", `{"boom":1}`),
	)

	entry, err := ParseHARExchange(body)
	if err != nil {
		t.Fatalf("ParseHARExchange: %v", err)
	}
	if entry.Status != 500 {
		t.Fatalf("无 200 时应取最后一条，实际 %d", entry.Status)
	}
}

func TestParseHARExchangeNoMatch(t *testing.T) {
	body := harBody(harEntryJSON("GET", "https://skl.hdu.edu.cn/api/userinfo", 200, "application/json", `{}`))
	if _, err := ParseHARExchange(body); err == nil {
		t.Fatal("没有 captcha-verify 时应报错")
	}
}

func TestParseHARExchangeBase64Body(t *testing.T) {
	// {"captchaVerifyResult":true,"checkCodeDto":{}}
	encoded := "eyJjYXB0Y2hhVmVyaWZ5UmVzdWx0Ijp0cnVlLCJjaGVja0NvZGVEdG8iOnt9fQ=="
	entryJSON := `{"startedDateTime":"2026-09-15T10:00:00+08:00",
		"request":{"method":"POST","url":"https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?code=1"},
		"response":{"status":200,"headers":[],"content":{"text":"` + encoded + `","encoding":"base64"}}}`

	entry, err := ParseHARExchange(harBody(entryJSON))
	if err != nil {
		t.Fatalf("ParseHARExchange: %v", err)
	}
	if !strings.Contains(entry.Body, `"captchaVerifyResult":true`) {
		t.Fatalf("base64 body 未解码: %s", entry.Body)
	}
}

func TestHookHandlerPushesEntryAndIgnoresNoise(t *testing.T) {
	ch := make(chan Entry, 2)
	handler := NewHookHandler(ch, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 无关请求：应被忽略，且不报错。
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"log":{"entries":[]}}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("无关上报应返回 200，实际 %d", resp.StatusCode)
	}

	// 命中请求：应推入通道。
	body := harBody(harEntryJSON("POST", "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?code=1", 200, "application/json", `{}`))
	resp, err = http.Post(srv.URL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case e := <-ch:
		if e.Status != 200 {
			t.Fatalf("推入的条目状态 = %d", e.Status)
		}
	default:
		t.Fatal("命中请求应推入通道")
	}
}

func TestHookHandlerRejectsNonPost(t *testing.T) {
	srv := httptest.NewServer(NewHookHandler(make(chan Entry, 1), nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("非 POST 应返回 405，实际 %d", resp.StatusCode)
	}
}

func TestHookHandlerDecompressesGzip(t *testing.T) {
	ch := make(chan Entry, 1)
	srv := httptest.NewServer(NewHookHandler(ch, nil))
	defer srv.Close()

	plain := harBody(harEntryJSON("POST", "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?code=1", 200, "application/json", `{"captchaVerifyResult":true,"checkCodeDto":{}}`))

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, &compressed)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case e := <-ch:
		if e.Status != 200 || e.Verdict != VerdictSuccess {
			t.Fatalf("gzip 上报未被正确解析: %+v", e)
		}
	default:
		t.Fatal("gzip 上报应被解压并推入通道")
	}
}

func TestDecodeHookBody(t *testing.T) {
	plain := []byte(`{"ok":true}`)

	if got, err := decodeHookBody(plain, ""); err != nil || string(got) != string(plain) {
		t.Fatalf("identity 应原样返回: %q %v", got, err)
	}

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write(plain)
	_ = zw.Close()

	// 声明 gzip。
	if got, err := decodeHookBody(compressed.Bytes(), "gzip"); err != nil || string(got) != string(plain) {
		t.Fatalf("gzip 应被解压: %q %v", got, err)
	}
	// 未声明但按魔数识别。
	if got, err := decodeHookBody(compressed.Bytes(), ""); err != nil || string(got) != string(plain) {
		t.Fatalf("未声明 gzip 也应按魔数识别: %q %v", got, err)
	}
	// 不支持的算法要给出可操作错误。
	if _, err := decodeHookBody(plain, "br"); err == nil {
		t.Fatal("brotli 应报不支持")
	}
}
