package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hdufuck/skl"
)

// fakeBackend 是一个可控的 skl 服务端替身。
type fakeBackend struct {
	mu      sync.Mutex
	records []string
	last    string

	// Analyze 返回 (HTTP status, 业务 code)。
	Analyze func(code string) (int, int)
	// CheckIn 返回 (HTTP status, body, 是否写入记录)。
	CheckIn func(code string) (int, string, bool)
	// Captcha 返回 (HTTP status, body, 是否写入记录)。
	Captcha func(param, code string) (int, string, bool)
}

func (b *fakeBackend) addRecord(id string) {
	b.mu.Lock()
	b.records = append(b.records, id)
	b.mu.Unlock()
}

func (b *fakeBackend) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.records...)
}

func (b *fakeBackend) lastParam() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

func (b *fakeBackend) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/check-in-student-detail/my", func(w http.ResponseWriter, _ *http.Request) {
		arr := make([]json.RawMessage, 0)
		for _, id := range b.snapshot() {
			arr = append(arr, json.RawMessage(fmt.Sprintf(`{"id":%q}`, id)))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(arr)
	})

	mux.HandleFunc(skl.PathSignInAnalyze, func(w http.ResponseWriter, r *http.Request) {
		status, biz := b.Analyze(r.URL.Query().Get("code"))
		cb := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(status)
		fmt.Fprintf(w, "%s(%s)", cb, fmt.Sprintf(`{"result":{"code":%d}}`, biz))
	})

	mux.HandleFunc(skl.PathSignInLegacy, func(w http.ResponseWriter, r *http.Request) {
		status, body, write := b.CheckIn(r.URL.Query().Get("code"))
		if write {
			b.addRecord("checkin-legacy")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	mux.HandleFunc(skl.PathSignInCaptchaVerify, func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("captchaVerifyParam")
		b.mu.Lock()
		b.last = param
		b.mu.Unlock()
		status, body, write := b.Captcha(param, r.URL.Query().Get("code"))
		if write {
			b.addRecord("checkin-captcha")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	return mux
}

type fakePrompter struct {
	mu      sync.Mutex
	answer  bool
	gates   int
	notices []string
}

func (p *fakePrompter) Gate(context.Context, Entry, time.Duration) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gates++
	return p.answer, nil
}

func (p *fakePrompter) Notify(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notices = append(p.notices, fmt.Sprintf(format, args...))
}

type fakeCaptchaSource struct {
	value string
	err   error
	used  int
}

func (s *fakeCaptchaSource) Param(context.Context) (string, error) {
	s.used++
	return s.value, s.err
}

func (s *fakeCaptchaSource) Close() error { return nil }

const codeRejectedBody = `{"code":0,"msg":"签到码不存在，不要玩我"}`

func newTestClient(t *testing.T, backend *fakeBackend) (*skl.Client, *Recorder, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(backend.handler())
	t.Cleanup(srv.Close)

	rec := NewRecorder(nil)
	client, err := skl.NewClient(
		skl.WithBaseURL(srv.URL),
		skl.WithToken("test-token"),
		skl.WithTransport(rec),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, rec, srv
}

func baseConfig(client *skl.Client, rec *Recorder) Config {
	return Config{
		Client:   client,
		Recorder: rec,
		Code:     "1234",
		UserID:   "24270001",
		Coord:    Coord{Lat: 30.313816, Lon: 120.343228},
		ReadBack: ReadBackToday(client),
	}
}

func TestRunAllCodeRejected(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.SkipGenuine = true

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Entries) != 4 {
		t.Fatalf("档位数 = %d, want 4", len(rep.Entries))
	}
	for _, e := range rep.Entries {
		if e.Verdict != VerdictCodeRejected {
			t.Fatalf("%s 判读 = %s, want code_rejected", e.Rung, e.Verdict)
		}
	}
	if rep.StoppedAt != "" {
		t.Fatalf("不应停止，却停在 %s", rep.StoppedAt)
	}
	if rep.WrittenWithoutCaptcha() {
		t.Fatal("不应出现不强制人机的证据")
	}
	if len(backend.snapshot()) != 0 {
		t.Fatalf("不应写入记录: %v", backend.snapshot())
	}
}

func TestRunLegacyWriteStopsByDefault(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) {
			return 200, `{"captchaVerifyResult":true,"checkCodeDto":{"id":"x"}}`, true
		},
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	rep, err := Run(context.Background(), baseConfig(client, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rep.Entries) != 2 {
		t.Fatalf("应在第 2 档后停止，实际执行 %d 档", len(rep.Entries))
	}
	last := rep.Entries[1]
	if last.Rung != RungLegacyCheckIn {
		t.Fatalf("停在第 %s 档", last.Rung)
	}
	if last.Verdict != VerdictWrittenNoCaptcha {
		t.Fatalf("判读 = %s, want written_without_captcha", last.Verdict)
	}
	if !last.Wrote || len(last.NewKeys) != 1 || last.NewKeys[0] != "id:checkin-legacy" {
		t.Fatalf("读回 diff 不对: %+v", last)
	}
	if rep.StoppedAt != RungLegacyCheckIn {
		t.Fatalf("StoppedAt = %s, want %s", rep.StoppedAt, RungLegacyCheckIn)
	}
	if !rep.WrittenWithoutCaptcha() {
		t.Fatal("应判定为不强制人机")
	}
}

func TestRunGenuineSucceeds(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(param, _ string) (int, string, bool) {
			if param == "GENUINE" {
				return 200, `{"captchaVerifyResult":true,"checkCodeDto":{"id":"c1"}}`, true
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Captcha = &fakeCaptchaSource{value: "GENUINE"}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rep.Entries) != 5 {
		t.Fatalf("档位数 = %d, want 5", len(rep.Entries))
	}
	genuine := rep.Entries[4]
	if genuine.Rung != RungCaptchaGenuine {
		t.Fatalf("第 5 档 = %s", genuine.Rung)
	}
	if genuine.Verdict != VerdictSuccess {
		t.Fatalf("真值档判读 = %s, want success", genuine.Verdict)
	}
	if genuine.ParamKind != ParamGenuine {
		t.Fatalf("凭证形态 = %s, want genuine", genuine.ParamKind)
	}
	if !strings.Contains(genuine.URL, "captchaVerifyParam=") {
		t.Fatalf("URL 里应带真值参数: %s", genuine.URL)
	}
	if rep.StoppedAt != RungCaptchaGenuine {
		t.Fatalf("StoppedAt = %s, want %s", rep.StoppedAt, RungCaptchaGenuine)
	}
	if got := rep.Successes(); len(got) != 1 || got[0] != RungCaptchaGenuine {
		t.Fatalf("Successes = %v", got)
	}
}

func TestRunForgedParamIsStructurallyValid(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Sample = `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2Fi","data":"JRMlgg1E"}`

	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 最后一次 captcha-verify 请求是伪造档。
	got := backend.lastParam()
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("伪造参数不是合法 JSON: %q", got)
	}
	if parsed["sceneId"] != "2q42bw25" || len(parsed["certifyId"]) != 10 {
		t.Fatalf("伪造参数未沿用样本: %v", parsed)
	}
}

func TestRunGateContinue(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(param, _ string) (int, string, bool) {
			if param == "GENUINE" {
				return 200, `{"captchaVerifyResult":true,"checkCodeDto":{"id":"c1"}}`, true
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	prompter := &fakePrompter{answer: true}
	cfg := baseConfig(client, rec)
	cfg.Prompter = prompter
	cfg.Captcha = &fakeCaptchaSource{value: "GENUINE"}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Entries) != 5 {
		t.Fatalf("交互闸返回继续时应跑满 5 档，实际 %d", len(rep.Entries))
	}
	if prompter.gates != 1 {
		t.Fatalf("Gates = %d, want 1", prompter.gates)
	}
	if rep.StoppedAt != "" {
		t.Fatalf("不应停止: %s", rep.StoppedAt)
	}
}

func TestRunSkipsGenuineOverBudget(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(param, _ string) (int, string, bool) {
			if param == "GENUINE" {
				return 200, `{"captchaVerifyResult":true,"checkCodeDto":{"id":"c1"}}`, true
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Captcha = &fakeCaptchaSource{value: "GENUINE"}
	cfg.CaptchaDeadline = time.Nanosecond

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Entries) != 4 {
		t.Fatalf("超出预算时应跳过真值档，实际 %d 档", len(rep.Entries))
	}
	if len(rep.Notes) == 0 {
		t.Fatal("应记录跳过原因")
	}
}

func TestRunPhoneHook(t *testing.T) {
	newBackend := func() *fakeBackend {
		return &fakeBackend{
			Analyze: func(string) (int, int) { return 200, 800 },
			CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
			Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
		}
	}

	t.Run("收到上报", func(t *testing.T) {
		client, rec, _ := newTestClient(t, newBackend())
		ch := make(chan Entry, 1)
		ch <- Entry{Rung: "phone", Title: "phone", Status: 200, Body: `{"captchaVerifyResult":true}`}

		cfg := baseConfig(client, rec)
		cfg.SkipGenuine = true
		cfg.Hook = ch

		rep, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if rep.PhoneHAR == nil || rep.PhoneHAR.Status != 200 || !rep.PhoneHAR.FromPhone {
			t.Fatalf("手机 HAR 未并入: %+v", rep.PhoneHAR)
		}
		if rep.HookMissing {
			t.Fatal("不应标记 hookMissing")
		}
	})

	t.Run("未收到上报", func(t *testing.T) {
		client, rec, _ := newTestClient(t, newBackend())
		ch := make(chan Entry)

		cfg := baseConfig(client, rec)
		cfg.SkipGenuine = true
		cfg.Hook = ch
		cfg.HookWait = time.Millisecond

		rep, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !rep.HookMissing || rep.PhoneHAR != nil {
			t.Fatalf("应标记 hookMissing: %+v", rep)
		}
	})
}

func TestRunRetriesOnEmptyBody(t *testing.T) {
	var calls atomic.Int32
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) {
			// 第一次返回「200 + 空 body」（模拟 skl-ticket 重放被拒）。
			if calls.Add(1) == 1 {
				return 200, "", false
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.SkipGenuine = true

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	missing := rep.Entries[2]
	if missing.Rung != RungCaptchaMissing {
		t.Fatalf("第 3 档 = %s", missing.Rung)
	}
	if missing.Status != 401 {
		t.Fatalf("重发后应记录最终响应 401，实际 %d", missing.Status)
	}
	if !strings.Contains(missing.Note, "重发") {
		t.Fatalf("应在备注里标明重发: %q", missing.Note)
	}
	if missing.Verdict != VerdictCodeRejected {
		t.Fatalf("判读 = %s, want code_rejected", missing.Verdict)
	}
	// 缺失档被请求两次（首次空 body + 重发），随后的伪造档一次。
	if got := calls.Load(); got != 3 {
		t.Fatalf("captcha-verify 请求次数 = %d, want 3", got)
	}
}

func TestRunRecordsRawExchange(t *testing.T) {
	backend := &fakeBackend{
		Analyze: func(string) (int, int) { return 200, 800 },
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.SkipGenuine = true

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	analyze := rep.Entries[0]
	if analyze.Status != 200 || !strings.Contains(analyze.Body, `"code":800`) {
		t.Fatalf("analyze 原始响应未记录: %+v", analyze)
	}
	if analyze.RespHeaders["Content-Type"] == "" {
		t.Fatalf("响应头未记录: %+v", analyze.RespHeaders)
	}
	checkIn := rep.Entries[1]
	if checkIn.Status != 401 || !strings.Contains(checkIn.Body, "签到码不存在") {
		t.Fatalf("check-in 原始响应未记录: %+v", checkIn)
	}
	if !strings.Contains(checkIn.URL, "code=1234") {
		t.Fatalf("URL 未记录: %s", checkIn.URL)
	}
}
