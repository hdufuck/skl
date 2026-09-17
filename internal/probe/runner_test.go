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
//
// 只有活路径 `captcha-verify`：探针已不再打遗留端点，脚手架里就不再留它的路由。
type fakeBackend struct {
	mu      sync.Mutex
	records []json.RawMessage

	// Captcha 返回 (HTTP status, body, 是否新增一条考勤记录)。
	Captcha func(param, code string) (int, string, bool)
}

func (b *fakeBackend) addRecord(raw string) {
	b.mu.Lock()
	b.records = append(b.records, json.RawMessage(raw))
	b.mu.Unlock()
}

func (b *fakeBackend) snapshot() []json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]json.RawMessage{}, b.records...)
}

func (b *fakeBackend) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/check-in-student-detail/my", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b.snapshot())
	})

	mux.HandleFunc(skl.PathSignInCaptchaVerify, func(w http.ResponseWriter, r *http.Request) {
		status, body, write := b.Captcha(r.URL.Query().Get("captchaVerifyParam"), r.URL.Query().Get("code"))
		if write {
			b.addRecord(`{"id":"checkin-captcha","right":true}`)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	return mux
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
		// 真值来源是必填项，给一个默认的；要观察取参次数的用例自行覆盖。
		Captcha: &fakeCaptchaSource{value: "GENUINE"},
	}
}

// 没有真值来源就无从验证库的 SignIn 封装路径，Run 必须当场报错而不是静默发一次空跑。
func TestRunRequiresCaptchaSource(t *testing.T) {
	backend := &fakeBackend{
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Captcha = nil

	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("没有真值来源时 Run 应报错")
	}
}

func TestRunGenuineSucceeds(t *testing.T) {
	backend := &fakeBackend{
		Captcha: func(param, _ string) (int, string, bool) {
			if param == "GENUINE" {
				return 200, `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{"id":"c1"}}`, true
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	rep, err := Run(context.Background(), baseConfig(client, rec))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rep.Entries) != 1 {
		t.Fatalf("档位数 = %d, want 1（只跑真值档）", len(rep.Entries))
	}
	genuine := rep.Entries[0]
	if genuine.Rung != RungCaptchaGenuine {
		t.Fatalf("档位 = %s", genuine.Rung)
	}
	if !strings.Contains(genuine.URL, "captchaVerifyParam=") {
		t.Fatalf("URL 里应带真值参数: %s", genuine.URL)
	}
	if genuine.CaptchaVerifyCode != "T001" {
		t.Fatalf("captchaVerifyCode = %q, want T001", genuine.CaptchaVerifyCode)
	}
	if genuine.Status != 200 {
		t.Fatalf("状态码 = %d, want 200", genuine.Status)
	}
	if len(genuine.AfterRequest) != 1 {
		t.Fatalf("真值档之后应记录到 1 条考勤记录: %v", genuine.AfterRequest)
	}
}

func TestRunPhoneHook(t *testing.T) {
	newBackend := func() *fakeBackend {
		return &fakeBackend{
			Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
		}
	}

	t.Run("收到上报", func(t *testing.T) {
		client, rec, _ := newTestClient(t, newBackend())
		ch := make(chan Entry, 1)
		ch <- Entry{Rung: "phone", Title: "phone", Status: 200, Body: `{"captchaVerifyResult":true}`}

		cfg := baseConfig(client, rec)
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

	// 手机端停在旧签到页时会带回上一个码：那次 401 与本次窗口无关，不能被
	// 当成「官方权威对照」。
	t.Run("手机端签到码与本次不一致", func(t *testing.T) {
		client, rec, _ := newTestClient(t, newBackend())
		ch := make(chan Entry, 1)
		ch <- Entry{
			Rung:   "phone",
			URL:    "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?userid=24270001&code=5888&t=1789410733678",
			Status: 401,
			Body:   codeRejectedBody,
		}

		cfg := baseConfig(client, rec)
		cfg.Hook = ch

		rep, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		joined := strings.Join(rep.Notes, " | ")
		if !strings.Contains(joined, "5888") || !strings.Contains(joined, "1234") {
			t.Fatalf("签到码不一致应记备注，实际备注: %q", joined)
		}
	})

	t.Run("手机端签到码与本次一致", func(t *testing.T) {
		client, rec, _ := newTestClient(t, newBackend())
		ch := make(chan Entry, 1)
		ch <- Entry{
			Rung:   "phone",
			URL:    "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?userid=24270001&code=1234&t=1789410733678",
			Status: 401,
			Body:   codeRejectedBody,
		}

		cfg := baseConfig(client, rec)
		cfg.Hook = ch

		rep, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if joined := strings.Join(rep.Notes, " | "); strings.Contains(joined, "不能当对照") {
			t.Fatalf("签到码一致不应报不一致，实际备注: %q", joined)
		}
	})
}

// 「200 + 空 body」已证实多为 skl-ticket 重放被拒：换一个新 ticket 重发一次，
// 但不该因此消耗真值档的重取预算。
func TestRunRetriesOnEmptyBody(t *testing.T) {
	var calls atomic.Int32
	backend := &fakeBackend{
		Captcha: func(string, string) (int, string, bool) {
			// 第一次返回「200 + 空 body」（模拟 skl-ticket 重放被拒）。
			if calls.Add(1) == 1 {
				return 200, "", false
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	src := &fakeCaptchaSource{value: "GENUINE"}
	cfg := baseConfig(client, rec)
	cfg.Captcha = src

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	genuine := rep.Entries[0]
	if genuine.Status != 401 {
		t.Fatalf("重发后应记录最终响应 401，实际 %d", genuine.Status)
	}
	if !strings.Contains(genuine.Note, "重发") {
		t.Fatalf("应在备注里标明重发: %q", genuine.Note)
	}
	if len(genuine.Attempts) != 1 {
		t.Fatalf("换 ticket 重发不应计入重取次数，实际 %d 次往返", len(genuine.Attempts))
	}
	// 真值档被请求两次（首次空 body + 重发）。重发走的是同一段 execute，
	// 因此会再取一次参数（一次换 ticket 一次取参，成本已由 200 空 body 的偶发性抵过）。
	if got := calls.Load(); got != 2 {
		t.Fatalf("captcha-verify 请求次数 = %d, want 2", got)
	}
	if src.used != 2 {
		t.Fatalf("取参次数 = %d, want 2（重发会重新取一次参数）", src.used)
	}
}

// 以下两个响应体取自 `har#3` 的浏览器抓包（HAR 第 98 / 101 条）的形状，
// 值一律替换为占位符：真实的学号、教师姓名与课程标识不入库。
const (
	captchaRejectedF001 = `{"captchaVerifyResult":false,"captchaVerifyCode":"F001"}`
	captchaSuccessT001  = `{"captchaVerifyResult":true,"captchaVerifyCode":"T001",` +
		`"checkCodeDto":{"code":"1234","courseId":"COURSE-ID","courseName":"示例课程",` +
		`"courseSchemaId":"SCHEMA-ID","expiresDate":"2006-01-01T00:00:20.000Z","expiresIn":20000,` +
		`"id":"record-id","latitude":30.00000000000000,"longitude":120.00000000000000,` +
		`"recordDate":"2025-12-31T16:00:00.000Z","requestLatitude":30.00001,` +
		`"requestLongitude":120.00001,"studentId":"24000000","teachName":"张三",` +
		`"teacherId":"000**","totalCheckInRecord":null,"week":1}}`
)

// `har#3` 抓包第 6/10 条：请求行超长时是网关应答 414，应用层没收到。
const uriTooLongBody = "URI too long\n"

// 真值档在「网关拒了超长请求行」之后必须换一个新参数重取；否则一次 414 就会
// 把整个窗口浪费掉（抓包里前两次提交都死在这里）。
func TestRunGenuineRetriesAfterURITooLong(t *testing.T) {
	var genuineCalls atomic.Int32
	backend := &fakeBackend{
		Captcha: func(param, _ string) (int, string, bool) {
			if param != "GENUINE" {
				return 401, codeRejectedBody, false
			}
			if genuineCalls.Add(1) == 1 {
				return 414, uriTooLongBody, false
			}
			return 200, captchaSuccessT001, true
		},
	}
	client, rec, _ := newTestClient(t, backend)

	src := &fakeCaptchaSource{value: "GENUINE"}
	cfg := baseConfig(client, rec)
	cfg.Captcha = src

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	genuine := rep.Entries[0]
	if genuine.Status != 200 {
		t.Fatalf("最终记录的状态码 = %d, want 200（不能被首次 414 覆盖）", genuine.Status)
	}
	if src.used != 2 {
		t.Fatalf("取参次数 = %d, want 2（必须重取一个新参数）", src.used)
	}
	if len(genuine.Attempts) != 2 {
		t.Fatalf("往返次数 = %d, want 2", len(genuine.Attempts))
	}
	if genuine.Attempts[0].Status != 414 || genuine.Attempts[0].Retry == "" {
		t.Fatalf("首次往返应记为 414 且带重试原因: %+v", genuine.Attempts[0])
	}
	if genuine.Attempts[1].Status != 200 || genuine.Attempts[1].Retry != "" {
		t.Fatalf("末次往返应是 200 且不再重试: %+v", genuine.Attempts[1])
	}
	if !strings.Contains(genuine.Note, "414") {
		t.Fatalf("备注里应说明 414 重取: %q", genuine.Note)
	}
	if genuine.CaptchaVerifyCode != "T001" {
		t.Fatalf("captchaVerifyCode = %q, want T001", genuine.CaptchaVerifyCode)
	}
}

// 抓包第 98→101 条的原样场景：有效签到码 + 人机判定 false（F001）→
// SDK 自动 reInitCaptcha，重取参数后成功。探针必须做同样的事。
func TestRunGenuineRetriesAfterCaptchaRejected(t *testing.T) {
	var genuineCalls atomic.Int32
	backend := &fakeBackend{
		Captcha: func(param, _ string) (int, string, bool) {
			if param != "GENUINE" {
				return 401, codeRejectedBody, false
			}
			if genuineCalls.Add(1) == 1 {
				return 200, captchaRejectedF001, false
			}
			return 200, captchaSuccessT001, true
		},
	}
	client, rec, _ := newTestClient(t, backend)

	src := &fakeCaptchaSource{value: "GENUINE"}
	cfg := baseConfig(client, rec)
	cfg.Captcha = src

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	genuine := rep.Entries[0]
	if src.used != 2 {
		t.Fatalf("取参次数 = %d, want 2", src.used)
	}
	if len(genuine.Attempts) != 2 {
		t.Fatalf("往返次数 = %d, want 2", len(genuine.Attempts))
	}
	// 末次记录的是成功那次响应，F001 只留在 attempts 里。
	if !strings.Contains(genuine.Body, `"captchaVerifyCode":"T001"`) {
		t.Fatalf("最终响应体应取成功那次: %q", genuine.Body)
	}
	if !strings.Contains(genuine.Attempts[0].Body, "F001") {
		t.Fatalf("首次往返应留档 F001: %+v", genuine.Attempts[0])
	}
}

// 签到码不存在这类明确的响应不该浪费窗口去重取参数。
func TestRunGenuineDoesNotRetryOnCodeRejected(t *testing.T) {
	backend := &fakeBackend{
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	src := &fakeCaptchaSource{value: "GENUINE"}
	cfg := baseConfig(client, rec)
	cfg.Captcha = src

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.used != 1 {
		t.Fatalf("取参次数 = %d, want 1（不该白重取）", src.used)
	}
	if len(rep.Entries[0].Attempts) != 1 {
		t.Fatalf("往返次数 = %d, want 1", len(rep.Entries[0].Attempts))
	}
}

// GenuineAttempts=1 时退化成「只打一枪」，且 414 会如实记录。
func TestRunGenuineAttemptsBudget(t *testing.T) {
	backend := &fakeBackend{
		Captcha: func(param, _ string) (int, string, bool) {
			if param != "GENUINE" {
				return 401, codeRejectedBody, false
			}
			return 414, uriTooLongBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	src := &fakeCaptchaSource{value: "GENUINE"}
	cfg := baseConfig(client, rec)
	cfg.Captcha = src
	cfg.GenuineAttempts = 1

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	genuine := rep.Entries[0]
	if src.used != 1 {
		t.Fatalf("取参次数 = %d, want 1", src.used)
	}
	if genuine.Status != 414 {
		t.Fatalf("状态码 = %d, want 414", genuine.Status)
	}
	// 重试预算耗尽时给出可读原因，而不是静默停在 414 上。
	if !strings.Contains(genuine.Note, "上限") {
		t.Fatalf("备注应说明未重取的原因（预算上限）: %q", genuine.Note)
	}
}

// 真值档连 HTTP 状态都没拿到时，报告要能指出来。
func TestRunGenuineUnproven(t *testing.T) {
	backend := &fakeBackend{
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Captcha = &fakeCaptchaSource{err: fmt.Errorf("SDK 未出参")}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.GenuineUnproven() {
		t.Fatalf("真值档没拿到状态却没报 GenuineUnproven: %+v", rep.Entries[0])
	}
}
