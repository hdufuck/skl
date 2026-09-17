package probe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hdufuck/skl"
	"github.com/hdufuck/skl/pkg/signin"
)

func TestForgeParamUsesSampleLengths(t *testing.T) {
	sample := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2FiMDM0","data":"JRMlgg1EZm9v"}`

	got := ForgeParam(sample)

	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("伪造值不是合法 JSON: %v (%s)", err, got)
	}
	if parsed.SceneID != "2q42bw25" {
		t.Fatalf("sceneId = %q, want 2q42bw25", parsed.SceneID)
	}
	if len(parsed.CertifyID) != 10 || len(parsed.DeviceToken) != 12 || len(parsed.Data) != 12 {
		t.Fatalf("字段长度未沿用样本: %+v", parsed)
	}
	if strings.Trim(parsed.CertifyID+parsed.DeviceToken+parsed.Data, "A") != "" {
		t.Fatalf("伪造内容应为等长占位符: %+v", parsed)
	}
}

func TestForgeParamWithoutSample(t *testing.T) {
	got := ForgeParam("")

	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("伪造值不是合法 JSON: %v", err)
	}
	if parsed.SceneID != skl.DefaultCaptchaSceneID {
		t.Fatalf("sceneId = %q, want %q", parsed.SceneID, skl.DefaultCaptchaSceneID)
	}
	if len(parsed.CertifyID) != signin.ForgeDefaults.CertifyIDLen {
		t.Fatalf("certifyId 长度 = %d, want %d", len(parsed.CertifyID), signin.ForgeDefaults.CertifyIDLen)
	}
}

func TestRedactCaptchaParam(t *testing.T) {
	param := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"` + strings.Repeat("D", 50) + `","data":"` + strings.Repeat("Z", 40) + `"}`

	got := RedactCaptchaParam(param)

	if !strings.Contains(got, `"certifyId":"kVBJ80iOKt"`) {
		t.Fatalf("certifyId 应保留: %s", got)
	}
	if !strings.Contains(got, `"sceneId":"2q42bw25"`) {
		t.Fatalf("sceneId 应保留: %s", got)
	}
	if !strings.Contains(got, "…(len=50)") || !strings.Contains(got, "…(len=40)") {
		t.Fatalf("deviceToken/data 应只留长度与前 20 字符: %s", got)
	}
	if strings.Contains(got, strings.Repeat("D", 21)) || strings.Contains(got, strings.Repeat("Z", 21)) {
		t.Fatalf("长字段未被截断: %s", got)
	}
}

func TestRedactURL(t *testing.T) {
	param := `{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"` + strings.Repeat("D", 30) + `","data":"x"}`

	raw := "https://skl.hdu.edu.cn/api/ali-nvc/captcha-verify?captchaVerifyParam=" + param + "&userid=2427&token=SECRET&sessionId=ALSO-SECRET&t=1"

	got := RedactURL(raw)

	if strings.Contains(got, "SECRET") || strings.Contains(got, "ALSO-SECRET") {
		t.Fatalf("会话凭据泄漏: %s", got)
	}
	if !strings.Contains(got, "token=<redacted>") || !strings.Contains(got, "sessionId=<redacted>") {
		t.Fatalf("会话凭据应被标注: %s", got)
	}
	if strings.Contains(got, strings.Repeat("D", 21)) {
		t.Fatalf("captchaVerifyParam 未字段级脱敏: %s", got)
	}
	if !strings.Contains(got, "userid=2427") {
		t.Fatalf("非敏感参数不应被改动: %s", got)
	}
}

func TestRedactHeadersDropsSecrets(t *testing.T) {
	got := RedactHeaders(map[string][]string{
		"X-Auth-Token":     {"super-secret"},
		"Skl-Ticket":       {"nonce"},
		"Content-Type":     {"application/json"},
		"Content-Encoding": {"gzip"},
	})

	if _, ok := got["X-Auth-Token"]; ok {
		t.Fatal("X-Auth-Token 不应出现在报告里")
	}
	if _, ok := got["Skl-Ticket"]; ok {
		t.Fatal("skl-ticket 不应出现在报告里")
	}
	if got["Content-Type"] != "application/json" {
		t.Fatalf("Content-Type 应保留: %v", got)
	}
}

func TestRedactBody(t *testing.T) {
	body := `{"captchaVerifyResult":true,"token":"SECRET-TOKEN","sessionId":"SECRET-SESSION","checkCodeDto":{"id":"c1"}}`

	got := RedactBody(body)

	if strings.Contains(got, "SECRET-TOKEN") || strings.Contains(got, "SECRET-SESSION") {
		t.Fatalf("响应体里的会话凭据泄漏: %s", got)
	}
	if !strings.Contains(got, `"token":"<redacted>"`) {
		t.Fatalf("token 字段应被抹掉: %s", got)
	}
	// id 是 CheckInRecord 主键，能追回那一条考勤记录，所以要打码。
	if !strings.Contains(got, `"id":"<记录主键，已打码>"`) || strings.Contains(got, `"c1"`) {
		t.Fatalf("记录主键应被打码: %s", got)
	}
}

// 落盘的 markdown 草稿是往 docs/ 抄的原料，所以响应体里的人/课程/记录/时刻
// 字段要按样本文档第 8 节那套规则打码；协议字段（签到码、周次、坐标）保留。
func TestRedactBodyMasksIdentityFields(t *testing.T) {
	body := `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{` +
		`"id":"record-key","code":"1234","studentId":"24000000",` +
		`"courseId":"COURSE-ID","courseSchemaId":"SCHEMA-ID","courseName":"示例课程",` +
		`"teachName":"张三丰","teacherId":"42860","week":1,` +
		`"expiresDate":"2019-03-04T05:06:07.000Z","recordDate":"2019-03-03T16:00:00.000Z",` +
		`"latitude":30.313072,"longitude":120.341896}}`

	got := RedactBody(body)

	for _, leak := range []string{"record-key", "24000000", "COURSE-ID", "SCHEMA-ID", "示例课程", "张三丰", "42860"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q 泄漏: %s", leak, got)
		}
	}
	for _, want := range []string{
		`"studentId":"24*****0"`,
		`"teachName":"张三"`,
		`"courseName":"<课程名，已打码>"`,
		`"id":"<记录主键，已打码>"`,
		`"expiresDate":"2006-01-02T15:04:05.000Z"`,
		`"recordDate":"2006-01-02T00:00:00.000Z"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("缺少 %s：%s", want, got)
		}
	}
	// 协议字段不动：签到码无隐私，周次/坐标不指向人。
	for _, keep := range []string{`"code":"1234"`, `"week":1`, `"captchaVerifyCode":"T001"`, `"latitude":30.313072`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("不该改动 %s：%s", keep, got)
		}
	}
}

// 非 JSON 的响应体（网关的 text/plain、JSONP 外壳）不能被破坏。
func TestRedactBodyLeavesPlainTextAlone(t *testing.T) {
	for _, body := range []string{"URI too long\n", `cb1({"result":{"code":800}})`, ""} {
		if got := RedactBody(body); got != body {
			t.Fatalf("RedactBody(%q) = %q，非 JSON 体应原样返回", body, got)
		}
	}
}

func TestMaskID(t *testing.T) {
	// 只留前 2 位与最后 1 位。
	if got := MaskID("24000000"); got != "24*****0" {
		t.Fatalf("MaskID = %q, want 24*****0", got)
	}
	if got := MaskID("24270001"); got != "24*****1" {
		t.Fatalf("MaskID = %q, want 24*****1", got)
	}
	if got := MaskID("ab"); got != "ab" {
		t.Fatalf("短 id 不应被打码: %q", got)
	}
}

// URLTooLongHint 的边界取自 `har#3` 抓包（**完整 URL** 字节数）：5623（第 1 条，
// 拿到业务 401）被接受，27847（第 10 条）被网关判 414。
// 注意这个常量只是「已实测的最长接受值」，不是服务端上限。
func TestURLTooLongHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		urlLen  int
		wantHit bool
	}{
		{name: "已实测被接受的最长 URL", urlLen: LongestAcceptedURLLen, wantHit: false},
		{name: "短 URL", urlLen: 4696, wantHit: false},
		{name: "刚超过已实测最长值", urlLen: LongestAcceptedURLLen + 1, wantHit: true},
		{name: "已实测被拒的 URL", urlLen: 27847, wantHit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hint := URLTooLongHint(tt.urlLen)
			if hit := hint != ""; hit != tt.wantHit {
				t.Fatalf("URLTooLongHint(%d) = %q, wantHit = %v", tt.urlLen, hint, tt.wantHit)
			}
		})
	}
}
