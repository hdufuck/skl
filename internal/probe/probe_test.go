package probe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hdufuck/skl"
)

func TestClassify(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name string
		in   ClassifyInput
		want Verdict
	}{
		{
			name: "传输错误",
			in:   ClassifyInput{Rung: RungCaptchaMissing, Err: "connection refused"},
			want: VerdictTransportError,
		},
		{
			name: "真值档写入记录即成功",
			in:   ClassifyInput{Rung: RungCaptchaGenuine, Status: 200, Body: []byte(`{}`), Wrote: true},
			want: VerdictSuccess,
		},
		{
			name: "缺失档写入记录 = 不强制人机",
			in:   ClassifyInput{Rung: RungCaptchaMissing, Status: 200, Body: []byte(`{}`), Wrote: true},
			want: VerdictWrittenNoCaptcha,
		},
		{
			name: "遗留档写入记录 = 不强制人机",
			in:   ClassifyInput{Rung: RungLegacyCheckIn, Status: 200, Body: []byte(`{}`), Wrote: true},
			want: VerdictWrittenNoCaptcha,
		},
		{
			name: "200 空 body",
			in:   ClassifyInput{Rung: RungLegacyCheckIn, Status: 200, Body: []byte("  \n")},
			want: VerdictEmptyBody,
		},
		{
			name: "analyze 100 成功",
			in:   ClassifyInput{Rung: RungAnalyzeA0, Status: 200, Body: []byte(`{"result":{"code":100}}`), HasAnalyzeCode: true, AnalyzeCode: 100},
			want: VerdictSuccess,
		},
		{
			name: "analyze 200 成功",
			in:   ClassifyInput{Rung: RungAnalyzeA0, Status: 200, Body: []byte(`{"result":{"code":200}}`), HasAnalyzeCode: true, AnalyzeCode: 200},
			want: VerdictSuccess,
		},
		{
			name: "analyze 400 要求人机",
			in:   ClassifyInput{Rung: RungAnalyzeA0, Status: 200, Body: []byte(`{"result":{"code":400}}`), HasAnalyzeCode: true, AnalyzeCode: 400},
			want: VerdictCaptchaRejected,
		},
		{
			name: "analyze 800 被拒",
			in:   ClassifyInput{Rung: RungAnalyzeA0, Status: 200, Body: []byte(`{"result":{"code":800}}`), HasAnalyzeCode: true, AnalyzeCode: 800},
			want: VerdictCodeRejected,
		},
		{
			name: "analyze 900 被拒",
			in:   ClassifyInput{Rung: RungAnalyzeA0, Status: 200, Body: []byte(`{"result":{"code":900}}`), HasAnalyzeCode: true, AnalyzeCode: 900},
			want: VerdictCodeRejected,
		},
		{
			name: "captchaVerifyResult=false 指向人机层",
			in:   ClassifyInput{Rung: RungCaptchaGenuine, Status: 200, Body: []byte(`{"captchaVerifyResult":false}`), CaptchaVerifyResult: boolPtr(false)},
			want: VerdictCaptchaRejected,
		},
		{
			name: "captchaVerifyResult=true 且有 checkCodeDto",
			in:   ClassifyInput{Rung: RungCaptchaGenuine, Status: 200, Body: []byte(`{"captchaVerifyResult":true,"checkCodeDto":{"id":"x"}}`), CaptchaVerifyResult: boolPtr(true), CheckCodeDtoLen: 12},
			want: VerdictSuccess,
		},
		{
			name: "captchaVerifyResult=true 但 checkCodeDto 为空",
			in:   ClassifyInput{Rung: RungCaptchaGenuine, Status: 200, Body: []byte(`{"captchaVerifyResult":true}`), CaptchaVerifyResult: boolPtr(true)},
			want: VerdictUnattributable,
		},
		{
			name: "401 签到码不存在",
			in:   ClassifyInput{Rung: RungCaptchaMissing, Status: 401, Body: []byte(`{"code":0,"msg":"签到码不存在，不要玩我"}`)},
			want: VerdictCodeRejected,
		},
		{
			name: "文案提到人机",
			in:   ClassifyInput{Rung: RungCaptchaMissing, Status: 403, Body: []byte(`{"code":0,"msg":"请完成人机验证"}`)},
			want: VerdictCaptchaRejected,
		},
		{
			name: "400 活路径 msg 指向参数层",
			in:   ClassifyInput{Rung: RungCaptchaForged, Status: 400, Body: []byte(`{"code":0,"msg":"参数不合法"}`)},
			want: VerdictParamRejected,
		},
		{
			name: "400 无 msg 活路径归因参数层",
			in:   ClassifyInput{Rung: RungCaptchaForged, Status: 400, Body: []byte(`bad request`)},
			want: VerdictParamRejected,
		},
		{
			name: "遗留档 400 无 msg 不硬判",
			in:   ClassifyInput{Rung: RungLegacyCheckIn, Status: 400, Body: []byte(`bad request`)},
			want: VerdictUnattributable,
		},
		{
			name: "未知形态",
			in:   ClassifyInput{Rung: RungLegacyCheckIn, Status: 500, Body: []byte(`{"boom":1}`)},
			want: VerdictUnattributable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.in); got != tt.want {
				t.Fatalf("Classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

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
	if len(parsed.CertifyID) != ForgeDefaults.CertifyIDLen {
		t.Fatalf("certifyId 长度 = %d, want %d", len(parsed.CertifyID), ForgeDefaults.CertifyIDLen)
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
	if !strings.Contains(got, `"id":"c1"`) {
		t.Fatalf("无关字段不应被改动: %s", got)
	}
}

func TestMaskID(t *testing.T) {
	if got := MaskID("24270001"); got != "2427****" {
		t.Fatalf("MaskID = %q", got)
	}
	if got := MaskID("ab"); got != "ab" {
		t.Fatalf("短 id 不应被打码: %q", got)
	}
}

// 测试数据一律用虚构姓名：真名不进仓库。
func TestMaskName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"张三丰", "张**"},
		{"欧阳修文", "欧**"}, // 复姓也只留第一个字
		{"张三", "张**"},
		{"李", "李**"}, // 单字名同样不露出长度
		{"Li Hua", "L**"},
		{"  张三丰  ", "张**"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := MaskName(tc.in); got != tc.want {
			t.Errorf("MaskName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSnapshotDiff(t *testing.T) {
	before := SnapshotFromRaw([]json.RawMessage{
		json.RawMessage(`{"id":"a","x":1}`),
	})
	after := SnapshotFromRaw([]json.RawMessage{
		json.RawMessage(`{"id":"a","x":1}`),
		json.RawMessage(`{"id":"b","x":2}`),
	})

	newKeys := after.NewKeys(before)
	if len(newKeys) != 1 || newKeys[0] != "id:b" {
		t.Fatalf("新增标识 = %v, want [id:b]", newKeys)
	}
	if after.NewKeys(after) != nil {
		t.Fatal("自身比对不应有新增")
	}
}

func TestSnapshotFallbackToContentHash(t *testing.T) {
	before := SnapshotFromRaw([]json.RawMessage{json.RawMessage(`{"courseName":"x"}`)})
	after := SnapshotFromRaw([]json.RawMessage{
		json.RawMessage(`{"courseName":"x"}`),
		json.RawMessage(`{"courseName":"y"}`),
	})

	if len(after.NewKeys(before)) != 1 {
		t.Fatalf("无 id 字段时应退化为内容哈希: %v", after.NewKeys(before))
	}
}
