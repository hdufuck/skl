package probe

import (
	"strings"
	"testing"
	"time"
)

// GenuineUnproven 是演练（--code 0000）里「真值档到底有没有跑起来」的唯一硬信号：
// transport_error 说明请求根本没发出去，不是「真值档失败」。
func TestGenuineUnproven(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		want    bool
	}{
		{
			name:    "真值档 transport_error",
			entries: []Entry{{Rung: RungCaptchaGenuine, Verdict: VerdictTransportError}},
			want:    true,
		},
		{
			name:    "真值档拿到了 401",
			entries: []Entry{{Rung: RungCaptchaGenuine, Status: 401, Verdict: VerdictCodeRejected}},
			want:    false,
		},
		{
			name:    "没跑真值档（--no-browser）不算未验证",
			entries: []Entry{{Rung: RungCaptchaForged, Status: 401, Verdict: VerdictCodeRejected}},
			want:    false,
		},
		{
			name: "前面的档 transport_error 不算在真值档头上",
			entries: []Entry{
				{Rung: RungAnalyzeA0, Verdict: VerdictTransportError},
				{Rung: RungCaptchaGenuine, Status: 401, Verdict: VerdictCodeRejected},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := &Report{Entries: tc.entries}
			if got := rep.GenuineUnproven(); got != tc.want {
				t.Fatalf("GenuineUnproven() = %v, want %v", got, tc.want)
			}
		})
	}
}

// 演练报告里必须能看到这条警告，否则「真值档没跑起来」会被表格里的一个「-」吞掉。
func TestMarkdownWarnsWhenGenuineUnproven(t *testing.T) {
	rep := &Report{
		Version: "signinprobe/test",
		Entries: []Entry{
			{Rung: RungCaptchaGenuine, ParamKind: ParamGenuine, Verdict: VerdictTransportError,
				Err: "probe: 获取真值 captchaVerifyParam: chromecaptcha: 触发验证码失败: context canceled"},
		},
	}
	md := rep.Markdown()
	if !strings.Contains(md, "真值档未验证") {
		t.Fatalf("报告没有标注真值档未验证：\n%s", md)
	}
}

// Notes 曾经只进 JSON，不进 md —— 演练时人看的是 md，等于没写。
func TestMarkdownRendersNotes(t *testing.T) {
	rep := &Report{
		Version: "signinprobe/test",
		Notes:   []string{"手机端上报的签到码是 5888，与本次的 0000 不同 ⟹ 那不是同一个窗口"},
	}
	if md := rep.Markdown(); !strings.Contains(md, "5888") || !strings.Contains(md, "备注") {
		t.Fatalf("报告没有渲染备注：\n%s", md)
	}
}

// 真值档重取时，被盖掉的那几次往返必须能在 md 里看到：抓包第 98 条的 F001
// 就是「有效签到码 + 人机判 false」的直接证据，只有第一次往返里有。
func TestMarkdownRendersAttempts(t *testing.T) {
	rep := &Report{
		Version: "signinprobe/test",
		Entries: []Entry{
			{
				Rung:              RungCaptchaGenuine,
				ParamKind:         ParamGenuine,
				Status:            200,
				CaptchaVerifyCode: "T001",
				Body:              `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{"id":"x"}}`,
				Verdict:           VerdictSuccess,
				Note:              "人机判定为 false ⟹ 换一个新参数重取",
				Attempts: []Attempt{
					{Status: 414, URLLen: 27847, Body: "URI too long\n",
						Retry: "HTTP 414：请求行长 27847 字节，被网关拒绝（未达应用）⟹ 换一个新参数重取"},
					{Status: 200, URLLen: 4696, Body: `{"captchaVerifyResult":false,"captchaVerifyCode":"F001"}`,
						Retry: "人机判定为 false ⟹ 换一个新参数重取"},
					{Status: 200, URLLen: 4696,
						Body: `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{"id":"x"}}`},
				},
			},
		},
	}

	md := rep.Markdown()
	for _, want := range []string{"往返明细", "27847", "F001", "captchaVerifyCode"} {
		if !strings.Contains(md, want) {
			t.Fatalf("报告缺少 %q：\n%s", want, md)
		}
	}
	// 成功那次响应是 e.Body，不该在「第 N 次响应」里重复渲染。
	if strings.Count(md, `"captchaVerifyCode":"T001"`) != 1 {
		t.Fatalf("成功响应被重复渲染：\n%s", md)
	}
}

// 落盘草稿里不能出现考勤记录主键（它能追回那一条记录）；哈希形态不指向人，保留。
func TestMarkdownMasksRecordKeys(t *testing.T) {
	rep := &Report{
		Version: "signinprobe/test",
		UserID:  "24000000",
		Entries: []Entry{
			{Rung: RungCaptchaGenuine, ParamKind: ParamGenuine, Status: 200,
				Before: 0, After: 1, Verdict: VerdictSuccess,
				NewKeys: []string{"id:zvQfKIM6bzPrJeteS1T", "sha256:deadbeef"}},
		},
	}
	md := rep.Markdown()
	if strings.Contains(md, "zvQfKIM6bzPrJeteS1T") {
		t.Fatalf("记录主键泄漏: \n%s", md)
	}
	// 期望值由 MaskID 推出，避免在测试里手数星号。
	if want := "id:" + MaskID("zvQfKIM6bzPrJeteS1T"); !strings.Contains(md, want) {
		t.Fatalf("记录主键应被打码成 %q: \n%s", want, md)
	}
	if !strings.Contains(md, "sha256:deadbeef") {
		t.Fatalf("哈希形态不指向人，应保留: \n%s", md)
	}
	if strings.Contains(md, "24000000") {
		t.Fatalf("学号泄漏: \n%s", md)
	}
	if !strings.Contains(md, "24*****0") {
		t.Fatalf("学号应被打码: \n%s", md)
	}
}

// 草稿里连运行时刻都不留：它和学号/课程同级，都指向「哪节课的谁」。
func TestMarkdownMasksRunTimestamp(t *testing.T) {
	rep := &Report{
		Version:   "signinprobe/test",
		StartedAt: time.Date(2026, 9, 16, 18, 31, 41, 0, time.FixedZone("CST", 8*3600)),
	}
	md := rep.Markdown()
	for _, leak := range []string{"2026-09-16", "18:31", "2026-09"} {
		if strings.Contains(md, leak) {
			t.Fatalf("草稿泄漏运行时刻 %q:\n%s", leak, md)
		}
	}
	if !strings.Contains(md, "运行时间：已打码") {
		t.Fatalf("应标明运行时间已打码:\n%s", md)
	}
}
