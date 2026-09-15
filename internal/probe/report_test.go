package probe

import (
	"strings"
	"testing"
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
