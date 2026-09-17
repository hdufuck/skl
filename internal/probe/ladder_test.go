package probe

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestParseLadder(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []RungID
	}{
		{"空串即默认顺序", "", nil},
		{"all 即默认顺序", "all", nil},
		{"首尾空格忽略", "  all\n", nil},
		{"大写也能认出来", "ALL", nil},
		{"genuine 只跑真值档", "genuine", []RungID{RungCaptchaGenuine}},
		{"junk 是三档非真值档", "junk", []RungID{RungLegacyCheckIn, RungCaptchaMissing, RungCaptchaForged}},
		{"pre 是 junk 的别名", "pre", []RungID{RungLegacyCheckIn, RungCaptchaMissing, RungCaptchaForged}},
		{
			"逗号列表按给定顺序",
			"captcha-verify-genuine,code-check-in",
			[]RungID{RungCaptchaGenuine, RungLegacyCheckIn},
		},
		{
			"元素里的空格忽略",
			" code-check-in , captcha-verify-forged ",
			[]RungID{RungLegacyCheckIn, RungCaptchaForged},
		},
		{"单档列表", "captcha-verify-missing", []RungID{RungCaptchaMissing}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLadder(tt.spec)
			if err != nil {
				t.Fatalf("ParseLadder(%q): %v", tt.spec, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ParseLadder(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

// 未知档位、空元素都要拒绝，并在错误里给出可照抄的合法值——命令行拼错档位
// 是真实窗口里最贵的错误，不能静默退化成默认阶梯。
func TestParseLadderErrors(t *testing.T) {
	bad := []string{
		"nope",
		"captcha-verify-genuine,nope",
		"code-check-in,,captcha-verify-forged",
		"code-check-in,",
		"phone-captcha-verify", // 手机端档位不在本机阶梯上
	}
	for _, spec := range bad {
		t.Run(spec, func(t *testing.T) {
			got, err := ParseLadder(spec)
			if err == nil {
				t.Fatalf("ParseLadder(%q) 应报错，实际 %v", spec, got)
			}
			if !strings.Contains(err.Error(), "captcha-verify-genuine") {
				t.Fatalf("错误里应列出合法档位: %v", err)
			}
		})
	}
}

// Config.Ladder 为空时必须还是原来那条默认阶梯（含真值档）。
func TestRunUsesDefaultLadderWhenUnset(t *testing.T) {
	backend := &fakeBackend{
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Captcha = &fakeCaptchaSource{value: "GENUINE"}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := rungsOf(rep)
	if !slices.Equal(got, Ladder) {
		t.Fatalf("默认开火顺序 = %v, want %v", got, Ladder)
	}
}

// 自定义顺序必须真的改掉档位数量与顺序，而不是只改个名字。
func TestRunCustomLadderOrder(t *testing.T) {
	backend := &fakeBackend{
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(string, string) (int, string, bool) { return 401, codeRejectedBody, false },
	}
	client, rec, _ := newTestClient(t, backend)

	cfg := baseConfig(client, rec)
	cfg.Ladder = []RungID{RungCaptchaForged, RungLegacyCheckIn}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []RungID{RungCaptchaForged, RungLegacyCheckIn}
	if got := rungsOf(rep); !slices.Equal(got, want) {
		t.Fatalf("开火顺序 = %v, want %v", got, want)
	}
}

// 真实窗口的核心用法：只跑真值档，不带前置三档的人机提交先验污染。
func TestRunGenuineOnlyLadder(t *testing.T) {
	backend := &fakeBackend{
		CheckIn: func(string) (int, string, bool) { return 401, codeRejectedBody, false },
		Captcha: func(param, _ string) (int, string, bool) {
			if param == "GENUINE" {
				return 200, `{"captchaVerifyResult":true,"captchaVerifyCode":"T001"}`, true
			}
			return 401, codeRejectedBody, false
		},
	}
	client, rec, _ := newTestClient(t, backend)

	ladder, err := ParseLadder("genuine")
	if err != nil {
		t.Fatalf("ParseLadder: %v", err)
	}
	cfg := baseConfig(client, rec)
	cfg.Ladder = ladder
	cfg.Captcha = &fakeCaptchaSource{value: "GENUINE"}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rungsOf(rep); !slices.Equal(got, []RungID{RungCaptchaGenuine}) {
		t.Fatalf("开火顺序 = %v, want 只跑真值档", got)
	}
	if rep.Entries[0].Status != 200 {
		t.Fatalf("真值档状态码 = %d, want 200", rep.Entries[0].Status)
	}
}

func rungsOf(rep *Report) []RungID {
	out := make([]RungID, len(rep.Entries))
	for i, e := range rep.Entries {
		out[i] = e.Rung
	}
	return out
}
