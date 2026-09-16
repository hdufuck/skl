package signin

import (
	"slices"
	"testing"

	"github.com/hdufuck/skl"
)

func TestMethodsStableIDsAndOrder(t *testing.T) {
	t.Parallel()

	got := make([]string, 0, len(Methods()))
	for _, m := range Methods() {
		if m.Title() == "" {
			t.Fatalf("Method %q 的 Title 为空", m.ID())
		}
		got = append(got, m.ID())
	}

	want := []string{
		MethodAnalyzeA0,
		MethodCodeCheckIn,
		MethodCaptchaMissing,
		MethodCaptchaForged,
		MethodCaptchaGenuine,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Methods() 的 ID 与顺序 = %v, want %v", got, want)
	}
}

func TestMethodsReturnsCopy(t *testing.T) {
	t.Parallel()

	ms := Methods()
	ms[0] = nil

	if Methods()[0] == nil {
		t.Fatal("Methods() 返回的切片被调用方修改后影响了包内状态")
	}
}

func TestFind(t *testing.T) {
	t.Parallel()

	for _, want := range Methods() {
		got, ok := Find(want.ID())
		if !ok {
			t.Fatalf("Find(%q) = false, want true", want.ID())
		}
		if got.ID() != want.ID() {
			t.Fatalf("Find(%q).ID() = %q", want.ID(), got.ID())
		}
	}

	if m, ok := Find("no-such-method"); ok || m != nil {
		t.Fatalf("Find(unknown) = (%v, %v), want (nil, false)", m, ok)
	}
}

// 每个 Method 都必须打到它自己的端点。
func TestEachMethodHitsItsOwnPath(t *testing.T) {
	t.Parallel()

	wantPath := map[string]string{
		MethodAnalyzeA0:      skl.PathSignInAnalyze,
		MethodCodeCheckIn:    skl.PathSignInLegacy,
		MethodCaptchaMissing: skl.PathSignInCaptchaVerify,
		MethodCaptchaForged:  skl.PathSignInCaptchaVerify,
		MethodCaptchaGenuine: skl.PathSignInCaptchaVerify,
	}

	for _, m := range Methods() {
		f := newFakeSkl(t)
		c := newTestSignin(t, f)

		// 带真值参数：Genuine 无需 provider，Forged 用自己的样本。
		_, _ = c.Do(t.Context(), m, Request{
			Code: "1212", Latitude: 1, Longitude: 2,
			CaptchaVerifyParam: `{"sceneId":"2q42bw25"}`,
		})

		if got := f.lastRequest(t).path; got != wantPath[m.ID()] {
			t.Fatalf("%s 打到 %q, want %q", m.ID(), got, wantPath[m.ID()])
		}
	}
}

func TestDoRejectsNilMethod(t *testing.T) {
	t.Parallel()

	f := newFakeSkl(t)
	c := newTestSignin(t, f)

	if _, err := c.Do(t.Context(), nil, Request{Code: "1212"}); err == nil {
		t.Fatal("Do(nil Method) = nil error, want error")
	}
}
