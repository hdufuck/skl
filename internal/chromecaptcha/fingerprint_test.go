package chromecaptcha

// 设备指纹预热的离线回归：New 必须等到设备指纹上传**落地**才算「可以点了」。
//
// 桩页面在 `getInstance`（就绪）之后才发出一次 cloudauth-device 请求，
// 复刻 `har#4` 里「就绪 → Log2/Log3 上传」的先后关系。

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// stubSDKWithFingerprint 在桩 SDK 基础上，就绪之后再模拟一次设备指纹上传。
func stubSDKWithFingerprint(fingerprintURL string, uploadDelay time.Duration) string {
	return fmt.Sprintf(`
window.initAliyunCaptcha = function (opts) {
  window.__initOpts = opts;
  setTimeout(function () {
    var btn = document.querySelector(opts.button);
    btn.addEventListener("click", function () {
      opts.captchaVerifyCallback("STUB-CAPTCHA-PARAM");
    });
    setTimeout(function () { fetch(%q).catch(function () {}); }, %d);
    if (opts.getInstance) {
      opts.getInstance({ stub: true });
    }
  }, %d);
};
`, fingerprintURL, uploadDelay/time.Millisecond, stubSDKBindDelay/time.Millisecond)
}

func TestWarmupWaitsForFingerprintUpload(t *testing.T) {
	const (
		fingerprintURL = "https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com/?Action=Log3"
		uploadDelay    = 400 * time.Millisecond
	)
	start := time.Now()
	src := newOfflineSource(t, Options{
		Fulfill: func(rawURL string) (string, string, bool) {
			switch {
			case strings.Contains(rawURL, "cloudauth-device"):
				return "application/json", `{"Code":"200","Success":true}`, true
			case strings.Contains(rawURL, "AliyunCaptcha"):
				return "application/javascript", stubSDKWithFingerprint(fingerprintURL, uploadDelay), true
			default:
				return "", "", false
			}
		},
		FingerprintGrace:  2 * time.Second,
		FingerprintSettle: 300 * time.Millisecond,
	})
	elapsed := time.Since(start)

	// 就绪在 stubSDKBindDelay，上传在它之后 uploadDelay —— New 返回时必须已经等过它。
	if want := stubSDKBindDelay + uploadDelay; elapsed < want {
		t.Fatalf("New 在 %s 就返回了：没有等设备指纹上传落地（至少要等到 %s）",
			elapsed.Round(time.Millisecond), want)
	}
	if elapsed > fingerprintWarmupBudget {
		t.Fatalf("New 用了 %s，超过预热上限", elapsed.Round(time.Millisecond))
	}
	seen, _, count := src.fp.snapshot()
	if !seen || count == 0 {
		t.Fatal("没有观察到设备指纹上传活动")
	}
}

// TestWarmupWithoutFingerprintReturnsAfterGrace 保证 deviceToken 已缓存
// （整条链路里没有任何 cloudauth-device 请求，手机那次成功样本就是这样）时，
// 预热只等 grace，不空等 settle 或预算。
func TestWarmupWithoutFingerprintReturnsAfterGrace(t *testing.T) {
	const grace = 500 * time.Millisecond
	start := time.Now()
	src := newOfflineSource(t, Options{
		FingerprintGrace:  grace,
		FingerprintSettle: 5 * time.Second,
	})
	elapsed := time.Since(start)

	if elapsed < stubSDKBindDelay+grace {
		t.Fatalf("New 在 %s 就返回了：没有等满 grace(%s)", elapsed.Round(time.Millisecond), grace)
	}
	if elapsed > stubSDKBindDelay+grace+3*time.Second {
		t.Fatalf("New 用了 %s：没有设备指纹请求时不该等 settle/budget", elapsed.Round(time.Millisecond))
	}
	if seen, _, count := src.fp.snapshot(); seen || count != 0 {
		t.Fatalf("桩页面不该有设备指纹请求: seen=%v count=%d", seen, count)
	}
}
