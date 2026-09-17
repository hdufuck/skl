package chromecaptcha

// 设备指纹（阿里云 cloudauth-device）的上传活动。
//
// 为什么盯它：`deviceToken` 是 SDK 初始化时就铸好的（挂在第一次 `InitCaptcha` 上），
// 而设备指纹的**数据**是之后才分 Log2 / Log3 两次 POST 到 cloudauth-device 的。
// `har#4` 的时序（页面加载为 0）：
//
//	  +0.18s  InitCaptcha（此时铸出 deviceToken / DeviceData）
//	  +0.49s  Log2（设备数据第一批）
//	  +3.42s  Log3（设备数据第二批）
//	  +3.45s  第一次点击 → InitCaptcha（带 DeviceToken）→ 提交
//
// 也就是说：页面刚 `getInstance` 就去点触发时，我们的 certifyId 引用的设备记录
// 可能**还没落库**，风控只能给出 F001（风险策略不通过）。预热因此要多等一步：
// 「设备指纹上传静下来」才算可以点了。
//
// ⚠️ 成因未证（`har#4` 里三次尝试都在 Log3 之后 25–650ms，仍全是 F001）。
// 这一步只是把**确定能避免的竞态**去掉，代价为零：它发生在 T0 之前。
//
// 判据用**时间**而不是「在途请求数为 0」：Log2 与 Log3 之间隔了近 3 秒，
// 而每次上传只要 ~55ms ——「多久没有新的设备指纹请求」比「当前没有在途请求」更稳，
// 也不怕某次请求的完成事件没到。

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
)

// 设备指纹等待的默认参数。
const (
	// defaultFingerprintGrace 是「等第一个设备指纹请求出现」的时长。
	//
	// 没有出现就当 deviceToken 已缓存（手机那次成功样本就是：同一个 token 复用，
	// 整条链路里没有任何 cloudauth-device 请求），不必空等。
	defaultFingerprintGrace = 1500 * time.Millisecond
	// defaultFingerprintSettle 是「多久没有新的设备指纹请求」就算落地。
	//
	// 必须大于 Log2→Log3 的间隔（实测 2.93s），否则会在 Log3 之前就宣布就绪。
	defaultFingerprintSettle = 4 * time.Second
	// fingerprintWarmupBudget 是整个等待的上限，避免异常页面把预热拖死。
	fingerprintWarmupBudget = 20 * time.Second
	// fingerprintPollInterval 是轮询间隔。
	fingerprintPollInterval = 100 * time.Millisecond
)

// fingerprintWatch 记录设备指纹请求的活动时刻。
//
// 它同时被两处使用：`Source` 的 `ListenTarget` 回调（CDP 事件循环里单线程执行）
// 与等待循环（`waitFingerprint`），所以每个方法都自己上锁。
type fingerprintWatch struct {
	mu     sync.Mutex
	seen   bool
	lastAt time.Time
	count  int
	// ids 是「已确认属于设备指纹」的请求 ID：`EventLoadingFinished` 只带 RequestID
	// 不带 URL，只能靠它把完成事件认回来。
	ids map[network.RequestID]struct{}
}

func newFingerprintWatch() *fingerprintWatch {
	return &fingerprintWatch{ids: map[network.RequestID]struct{}{}}
}

// track 记一次开始：把它记为活动，并记住这个请求 ID 以便认回完成事件。
func (w *fingerprintWatch) track(id network.RequestID, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observeLocked(at)
	w.ids[id] = struct{}{}
}

// finish 认领一个完成事件；不是设备指纹请求时返回 false。
func (w *fingerprintWatch) finish(id network.RequestID, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.ids[id]; !ok {
		return
	}
	delete(w.ids, id)
	w.observeLocked(at)
}

func (w *fingerprintWatch) observeLocked(at time.Time) {
	w.seen = true
	w.lastAt = at
	w.count++
}

// snapshot 返回（是否见过设备指纹请求、最后一次活动时刻、请求次数）。
func (w *fingerprintWatch) snapshot() (bool, time.Time, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen, w.lastAt, w.count
}

// isDeviceFingerprintURL 报告一个 URL 是否是设备指纹上传。
//
// 实测主机名形如 `cloudauth-device-dualstack.cn-shanghai.aliyuncs.com`
// （`har#4` 的 Log2 / Log3），历史版本里也有 `cloudauth-device.<region>…`。
func isDeviceFingerprintURL(rawURL string) bool {
	return strings.Contains(hostOf(rawURL), "cloudauth-device")
}

// hostOf 取 URL 的主机名；解析不出来时退回整串。
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// waitFingerprint 等设备指纹上传落地，返回时页面才算真正「可以点了」。
//
// 它只花 T0 **之前**的时间（预热发生在输入签到码之前），所以预算给得宽。
func (s *Source) waitFingerprint(ctx context.Context, grace, settle time.Duration) {
	if grace <= 0 {
		grace = defaultFingerprintGrace
	}
	if settle <= 0 {
		settle = defaultFingerprintSettle
	}

	start := time.Now()
	deadline := start.Add(fingerprintWarmupBudget)
	ticker := time.NewTicker(fingerprintPollInterval)
	defer ticker.Stop()

	for {
		seen, lastAt, count := s.fp.snapshot()
		now := time.Now()
		switch {
		case !seen && now.Sub(start) >= grace:
			s.logf("chromecaptcha: %s 内没有设备指纹上传（deviceToken 已缓存？），直接就绪", grace)
			return
		case seen && now.Sub(lastAt) >= settle:
			s.logf("chromecaptcha: 设备指纹已落地（%d 次上传，最后一次 %s 前）",
				count, now.Sub(lastAt).Round(time.Millisecond))
			return
		case now.After(deadline):
			s.logf("chromecaptcha: 设备指纹等待超过 %s，不再等（见过=%v），就绪", fingerprintWarmupBudget, seen)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
