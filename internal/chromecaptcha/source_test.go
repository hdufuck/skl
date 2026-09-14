package chromecaptcha

import (
	"context"
	"testing"
	"time"
)

// browserContext 是「把调用方 deadline/取消叠加到浏览器 ctx 上」的关键修复点：
// 之前 Param 直接把调用方 ctx 交给 chromedp.Run，运行时必然报 invalid context。
func TestBrowserContextPropagatesDeadline(t *testing.T) {
	s := &Source{ctx: context.Background()}

	parent, cancelParent := context.WithTimeout(context.Background(), time.Hour)
	defer cancelParent()
	want, ok := parent.Deadline()
	if !ok {
		t.Fatal("父 ctx 应有 deadline")
	}

	bctx, cancel := s.browserContext(parent)
	defer cancel()

	got, ok := bctx.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatalf("deadline 未传播: ok=%v got=%v want=%v", ok, got, want)
	}
}

func TestBrowserContextWithoutDeadline(t *testing.T) {
	s := &Source{ctx: context.Background()}

	bctx, cancel := s.browserContext(context.Background())
	defer cancel()

	if _, ok := bctx.Deadline(); ok {
		t.Fatal("父 ctx 无 deadline 时不应凭空产生 deadline")
	}
}

func TestBrowserContextCancelsWithParent(t *testing.T) {
	s := &Source{ctx: context.Background()}

	parent, cancelParent := context.WithCancel(context.Background())
	bctx, cancel := s.browserContext(parent)
	defer cancel()

	cancelParent()

	select {
	case <-bctx.Done():
	case <-time.After(time.Second):
		t.Fatal("父 ctx 取消后浏览器 ctx 未取消")
	}
}
