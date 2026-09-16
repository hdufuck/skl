package signin

import (
	"context"
	"errors"
	"slices"

	"github.com/hdufuck/skl"
)

// Method 是一条可枚举的签到路径描述符。
//
// ID 沿用 cmd/signinprobe 阶梯里的标识，便于把结果写进日志、数据库或报告时
// 对得上；Title 是直接可展示的中文标题。
type Method interface {
	// ID 是稳定标识，取值见 MethodAnalyzeA0 等常量。
	ID() string
	// Title 是中文标题。
	Title() string
	// SignIn 用给定 client 执行该路径。
	SignIn(ctx context.Context, client *skl.Client, req Request) (*Outcome, error)
}

// 稳定的方法 ID；与探针阶梯的档位逐字对应。
const (
	MethodAnalyzeA0      = "analyze-a0"
	MethodCodeCheckIn    = "code-check-in"
	MethodCaptchaMissing = "captcha-verify-missing"
	MethodCaptchaForged  = "captcha-verify-forged"
	MethodCaptchaGenuine = "captcha-verify-genuine"
)

type method struct {
	id    string
	title string
	run   func(ctx context.Context, c *Client, req Request) (*Outcome, error)
}

func (m method) ID() string    { return m.id }
func (m method) Title() string { return m.title }

func (m method) SignIn(ctx context.Context, client *skl.Client, req Request) (*Outcome, error) {
	return m.run(ctx, New(client), req)
}

// methods 按「不需要人机 → 需要人机」排序。
//
// WithParam 只有方法形式，不单列描述符：它就是「显式给真值的 Genuine」。
var methods = []Method{
	method{
		id:    MethodAnalyzeA0,
		title: "遗留 JSONP check-code-analyze（a=0，无人机凭证，无定位）",
		run:   func(ctx context.Context, c *Client, req Request) (*Outcome, error) { return c.Analyze(ctx, req) },
	},
	method{
		id:    MethodCodeCheckIn,
		title: "遗留 code-check-in（无人机凭证，带定位）",
		run:   func(ctx context.Context, c *Client, req Request) (*Outcome, error) { return c.Legacy(ctx, req) },
	},
	method{
		id:    MethodCaptchaMissing,
		title: "活路径 captcha-verify（缺失 captchaVerifyParam）",
		run:   func(ctx context.Context, c *Client, req Request) (*Outcome, error) { return c.WithoutParam(ctx, req) },
	},
	method{
		id:    MethodCaptchaForged,
		title: "活路径 captcha-verify（伪造 captchaVerifyParam）",
		run:   func(ctx context.Context, c *Client, req Request) (*Outcome, error) { return c.Forged(ctx, req) },
	},
	method{
		id:    MethodCaptchaGenuine,
		title: "活路径 captcha-verify（真值 captchaVerifyParam）",
		run:   func(ctx context.Context, c *Client, req Request) (*Outcome, error) { return c.Genuine(ctx, req) },
	},
}

// Methods 返回全部签到方式，按「不需要人机 → 需要人机」排序。
//
// 返回的是副本，调用方修改它不会影响后续调用。
func Methods() []Method { return slices.Clone(methods) }

// Find 按 ID 取回单个 Method；未知 ID 返回 false。
func Find(id string) (Method, bool) {
	for _, m := range methods {
		if m.ID() == id {
			return m, true
		}
	}
	return nil, false
}

// Do 跑任意一条方式，便于遍历 Methods() 时不必为每条路径写类型分支。
func (c *Client) Do(ctx context.Context, m Method, req Request) (*Outcome, error) {
	if m == nil {
		return nil, errors.New("signin: nil Method")
	}
	if c == nil || c.client == nil {
		return nil, errNoClient
	}
	return m.SignIn(ctx, c.client, req)
}
