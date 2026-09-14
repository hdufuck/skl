package skl

import (
	"net/url"
	"slices"
	"strings"
)

// SessionTokenParam 是 skl 会话 token 在 URL 中使用的参数名。
const SessionTokenParam = "token"

// tokenFromRawURL 从任意 URL 中提取 skl 会话 token。
//
// skl 的会话 token 由 CAS 回调后重定向带回，实测落在 **URL fragment**：
//
//	https://skl.hdu.edu.cn/index.html#?token=11111111-2222-4333-8444-555555555555&t=1700000000001
//
// 前端也兼容 query 形式与 hash 路由形式，因此这里两种都认：
//
//	https://skl.hdu.edu.cn/index.html?token=xxx
//	https://skl.hdu.edu.cn/#/some/path?token=xxx
//
// 找不到时返回空串。
func tokenFromRawURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	for _, qs := range []string{u.RawQuery, fragmentQuery(u.Fragment)} {
		if qs == "" {
			continue
		}
		if v := valuesFromQuery(qs).Get(SessionTokenParam); v != "" {
			return v
		}
	}
	return ""
}

// fragmentQuery 把 URL fragment 归一化成 query string。
//
// fragment 可能是 `?token=x`、`token=x` 或 `/path?token=x`，
// 没有 `?` 时整体当作 query string 处理（`/sign/in` 这种路径自然解析不出 token）。
func fragmentQuery(fragment string) string {
	f := strings.TrimPrefix(fragment, "#")
	if _, after, ok := strings.Cut(f, "?"); ok {
		return after
	}
	return f
}

// valuesFromQuery 解析 query string，失败时退化为手工扫描。
//
// 这里刻意不返回 error：调用方只关心能否拿到 token，
// 而 CAS 回调 URL 里偶尔出现未转义字符导致 url.ParseQuery 报错。
func valuesFromQuery(qs string) url.Values {
	if v, err := url.ParseQuery(qs); err == nil {
		return v
	}

	v := url.Values{}
	for pair := range strings.SplitSeq(qs, "&") {
		k, val, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			continue
		}
		if dec, err := url.QueryUnescape(val); err == nil {
			val = dec
		}
		v.Add(k, val)
	}
	return v
}

// extractSessionToken 从一串按时间顺序记录的 URL 中提取最新的 session token。
//
// 倒序扫描：CAS 登录链末尾的 URL 才是携带 token 的那个，
// 正序遇到历史遗留的 token 会取错。
func extractSessionToken(rawURLs []string) string {
	for _, raw := range slices.Backward(rawURLs) {
		if tk := tokenFromRawURL(raw); tk != "" {
			return tk
		}
	}
	return ""
}
