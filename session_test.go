package skl

import "testing"

func TestTokenFromRawURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "fragment query (实测形态)",
			url:  "https://skl.hdu.edu.cn/index.html#?token=11111111-2222-4333-8444-555555555555&t=1700000000001",
			want: "11111111-2222-4333-8444-555555555555",
		},
		{
			name: "普通 query",
			url:  "https://skl.hdu.edu.cn/index.html?token=abc123",
			want: "abc123",
		},
		{
			name: "hash 路由",
			url:  "https://skl.hdu.edu.cn/#/sign/in?token=abc123",
			want: "abc123",
		},
		{
			name: "fragment 不带问号",
			url:  "https://skl.hdu.edu.cn/index.html#token=abc123",
			want: "abc123",
		},
		{
			name: "token 在 query 而其它参数在 fragment",
			url:  "https://skl.hdu.edu.cn/index.html?token=abc123#?t=1",
			want: "abc123",
		},
		{
			name: "CAS 登录页（无 token）",
			url:  "https://cas.hdu.edu.cn/cas/login?state=HdtrtWrmARrpNrNNa2x&service=https%3A%2F%2Fskl.hdu.edu.cn%2Fapi%2Fcas%2Flogin",
			want: "",
		},
		{
			name: "API 地址（无 token）",
			url:  "https://skl.hdu.edu.cn/api/userinfo?type=&index=index.html",
			want: "",
		},
		{
			name: "路径看起来像 query（无 token）",
			url:  "https://skl.hdu.edu.cn/index.html#/sign/in/detail",
			want: "",
		},
		{
			name: "相对/裸 fragment",
			url:  "#?token=xyz",
			want: "xyz",
		},
		{
			name: "空串",
			url:  "",
			want: "",
		},
		{
			name: "token 为空值",
			url:  "https://skl.hdu.edu.cn/index.html#?token=&t=1",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenFromRawURL(tt.url); got != tt.want {
				t.Fatalf("tokenFromRawURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractSessionTokenPrefersLatest(t *testing.T) {
	t.Parallel()

	chain := []string{
		"https://skl.hdu.edu.cn/api/userinfo?type=&index=index.html",
		"https://cas.hdu.edu.cn/cas/login?state=S&service=...",
		"https://sso.hdu.edu.cn/login?service=...",
		"https://skl.hdu.edu.cn/api/cas/login?state=S&index=index.html&ticket=ST-1-abc",
		// 旧 token（例如同一 jar 内更早的一次登录）不应胜出
		"https://skl.hdu.edu.cn/index.html#?token=OLD&t=1",
		"https://skl.hdu.edu.cn/index.html#?token=NEW&t=2",
	}
	if got := extractSessionToken(chain); got != "NEW" {
		t.Fatalf("extractSessionToken = %q, want %q", got, "NEW")
	}
}

func TestExtractSessionTokenEmpty(t *testing.T) {
	t.Parallel()

	if got := extractSessionToken(nil); got != "" {
		t.Fatalf("extractSessionToken(nil) = %q, want empty", got)
	}
	if got := extractSessionToken([]string{"https://cas.hdu.edu.cn/cas/login"}); got != "" {
		t.Fatalf("extractSessionToken = %q, want empty", got)
	}
}

func TestFragmentQuery(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"?token=x&t=1":      "token=x&t=1",
		"#?token=x":         "token=x",
		"token=x":           "token=x",
		"/sign/in?token=x":  "token=x",
		"/sign/in/detail":   "/sign/in/detail",
		"":                  "",
		"##?token=x":        "token=x",
		"/a?b?c?token=deep": "b?c?token=deep",
	}
	for in, want := range tests {
		if got := fragmentQuery(in); got != want {
			t.Fatalf("fragmentQuery(%q) = %q, want %q", in, got, want)
		}
	}
}
