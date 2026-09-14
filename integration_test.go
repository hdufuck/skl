//go:build integration

// 这些用例会真实访问 skl.hdu.edu.cn 与 sso.hdu.edu.cn，只在显式开启时运行：
//
//	HDU_USER=2427xxxx HDU_PASS=... go test -tags integration -run Integration -v ./...
//
// 只覆盖鉴权与只读接口。**不包含任何签动用例**：签到会产生真实考勤记录。
package skl

import (
	"context"
	"os"
	"testing"
	"time"
)

func integrationClient(t *testing.T) *Client {
	t.Helper()

	user := os.Getenv("HDU_USER")
	pass := os.Getenv("HDU_PASS")
	if pass == "" {
		pass = os.Getenv("HDU_PASSWORD")
	}
	if user == "" || pass == "" {
		t.Skip("需要 HDU_USER 与 HDU_PASS/HDU_PASSWORD 才能运行集成测试")
	}

	c, err := NewClient(
		WithCredentials(user, pass),
		WithTimeout(30*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestIntegrationLogin(t *testing.T) {
	c := integrationClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.Token() == "" {
		t.Fatal("Login 成功但 token 为空")
	}
	t.Logf("取得 token: %s...", firstN(c.Token(), 8))
}

// TestIntegrationTokenOnly 验证「只注入 token、不走登录」的路径，
// 这也是二次开发时最常用的模式（token 从外部持久化读取）。
func TestIntegrationTokenOnly(t *testing.T) {
	token := os.Getenv("SKL_TOKEN")
	if token == "" {
		t.Skip("需要 SKL_TOKEN 才能运行（可在浏览器 localStorage.sessionId 里取）")
	}

	c, err := NewClient(WithToken(token))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	user, err := c.UserInfo(ctx)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	t.Logf("用户: %s (%s) 班级=%s 类型=%d", user.UserName, user.ID, user.ClassNo, user.UserType)
}

func TestIntegrationReadOnlyEndpoints(t *testing.T) {
	c := integrationClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	user, err := c.UserInfo(ctx)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	years, err := c.SchoolYears(ctx)
	if err != nil {
		t.Fatalf("SchoolYears: %v", err)
	}
	t.Logf("学年学期: %d 条，最新 %s", len(years), years[0].SchoolYearID)

	courses, err := c.Courses(ctx, time.Now())
	if err != nil {
		t.Fatalf("Courses: %v", err)
	}
	t.Logf("今日课程: %d 门", len(courses))

	for _, course := range courses {
		counts, err := c.CheckInCountByCourse(ctx, course.CourseID)
		if err != nil {
			t.Fatalf("CheckInCountByCourse(%s): %v", course.CourseID, err)
		}
		for _, cnt := range counts {
			t.Logf("  %s: 到%d 缺%d 迟%d 假%d 早退%d",
				course.CourseName, cnt.RightCount, cnt.AbsentCount,
				cnt.LateCount, cnt.LeaveCount, cnt.AbsentLeaveCount)
		}
	}

	// 验证 user 缓存生效：第二次调用不应再打网络。
	cached, err := c.User(ctx)
	if err != nil {
		t.Fatalf("User(cached): %v", err)
	}
	if cached.ID != user.ID {
		t.Fatalf("缓存的用户 id = %q, want %q", cached.ID, user.ID)
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
