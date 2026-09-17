// Command teacheraccess 对**一个**教师端只读接口发出**一次**访问请求，
// 用来观测角色权限边界。它是一次性人工工具，不是测试、不落盘、不重试。
//
// # 为什么挑这个接口
//
// 目标是 `GET /api/checkIn/course-check-in-count?courseId=<id>`（docs/api.md §4.1），
// 因为它在教师端 GET 里风险最小：
//
//   - **只读、幂等**：返回某门课的考勤聚合计数，没有写副作用。
//   - **不吐他人隐私**：返回的是计数，不是姓名/学号/考勤明细。
//   - **参数可得**：courseId 来自已实测的只读接口 `/api/course`，不必猜未知参数。
//   - **归因清晰**：学生 token 打它会被角色门拦下 —— 实测是
//     `400 {"code":0,"msg":"非任课老师无权查看"}`（不是 403），
//     正好补上 docs/api.md §5「各接口角色权限边界未逐个验证」的一个实测点。
//
// # 明确不用的教师端 GET（有副作用或读他人数据）
//
//	GET /checkIn/delete-code                       提前结束签到窗口
//	GET /course/update                             触发课表同步
//	GET /assist-course/delete                      删除
//	GET /listener-record-export/...                生成导出文件
//	GET /check-in-student-detail/school|encrypted-school   读其他学生考勤明细
//	GET /check-in-student-detail/encrypted-id      任意学号的查询 oracle
//	GET /dormitory/*、/mark/group/record-*、/ai-call/call-detail/{id}
//
// # 行为纪律
//
//   - 鉴权步骤与 cmd/signinprobe 相同：优先用已有 token，否则账号密码走 CAS/SSO。
//   - 对目标接口**只发一次**请求（Request.NoRelogin），不重试、不自动重登重放。
//   - `200` + 空 body 是 skl-ticket 重放/限流，本次即无结论，不要立刻重跑。
//   - 终端输出**未打码**（含真实姓名/学号/课程数据），只给你自己看，不要整段外传。
//
// # 用法
//
//	export SKL_TOKEN=<localStorage.sessionId>       # 或 HDU_USER / HDU_PASS
//	go run ./cmd/teacheraccess                      # 取今日第一门课的 courseId
//	go run ./cmd/teacheraccess -course-id <courseId>  # 指定 courseId（少一次只读查询）
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hdufuck/skl"
)

// teacherPath 是本工具唯一会打的接口。要换接口请先按文件头的风险清单重挑。
const teacherPath = "/api/checkIn/course-check-in-count"

const previewRunes = 512

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "[access] 失败:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		user     = flag.String("user", envOr("HDU_USER", ""), "CAS/SSO 账号（默认 $HDU_USER）")
		pass     = flag.String("pass", envOr("HDU_PASS", envOr("HDU_PASSWORD", "")), "CAS/SSO 密码（默认 $HDU_PASS）")
		token    = flag.String("token", os.Getenv("SKL_TOKEN"), "已有的 session token（可跳过登录）")
		base     = flag.String("base", "", "覆盖站点根地址（默认 https://skl.hdu.edu.cn）")
		courseID = flag.String("course-id", "", "指定 courseId；留空则取今日第一门课")
		timeout  = flag.Duration("timeout", 30*time.Second, "单次请求超时")
	)
	flag.Parse()

	fmt.Fprintln(os.Stderr, "[access] ⚠ 本行以下的终端输出**未打码**（含真实姓名/学号/课程数据）：")
	fmt.Fprintln(os.Stderr, "[access]    它只给你自己看，不要整段复制到 issue / 文档 / 群里。")
	fmt.Fprintln(os.Stderr, "[access]    本工具对目标接口只发一次请求，不重试、不落盘。")

	// ---------- 鉴权（与 cmd/signinprobe 相同）----------
	opts := []skl.Option{skl.WithTimeout(*timeout)}
	if *base != "" {
		opts = append(opts, skl.WithBaseURL(*base))
	}
	if *token != "" {
		opts = append(opts, skl.WithToken(*token))
	}
	if *user != "" && *pass != "" {
		opts = append(opts, skl.WithCredentials(*user, *pass))
	}

	client, err := skl.NewClient(opts...)
	if err != nil {
		return err
	}
	if *token == "" && !client.HasCredentials() {
		return errors.New("既没有 SKL_TOKEN，也没有 HDU_USER/HDU_PASS")
	}

	ctx := context.Background()
	loginCtx, cancelLogin := context.WithTimeout(ctx, 3*time.Minute)
	defer cancelLogin()

	if client.HasCredentials() {
		logf("登录中（CAS/SSO）…")
		if err := client.Login(loginCtx); err != nil {
			return fmt.Errorf("登录失败: %w", err)
		}
	}

	me, err := client.UserInfo(loginCtx)
	if err != nil {
		return fmt.Errorf("读取用户信息失败（token 可能已失效，且没有可用的账号密码重新登录）: %w", err)
	}
	role := "学生"
	if me.IsTeacher() {
		role = "教师"
	}
	logf("当前身份：%s（%s）userType=%d（%s）", me.UserName, me.ID, me.UserType, role)

	// ---------- 目标 courseId ----------
	id := strings.TrimSpace(*courseID)
	if id == "" {
		courses, err := client.Courses(loginCtx, time.Now())
		if err != nil {
			return fmt.Errorf("读取今日课程失败（用 -course-id 直接指定可跳过这一步）: %w", err)
		}
		if len(courses) == 0 {
			return errors.New("今日没有课程，拿不到 courseId；请用 -course-id 指定")
		}
		id = courses[0].CourseID
		logf("使用今日第一门课的 courseId=%s", id)
	}

	// ---------- 唯一的一次目标请求 ----------
	reqCtx, cancelReq := context.WithTimeout(ctx, *timeout)
	defer cancelReq()

	logf("目标：GET %s?courseId=%s（只发这一次）", teacherPath, id)
	resp, err := client.Do(reqCtx, &skl.Request{
		Method:    http.MethodGet,
		Path:      teacherPath,
		Query:     url.Values{"courseId": {id}},
		NoRelogin: true,
	})

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}

	switch {
	case err == nil:
		fmt.Fprintf(os.Stderr, "[access] HTTP %d %s\n", status, preview(resp.Body))
		if me.IsTeacher() {
			fmt.Fprintln(os.Stderr, "[access] 结论：访问成功（200）。当前是教师身份，属正常。")
		} else {
			fmt.Fprintln(os.Stderr, "[access] 结论：学生身份拿到了 200 —— 该接口未按角色拦截，记录并走负责任披露流程。")
		}
		return nil

	case errors.Is(err, skl.ErrEmptyBody):
		fmt.Fprintf(os.Stderr, "[access] HTTP %d + 空 body：skl-ticket 重放或被 WAF/限流拦截，本次无结论。\n", status)
		return errors.New("无结论（200 + 空 body）；不要立刻重跑，先等一会儿再换新 token 试")

	default:
		var apiErr *skl.APIError
		if !errors.As(err, &apiErr) {
			return fmt.Errorf("请求失败（没拿到可判读的响应）: %w", err)
		}
		if apiErr.NeedLogin() {
			return fmt.Errorf("会话失效（响应带 url），请重新取 SKL_TOKEN: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[access] HTTP %d code=%d msg=%q\n", apiErr.StatusCode, apiErr.Code, apiErr.Msg)
		switch {
		case apiErr.StatusCode == http.StatusForbidden || permissionMsg(apiErr.Msg):
			if me.IsTeacher() {
				fmt.Fprintln(os.Stderr, "[access] 结论：权限边界成立 —— 当前是教师身份仍被拒，说明还缺别的条件（例如不是该课任课老师）。")
			} else {
				fmt.Fprintln(os.Stderr, "[access] 结论：权限边界成立，且符合预期 —— 学生身份被角色门拦下（服务端可能用 400 + 业务 msg，而不仅是 403）。")
			}
		case apiErr.StatusCode == http.StatusBadRequest:
			fmt.Fprintln(os.Stderr, "[access] 结论：参数形状不对（400，文案未指向权限），本次不作为权限证据。")
		default:
			fmt.Fprintf(os.Stderr, "[access] 结论：未归因（HTTP %d）。\n", apiErr.StatusCode)
		}
		return nil
	}
}

// preview 把响应体压成一行，最长 previewRunes 个字符。
func preview(body []byte) string {
	s := strings.ReplaceAll(strings.TrimSpace(string(body)), "\n", " ")
	r := []rune(s)
	if len(r) > previewRunes {
		return string(r[:previewRunes]) + "…"
	}
	return s
}

// permissionMsg 判断业务错误文案是否属于「权限/角色」拒绝。
//
// 实测：`GET /api/checkIn/course-check-in-count` 的角色门走的是
// `400 {"code":0,"msg":"非任课老师无权查看"}`，而不是 403，
// 所以判据不能只看状态码。
func permissionMsg(msg string) bool {
	for _, kw := range []string{"无权", "权限", "任课老师", "禁止", "不允许"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[access] "+format+"\n", args...)
}
