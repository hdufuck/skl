package skl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DateFormat 是 skl 各类日期参数使用的格式。
const DateFormat = "2006-01-02"

// 常用 API 路径。
const (
	PathUserInfo      = "/api/userinfo"
	PathJsapiTicket   = "/api/dingtalk/jsapi_ticket"
	PathSchoolYears   = "/api/school-year/all"
	PathCourses       = "/api/course"
	PathAllSchoolUnit = "/api/common/all-school-unit"
	PathMarkItems     = "/api/mark/stu-mark-items"

	PathCheckInCountByCourse = "/api/checkIn/stu-course-check-in-count"
	PathCheckInOverview      = "/api/checkIn/stu-check-count"
	PathMyCheckInDetail      = "/api/check-in-student-detail/my"

	PathSignInCaptchaVerify = "/api/ali-nvc/captcha-verify"
	PathSignInLegacy        = "/api/checkIn/code-check-in"
	PathSignInAnalyze       = "/api/ali-nvc/check-code-analyze"
	PathLegacyValidCode     = "/api/checkIn/valid-code"
	PathCaptchaImage        = "/api/checkIn/create-code-img"
)

// decodeJSON 把响应体解析到 T。
//
// 业务错误已经由 Do/apiErrorFrom 处理，这里只负责反序列化。
func decodeJSON[T any](resp *Response) (T, error) {
	var out T
	if err := resp.JSON(&out); err != nil {
		return out, err
	}
	return out, nil
}

// UserInfo 获取当前登录用户信息。
//
// 每次调用都会请求服务端；需要缓存时用 User。
func (c *Client) UserInfo(ctx context.Context) (*UserInfo, error) {
	user, err := c.userInfo(ctx, false)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.user = user
	c.mu.Unlock()
	return user, nil
}

// userInfo 是 UserInfo 的内部实现，noRelogin 用于登录过程中避免递归重登。
func (c *Client) userInfo(ctx context.Context, noRelogin bool) (*UserInfo, error) {
	resp, err := c.Do(ctx, &Request{
		Method:    http.MethodGet,
		Path:      PathUserInfo,
		Query:     url.Values{"type": {""}, "index": {c.index}},
		NoRelogin: noRelogin,
	})
	if err != nil {
		return nil, err
	}
	user, err := decodeJSON[UserInfo](resp)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// User 返回当前用户信息，优先使用缓存。
//
// 缓存在 SetToken 与 Login 时失效。
func (c *Client) User(ctx context.Context) (*UserInfo, error) {
	c.mu.RLock()
	cached := c.user
	c.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	return c.UserInfo(ctx)
}

// JsapiTicket 获取钉钉 JSAPI 签名票据。
//
// 该接口只在钉钉容器内可用；非钉钉环境下也能调用成功，但返回的签名
// 无法驱动任何 JSAPI（例如扫一扫、精确定位）。
//
// 注意：抓包显示该接口在钉钉容器里会返回 `200 + 空 body`
// （HAR#2 中该请求响应体为 0 字节，同一账号在 HAR#1 里又返回了完整 JSON）。
// 因此这里显式允许空 body，再把空票据翻译成一个带上下文的 ErrEmptyBody，
// 而不是当成结构解析失败。
func (c *Client) JsapiTicket(ctx context.Context, pageURL string) (*JsapiTicket, error) {
	if pageURL == "" {
		pageURL = c.baseURL + "/" + c.index
	}
	resp, err := c.Do(ctx, &Request{
		Method:         http.MethodGet,
		Path:           PathJsapiTicket,
		Query:          url.Values{"url": {pageURL}},
		AllowEmptyBody: true,
	})
	if err != nil {
		return nil, err
	}
	if resp.IsEmpty() {
		return nil, fmt.Errorf("%w: %s 返回空 body", ErrEmptyBody, PathJsapiTicket)
	}
	ticket, err := decodeJSON[JsapiTicket](resp)
	if err != nil {
		return nil, err
	}
	return &ticket, nil
}

// SchoolYears 获取全部学年学期。
func (c *Client) SchoolYears(ctx context.Context) ([]SchoolYear, error) {
	resp, err := c.Get(ctx, PathSchoolYears, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]SchoolYear](resp)
}

// Courses 获取指定日期（通常为当天）的课程表。
//
// startTime 以 DateFormat 传给服务端，实测传当天日期即返回当天课程。
func (c *Client) Courses(ctx context.Context, startTime time.Time) ([]Course, error) {
	resp, err := c.Get(ctx, PathCourses, url.Values{
		"startTime": {startTime.Format(DateFormat)},
	})
	if err != nil {
		return nil, err
	}
	body, err := decodeJSON[struct {
		List []Course `json:"list"`
	}](resp)
	if err != nil {
		return nil, err
	}
	return body.List, nil
}

// AllSchoolUnits 获取全校单位列表。
func (c *Client) AllSchoolUnits(ctx context.Context) ([]SchoolUnit, error) {
	resp, err := c.Get(ctx, PathAllSchoolUnit, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]SchoolUnit](resp)
}

// CheckInCountByCourse 获取某门课的考勤统计（返回数组，通常只取第一个元素）。
func (c *Client) CheckInCountByCourse(ctx context.Context, courseID string) ([]CheckInCount, error) {
	resp, err := c.Get(ctx, PathCheckInCountByCourse, url.Values{"courseId": {courseID}})
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]CheckInCount](resp)
}

// CheckInOverview 获取未查看的签到记录。
func (c *Client) CheckInOverview(ctx context.Context) (*CheckInOverview, error) {
	resp, err := c.Get(ctx, PathCheckInOverview, nil)
	if err != nil {
		return nil, err
	}
	overview, err := decodeJSON[CheckInOverview](resp)
	if err != nil {
		return nil, err
	}
	return &overview, nil
}

// MyCheckInDetails 获取 [start, end] 区间内本人的签到明细。
//
// 服务端返回裸 JSON 数组，元素形态未实测，因此以 RawMessage 透出。
func (c *Client) MyCheckInDetails(ctx context.Context, start, end time.Time) ([]json.RawMessage, error) {
	resp, err := c.Get(ctx, PathMyCheckInDetail, url.Values{
		"startDate": {start.Format(DateFormat)},
		"endDate":   {end.Format(DateFormat)},
	})
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]json.RawMessage](resp)
}

// MarkItems 获取某门课的过程考核项配置。
func (c *Client) MarkItems(ctx context.Context, courseID string) (*MarkItems, error) {
	resp, err := c.Get(ctx, PathMarkItems, url.Values{"courseId": {courseID}})
	if err != nil {
		return nil, err
	}
	items, err := decodeJSON[MarkItems](resp)
	if err != nil {
		return nil, err
	}
	return &items, nil
}

// Raw 是通用逃生口：按原样返回响应，便于调用本包尚未封装类型化的接口。
//
// 前端用到的完整接口清单见 README；常见的有
// `/api/checkIn/update`、`/api/mark/submit`、`/api/leave/add`、
// `/api/talk-booking/my` 等。
func (c *Client) Raw(ctx context.Context, method, path string, query url.Values, body []byte) (*Response, error) {
	return c.Do(ctx, &Request{Method: method, Path: path, Query: query, Body: body})
}

// RawJSON 与 Raw 类似，但额外把响应体解析到 v。
func (c *Client) RawJSON(ctx context.Context, method, path string, query url.Values, body []byte, v any) error {
	resp, err := c.Raw(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	if err := resp.JSON(v); err != nil {
		return fmt.Errorf("skl: 解析 %s %s 响应: %w", method, path, err)
	}
	return nil
}
