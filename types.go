package skl

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UserType 是 skl 用户类型。
type UserType int

const (
	// UserTypeStudent 学生。前端判据：`userType !== 3`。
	UserTypeStudent UserType = 1
	// UserTypeTeacher 教师。前端判据：`userType === 3`。
	UserTypeTeacher UserType = 3
)

// UserInfo 是 `GET /api/userinfo` 的响应，同时也是会话有效性的探针。
//
// 字段形态取自 `har#1`/`har#2` 的实测抓包，全部字段保留原始 JSON 名。
type UserInfo struct {
	AcademicCredentials json.RawMessage `json:"academicCredentials"`
	Birthday            *time.Time      `json:"birthday"`
	ClassNo             string          `json:"classNo"`
	Degree              *string         `json:"degree"`
	ForcedUpdatePhone   json.RawMessage `json:"forcedUpdatePhone"`
	Grade               string          `json:"grade"`
	// ID 是学号/工号，签到接口的 userid 参数取自此字段。
	ID         string          `json:"id"`
	Major      string          `json:"major"`
	Phone      string          `json:"phone"`
	RoleIDList []any           `json:"roleIdList"`
	RoleList   []any           `json:"roleList"`
	SchoolDay  json.RawMessage `json:"schoolDay"`
	// Sex 是字符串 "1"/"2"（1=男，2=女）。
	Sex         string   `json:"sex"`
	TeacherName string   `json:"teacherName"`
	UnitCode    string   `json:"unitCode"`
	UnitID      string   `json:"unitId"`
	UnitName    string   `json:"unitName"`
	UserName    string   `json:"userName"`
	UserType    UserType `json:"userType"`
}

// IsTeacher 报告该用户是否为教师。
func (u *UserInfo) IsTeacher() bool { return u != nil && u.UserType == UserTypeTeacher }

// JsapiTicket 是 `GET /api/dingtalk/jsapi_ticket` 的响应。
//
// 它只在钉钉容器里才有意义（用于 `dd.config` 和
// `biz.util.scan` / `device.geolocation.get` 等 JSAPI 鉴权）。
// 在钉钉之外调用该接口不会报错，也无法用于任何自动化场景。
type JsapiTicket struct {
	TimeStamp int64  `json:"timeStamp"`
	AgentID   int64  `json:"agentId"`
	CorpID    string `json:"corpId"`
	Signature string `json:"signature"`
	NonceStr  string `json:"nonceStr"`
}

// SchoolYear 是 `GET /api/school-year/all` 数组中的一个学年学期。
type SchoolYear struct {
	FirstData    *time.Time `json:"firstData"`
	IntegerYear  int        `json:"integerYear"`
	LastData     *time.Time `json:"lastData"`
	SchoolYearID string     `json:"schoolYearId"`
	Semester     string     `json:"semester"`
	Year         string     `json:"year"`
}

// Course 是 `GET /api/course` 中的一个课程条目。
type Course struct {
	ClassRoom       string  `json:"classRoom"`
	CourseClass     string  `json:"courseClass"`
	CourseCode      string  `json:"courseCode"`
	CourseID        string  `json:"courseId"`
	CourseName      string  `json:"courseName"`
	CourseNo        string  `json:"courseNo"`
	CourseSchema    string  `json:"courseSchema"`
	CourseSchemaID  string  `json:"courseSchemaId"`
	CourseType      string  `json:"courseType"`
	EndSection      int     `json:"endSection"`
	EndWeek         int     `json:"endWeek"`
	ListenStatus    any     `json:"listenStatus"`
	ListenTime      float64 `json:"listenTime"`
	Mark            float64 `json:"mark"`
	Period          any     `json:"period"`
	SchoolYear      string  `json:"schoolYear"`
	Semester        string  `json:"semester"`
	StartSection    int     `json:"startSection"`
	StartWeek       int     `json:"startWeek"`
	StudentCount    int     `json:"studentCount"`
	StudentType     string  `json:"studentType"`
	TeacherMajor    string  `json:"teacherMajor"`
	TeacherName     string  `json:"teacherName"`
	TeacherNo       string  `json:"teacherNo"`
	TeacherUnitName string  `json:"teacherUnitName"`
	TeacherUnitNo   string  `json:"teacherUnitNo"`
	TotalTime       float64 `json:"totalTime"`
	UnitCode        string  `json:"unitCode"`
	UnitName        string  `json:"unitName"`
	WeekDay         int     `json:"weekDay"`
}

// SchoolUnit 是 `GET /api/common/all-school-unit` 数组中的一个单位。
type SchoolUnit struct {
	Director      string  `json:"director"`
	DirectorName  *string `json:"directorName"`
	Principal     string  `json:"principal"`
	PrincipalName *string `json:"principalName"`
	Type          string  `json:"type"`
	UnitCode      string  `json:"unitCode"`
	UnitName      string  `json:"unitName"`
}

// CheckInCount 是 `GET /api/checkIn/stu-course-check-in-count` 返回数组中的元素，
// 表示某门课一学期的考勤统计。
//
// 前七个字段由 skl 前端考勤明细页直接消费，可视为已实测。
//
// ⚠️ 其余字段是**按命名惯例补齐的猜测**，`har#3` 的抓包并不支持它们：
// 抓到的元素（`/checkIn/stu-course-check-in-count`）实际带的是**身份字段**
// （`id`、`userId`、`classNo`、`name`、`major`、`unitCode`、`unitName`、
// `grade`、`studyLevel`），而不是这里的 `courseCode` 系；未实测到
// `courseId`/`courseName`/`teacherName`。另外实测值 `absentTimeCount` 是 `0.0`
// （浮点写法），而 Go 的 `encoding/json` 对 `0.0` → `int` 是**报错**（不是取整），
// 所以这个结构体自己实现 `UnmarshalJSON` 做宽松取整（见下）。
// 要动这几个字段之前先补一次实测。
type CheckInCount struct {
	AbsentCount      int     `json:"absentCount"`
	AbsentLeaveCount int     `json:"absentLeaveCount"`
	AbsentTimeCount  int     `json:"absentTimeCount"`
	CourseTotalTime  float64 `json:"courseTotalTime"`
	LateCount        int     `json:"lateCount"`
	LeaveCount       int     `json:"leaveCount"`
	RightCount       int     `json:"rightCount"`

	CourseCode    string `json:"courseCode"`
	CourseGroupNo string `json:"courseGroupNo"`
	CourseID      string `json:"courseId"`
	CourseName    string `json:"courseName"`
	CourseNo      string `json:"courseNo"`
	CourseType    string `json:"courseType"`
	TeacherName   string `json:"teacherName"`
}

// UnmarshalJSON 容忍服务端把整数值写成浮点。
//
// 实测（`har#3` 采集的 `/checkIn/stu-course-check-in-count`）里有 `absentTimeCount: 0.0`，
// 而 Go 的 `encoding/json` 对 `0.0` → `int` 是**报错**，会让整个数组解码失败 ——
// 真实响应根本读不回来。这里先把计数字段收成 `json.Number` 再取整，
// **字段类型保持 `int`**，调用方不受影响。
// 非整数值（如 `1.5`）会被截断：服务端这些字段是次数，不应当有小数。
func (c *CheckInCount) UnmarshalJSON(data []byte) error {
	var raw struct {
		AbsentCount      json.Number `json:"absentCount"`
		AbsentLeaveCount json.Number `json:"absentLeaveCount"`
		AbsentTimeCount  json.Number `json:"absentTimeCount"`
		CourseTotalTime  float64     `json:"courseTotalTime"`
		LateCount        json.Number `json:"lateCount"`
		LeaveCount       json.Number `json:"leaveCount"`
		RightCount       json.Number `json:"rightCount"`

		CourseCode    string `json:"courseCode"`
		CourseGroupNo string `json:"courseGroupNo"`
		CourseID      string `json:"courseId"`
		CourseName    string `json:"courseName"`
		CourseNo      string `json:"courseNo"`
		CourseType    string `json:"courseType"`
		TeacherName   string `json:"teacherName"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("skl: 解析考勤统计失败: %w", err)
	}

	counts := []struct {
		src  json.Number
		dest *int
	}{
		{raw.AbsentCount, &c.AbsentCount},
		{raw.AbsentLeaveCount, &c.AbsentLeaveCount},
		{raw.AbsentTimeCount, &c.AbsentTimeCount},
		{raw.LateCount, &c.LateCount},
		{raw.LeaveCount, &c.LeaveCount},
		{raw.RightCount, &c.RightCount},
	}
	for _, n := range counts {
		v, err := countFromNumber(n.src)
		if err != nil {
			return err
		}
		*n.dest = v
	}
	c.CourseTotalTime = raw.CourseTotalTime
	c.CourseCode = raw.CourseCode
	c.CourseGroupNo = raw.CourseGroupNo
	c.CourseID = raw.CourseID
	c.CourseName = raw.CourseName
	c.CourseNo = raw.CourseNo
	c.CourseType = raw.CourseType
	c.TeacherName = raw.TeacherName
	return nil
}

// countFromNumber 把计数字段取整；字段缺失/为空/为 null 时算 0。
func countFromNumber(n json.Number) (int, error) {
	s := strings.TrimSpace(n.String())
	if s == "" || s == "null" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("skl: 考勤统计字段期望数字，收到 %q", s)
	}
	return int(f), nil
}

// Total 返回已判定次数的总和。
func (c CheckInCount) Total() int {
	return c.AbsentCount + c.AbsentLeaveCount + c.LateCount + c.LeaveCount + c.RightCount
}

// CheckInOverview 是 `GET /api/checkIn/stu-check-count` 的响应。
//
// 未选中课程时服务端返回 `{"courseName":null,"list":[]}`；
// list 的元素形态未实测，因此保持 RawMessage。
type CheckInOverview struct {
	CourseName *string           `json:"courseName"`
	List       []json.RawMessage `json:"list"`
}

// MarkItems 是 `GET /api/mark/stu-mark-items` 的响应，描述一门课的过程考核配置。
type MarkItems struct {
	CheckInMark   *CheckInMark `json:"checkInMark"`
	CourseCode    string       `json:"courseCode"`
	CourseGroupNo *string      `json:"courseGroupNo"`
	CourseName    string       `json:"courseName"`
	CourseNo      string       `json:"courseNo"`
	CourseType    string       `json:"courseType"`
	TeacherName   string       `json:"teacherName"`
	List          []MarkItem   `json:"list"`
}

// CheckInMark 是考勤扣分规则（每次扣多少分）。
type CheckInMark struct {
	Absent      float64 `json:"absent"`
	Late        float64 `json:"late"`
	AbsentLeave float64 `json:"absentLeave"`
}

// MarkItem 是一个考核大项。前端对 `type=="0"`（考勤）做了特殊处理。
type MarkItem struct {
	MarkItemID   string           `json:"markItemId"`
	MarkItemName string           `json:"markItemName"`
	MarkMode     int              `json:"markMode"`
	Percent      float64          `json:"percent"`
	Type         string           `json:"type"`
	MarkItems    []MarkItemDetail `json:"markItems"`
}

// MarkItemDetail 是考核大项下的子项。
type MarkItemDetail struct {
	MarkItemID      string  `json:"markItemId"`
	MarkItemName    string  `json:"markItemName"`
	MarkItemPercent float64 `json:"markItemPercent"`
	MarkDefault     float64 `json:"markDefault"`
}
