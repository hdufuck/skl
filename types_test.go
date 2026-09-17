package skl

import (
	"encoding/json"
	"testing"
)

// checkInCountFixture 是 `har#3` 采集到的真实响应形状（学号已按
// docs/signin-probe.md §4.4 的规则打码）：
//
//   - 计数字段里 `absentTimeCount` 是 **`0.0`**（浮点写法），而 Go 的
//     `encoding/json` 对 `0.0` → `int` 是**报错**，会让整个数组解码失败；
//   - 元素带的是**身份字段**（`id`/`userId`/`classNo`/`major`/…），
//     而不是 `CheckInCount` 里那套 `courseCode` 系（那部分仍是猜测）。
const checkInCountFixture = `[{"absentCount":0,"absentLeaveCount":0,"absentTimeCount":0.0,` +
	`"classNo":null,"courseTotalTime":34,"grade":null,"id":null,"lateCount":0,` +
	`"leaveCount":0,"major":null,"name":null,"rightCount":1,"studyLevel":null,` +
	`"unitCode":null,"unitName":null,"userId":"24000000"}]`

// TestCheckInCountToleratesFloatCounts 锁住那个「真实响应读不回来」的缺陷：
// 整数值被写成浮点时也必须能解码，且字段类型仍是 int。
func TestCheckInCountToleratesFloatCounts(t *testing.T) {
	t.Parallel()

	var counts []CheckInCount
	if err := json.Unmarshal([]byte(checkInCountFixture), &counts); err != nil {
		t.Fatalf("真实响应解码失败（0.0 不能被 int 接受，会让整个数组失败）: %v", err)
	}
	if len(counts) != 1 {
		t.Fatalf("解出 %d 条，want 1", len(counts))
	}

	got := counts[0]
	if got.RightCount != 1 {
		t.Fatalf("rightCount = %d, want 1（判到课就用它）", got.RightCount)
	}
	if got.AbsentTimeCount != 0 {
		t.Fatalf("absentTimeCount = %d, want 0", got.AbsentTimeCount)
	}
	if got.CourseTotalTime != 34 {
		t.Fatalf("courseTotalTime = %v, want 34", got.CourseTotalTime)
	}
	if got.Total() != 1 {
		t.Fatalf("Total() = %d, want 1", got.Total())
	}
}

func TestCheckInCountMissingFieldsAreZero(t *testing.T) {
	t.Parallel()

	var counts []CheckInCount
	if err := json.Unmarshal([]byte(`[{"rightCount":2}]`), &counts); err != nil {
		t.Fatalf("缺字段的响应应当按 0 处理: %v", err)
	}
	if len(counts) != 1 || counts[0].Total() != 2 {
		t.Fatalf("Total() = %+v, want rightCount=2 且其余为 0", counts)
	}
}

func TestCheckInCountRejectsNonNumbers(t *testing.T) {
	t.Parallel()

	var counts []CheckInCount
	err := json.Unmarshal([]byte(`[{"rightCount":"很多"}]`), &counts)
	if err == nil {
		t.Fatal("非数字的计数字段应当报错，而不是静默算 0")
	}
}
