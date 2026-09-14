# skl API 文档

杭电学勤系统（`skl.hdu.edu.cn`）的接口参考，按**学生端**与**教师端**分组。

## 证据等级

本文档把「已知」和「猜到」分开标注，因为两者混在一起最容易误导二次开发：

| 标记 | 含义 |
| --- | --- |
| ✅ | **已实测**：真机请求过，或有抓包证据 |
| 📖 | **源码**：端点与参数名取自前端构建产物（`index-BjaCUYRh.js` 等），未逐个真机验证 |
| ⚠️ | **未证实**：参数形状或语义不确定，已在备注里说明 |

角色归属（学生端 / 教师端）来自「哪个页面在调它」加接口语义推断。
服务端应当有角色校验（前端对 403 的处理文案是「没有权限」），
**但本包没有逐个验证权限边界**。

抓包只覆盖了学生端的少量接口（见 `README.md` 的状态一览），
因此本文档绝大部分条目是 📖。所有端点清单来自前端 API 模块，
不是从抓包里猜的。

---

## 1. 通用约定

### 1.1 Base URL 与鉴权

```text
https://skl.hdu.edu.cn/api
```

两个请求头，缺一不可（详见 `doc.go` 的鉴权模型）：

| 头 | 值 | 说明 |
| --- | --- | --- |
| `X-Auth-Token` | `<uuid>` | 会话凭据，即 `localStorage.sessionId` |
| `skl-ticket` | `<nanoid(21)>` | **每请求一次性**防重放 nonce |

没有 cookie。`skl-ticket` 重放会得到 `HTTP 200 + 空 body`。

### 1.2 响应形态

| 形态 | 含义 |
| --- | --- |
| `200` + JSON | 正常 |
| `200` + **空 body** | `skl-ticket` 重放，或（未证实）被限流。**不能用状态码判断成败** |
| `400` + `{"code":0,"msg":"..."}` | 参数缺失/非法（如 `Request method 'POST' is not supported`） |
| `401` + `{"code":0,"msg":"..."}` | **业务校验失败**（如「签到码不存在，不要玩我」） |
| `401` + `{"url":"..."}` | **会话失效**，需跳转该 URL 走 CAS 登录 |
| `403` | 无权限（前端文案「没有权限」） |

`401` 不是「空 body」：业务失败会带 JSON。两个键（`url` / `msg`）就是区分
会话失效与业务失败的唯一判据。

### 1.3 参数约定

- 日期：`2006-01-02`（如 `startTime=2026-09-14`、`startDate`/`endDate`）
- 时间戳：毫秒（`recordDate`、`expiresIn`、`t`）
- 经纬度：十进制浮点；前端用钉钉 `coordinate: 0`（**标准/WGS-84**）
- 大批接口用 `params`（query）而非 body，即使语义上是写操作
- 数组与复杂对象常见于 POST body

### 1.4 角色

`GET /userinfo` 的 `userType`：**`1` = 学生，`3` = 教师**（前端判据 `userType === 3`）。

---

## 2. 鉴权

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/userinfo` | `type`（空串）、`index`（如 `index.html`） | ✅ | 会话探针 + 用户信息。无 token 时返回 `401 {"url": cas 登录地址}` |
| GET | `/cas/login` | `state`、`index`、`ticket`（必填） | ✅ | CAS 回调。ticket 无效时 302 回登录页；有效时 302 到 `index.html#?token=<uuid>` |
| GET | `/dingtalk/jsapi_ticket` | `url` | ✅ | 钉钉 JSAPI 签名。钉钉内可能返回 `200 + 空 body` |
| GET | `/dingtalk/initDingtalkChat` | `userId` | 📖 | 返回 `{msg: <目标 userId>}`，用于发起单聊 |

**登录链**（4 跳，已在真机跑通）：

```text
GET /userinfo（无 token）
  → 401 {"url":"https://cas.hdu.edu.cn/cas/login?state=..&service=.."}
GET  <cas url>          → 302 → sso.hdu.edu.cn/login?service=..&state=..
POST <sso login>        → AES-ECB 密码，302 带 ticket=ST-..
GET  /cas/login?ticket= → 302 → https://skl.hdu.edu.cn/index.html#?token=<uuid>
```

登录实现见 `auth.go`；`state` 由后端生成并随 `service` 回传，不需要自己造。

---

## 3. 学生端 API

### 3.1 课表与基础数据

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/course` | `startTime`（日期） | ✅ | 返回 `{list:[Course]}`；本包 `Courses()` |
| GET | `/school-year/all` | — | ✅ | 裸 JSON 数组；本包 `SchoolYears()` |
| GET | `/common/all-unit` | — | 📖 | 单位列表 |
| GET | `/common/all-school-unit` | — | ✅ | 本包 `AllSchoolUnits()` |
| GET | `/campus/list` | — | 📖 | 校区列表 |
| GET | `/course/teacher-list` | `params` | 📖 | 教师列表 |

### 3.2 签到 ★

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| **POST** | **`/ali-nvc/captcha-verify`** | query: `captchaVerifyParam`(JSON 串)、`userid`、`code`、`latitude`、`longitude`、`t`(ms) | ✅ | **当前前端唯一在用的签到接口**。需要阿里云验证码参数 |
| GET | `/checkIn/code-check-in` | `code`、`id`（`latitude`/`longitude` ⚠️） | ✅端点 / ⚠️参数 | 遗留，**不需要验证码参数** |
| GET | `/ali-nvc/check-code-analyze` | `userid`、`code`、`t`、`token`、`a`、`callback`(JSONP) | ✅ | 遗留 JSONP，**完全不传定位**。`a=0` 表示未做人机验证 |
| GET | `/checkIn/valid-code` | `code`、`id` | ✅ | 图形验证码流程；无会话时 `400 + 空 body` |
| GET | `/checkIn/create-code-img` | — | ✅ | 返回图片 blob（图形验证码） |

**`captcha-verify` 的响应**（字段名取自前端源码，ⓘ 抓包里的两次签到都 401，
所以成功响应未实测）：

```json
{ "captchaVerifyResult": ..., "checkCodeDto": ... }
```

`check-code-analyze` 的业务码（前端分支判断）：`100`/`200` 成功，
`400` 要求滑块，`800`/`900` 被拒。实测无效签到码得到 `800`。

> ⚠️ 人机验证是否**强制**无法用无效签到码证伪：签到码校验先于验证码，
> 缺失/伪造/不传 `captchaVerifyParam` 都返回同一个
> `401 {"code":0,"msg":"签到码不存在，不要玩我"}`。

### 3.3 考勤查询

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/checkIn/stu-course-check-in-count` | `courseId` | ✅ | 裸数组；本包 `CheckInCountByCourse()` |
| GET | `/checkIn/stu-check-count` | `params` | ✅ | `{courseName, list}`；本包 `CheckInOverview()` |
| GET | `/check-in-student-detail/my` | `startDate`、`endDate` | ✅ | 裸数组；本包 `MyCheckInDetails()` |
| GET | `/check-in-student-detail/trend` | `id`、`schoolYear`、`semester` | 📖 | 趋势分析 |
| GET | `/checkIn/all-course-check-in-count` | `params` | 📖 | 全部课程考勤统计 |

### 3.4 过程考核与作业

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/mark/stu-mark-items` | `courseId` | ✅ | 本包 `MarkItems()` |
| GET | `/mark/item-detail` | `params`（⚠️ 很可能是 `markItemId`） | 📖 | |
| GET | `/mark/mark-record` | `params` | 📖 | |
| GET | `/mark/mark-record-status-count` | `params` | 📖 | |
| POST | `/mark/submit` | body | 📖 | 提交个人作业 |
| POST | `/mark/group/submit` | body | 📖 | 提交小组作业 |
| GET | `/mark/group/my` | `params` | 📖 | |
| POST | `/mark/group/create` | `params`（body 为 null） | 📖 | |
| POST | `/mark/group/join` | `params` | 📖 | |
| POST | `/mark/group/leave` | `params` | 📖 | |
| DELETE | `/mark/group/delete` | `params` | 📖 | |
| POST | `/mark/group/update-name` | `params` | 📖 | |
| GET | `/mark/group/members` | `params` | 📖 | |
| POST | `/mark/group/member/add` | body | 📖 | |
| GET | `/mark/group/search-students` | `params` | 📖 | |
| GET | `/user/search` | `params` | 📖 | 搜学生 |

注：`/mark/group/*` 一族多为 `POST` + `params` + `body=null`。

### 3.5 请假

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| POST | `/leave/add` | body | 📖 | 学生提交请假 |
| GET | `/leave/detail` | `params` | 📖 | |
| GET | `/leave/student-list` | `params` | 📖 | 本人请假记录 |

### 3.6 谈心预约 / 咖啡 / 心理

| 方法 | 路径 | 参数 | 等级 |
| --- | --- | --- | --- |
| GET | `/talk-booking/my` | `params` | 📖 |
| GET | `/talk-booking/{id}` | — | 📖 |
| POST | `/talk-booking` | body | 📖 |
| PUT | `/talk-booking/{id}` | body | 📖 |
| POST | `/talk-booking/{id}/cancel` | — | 📖 |
| GET | `/talk-booking/coffee/pager` | `params` | 📖 |
| POST | `/talk-booking/{id}/coffee-confirm` \| `/coffee-receive` \| `/coffee-reject` | — | 📖 |
| GET | `/talk-coffee-product` | `params` | 📖 |
| GET | `/talk-coffee-shop` | `params` | 📖 |
| GET | `/psy-counselor/list` | `kind=1` | 📖 |
| GET | `/psy-counselor/detail` | `counselorId`、`kind=1` | 📖 |
| GET | `/psy-counselor/available-slots` | `kind=1` | 📖 |
| GET | `/counseling-schedule/book` | `params` | 📖 |

### 3.7 辅导员满意度评价

| 方法 | 路径 | 参数 | 等级 |
| --- | --- | --- | --- |
| GET | `/counselor-team/student-satisfaction/my/list` | `status` | 📖 |
| GET | `/counselor-team/student-satisfaction/{token}/config` | — | 📖 |
| POST | `/counselor-team/student-satisfaction/{token}/submissions` | body | 📖 |

### 3.8 考试与统计

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/exam-paper/stu/detail` | `params` | 📖 | |
| POST | `/exam-paper/stu/commit` | body | 📖 | |
| GET | `/stat/stu/user` | `params` | 📖 | 前端设了 **120s** 超时，属重接口 |

---

## 4. 教师端 API

### 4.1 签到码与考勤管理 ★

| 方法 | 路径 | 参数 / body | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| **POST** | **`/checkIn/create-code`** | body: `courseId`、`courseSchemaId`、`recordDate`、`latitude`、`longitude`、`expiresIn` | 📖 | **老师当时的定位就是围栏中心**；返回对象含 `code`、`expiresIn`/`expiresDate`、`latitude`、`longitude` |
| GET | `/checkIn/delete-code` | `code` | 📖 | 提前结束签到 |
| POST | `/checkIn/list` | body | 📖 | |
| POST | `/checkIn/history-list` | body: `courseId`、`courseSchemaId`、`recordDate` | 📖 | 返回数组，**每条带 `distance`（米）** |
| POST | `/checkIn/update` | body | 📖 | 改单个学生状态 |
| POST | `/checkIn/update-all` | body | 📖 | 批量改考勤 |
| POST | `/checkIn/reset` | body | 📖 | 清空记录 |
| GET | `/checkIn/course-check-in-count` | `courseId` | 📖 | |
| GET | `/checkIn/all-course-check-in-count` | `params` | 📖 | |

**`distance` 语义**：服务端用「老师生成签到码时的定位」与「学生签到时的定位」
算出距离。教师端 UI 以 2000m 为界着色（`< 2000` 绿，`>= 2000` 红 +「异常」）。
服务端**照记不误、不因距离超限拒签**（此条由项目所有者确认，非抓包推断）。

### 4.2 考勤明细（含全校视角）

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/check-in-student-detail/my` | `startDate`、`endDate` | 📖 | 无 `studentId` 时走 `my` |
| GET | `/check-in-student-detail/school` | `studentId`、`classNo` 等 | 📖 | 指定学生 |
| GET | `/check-in-student-detail/encrypted-school` | 同上 | 📖 | 加密 id 版本 |
| GET | `/check-in-student-detail/encrypted-id` | `studentId` | 📖 | 返回 `{id: <加密 id>}` |
| GET | `/check-in-student-detail/trend` | `id`、`schoolYear`、`semester` | 📖 | |

前端选路逻辑：`encrypted-school`（有权限看全校）→ `school`（指定学生）→ `my`（自己）。

### 4.3 课表与考核

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/course/update` | — | 📖 | 同步课表（前端提示「可能需要几秒钟」） |
| GET | `/course/teacher-list` | `params` | 📖 | |
| POST | `/teacher-mark/save` | body | 📖 | 成绩录入 |
| POST | `/mark/group/mark-single` | `params` | 📖 | |
| POST | `/mark/group/mark-record-save` | body | 📖 | |
| GET | `/mark/group/record-list` | `params` | 📖 | |
| GET | `/mark/group/record-detail` | `params` | 📖 | |
| POST | `/mark/extension-apply` | `params` | 📖 | |
| POST | `/mark/extension-review` | `params` | 📖 | |
| POST | `/mark/group/extension-apply` | `params` | 📖 | |
| POST | `/mark/group/extension-review` | `params` | 📖 | |
| POST | `/course/group/{id}` | — | 📖 | 建课程群 |

### 4.4 请假审批

| 方法 | 路径 | 参数 | 等级 |
| --- | --- | --- | --- |
| POST | `/leave/audit` | body | 📖 |
| POST | `/leave/batch-audit` | body | 📖 |
| POST | `/leave/courseAudit` | body | 📖 |
| GET | `/leave/tech-list` | `params` | 📖 |
| GET | `/leave/course-tech-list` | `params` | 📖 |

### 4.5 AI 外呼 / 帮扶 / 宿舍 / 督导

| 方法 | 路径 | 参数 | 等级 |
| --- | --- | --- | --- |
| POST | `/ai-call/call-list` | body | 📖 |
| POST | `/ai-call/teacherBatchMark` | body | 📖 |
| GET | `/ai-call/call-detail/{id}` | — | 📖 |
| GET | `/assist-course/choosed-list` \| `/stu-course-list` | `params` | 📖 |
| POST | `/assist-course/save-list` \| `/update` | body | 📖 |
| GET | `/assist-course/delete` | `params` | 📖 |
| GET | `/assist-analysis/report/list` | `params` | 📖 |
| GET | `/assist-doc/detail` | `params` | 📖 |
| POST | `/assist-doc/updateTeacher` | body | 📖 |
| GET | `/assist-student-record/detail` | `params` | 📖 |
| POST | `/assist-student-record/save` | body | 📖 |
| GET | `/assist-teacher-record/detail` | `params` | 📖 |
| POST | `/assist-teacher-record/save` | body | 📖 |
| GET | `/listen-record/stat-unit` | `params` | 📖 |
| GET | `/listener-record-export/{...}` | `params` | 📖 |
| GET | `/listener-course/all-unit` | — | 📖 |
| POST | `/listener-course-record/add-order` \| `/cancel` \| `/edit` | body | 📖 |
| GET | `/listener-course-record/detail` | `params` | 📖 |
| GET | `/dormitory/my-task` \| `/risk/detail` \| `/task-detail` \| `/taskGroup-detail` \| `/room/bedList` | `params` | 📖 |
| POST | `/dormitory/save-task-detail` \| `/saveRisk` \| `/commitTaskGroupStatus` | body | 📖 |
| POST | `/sec-event/save` | body | 📖 |
| GET | `/sec-event/detail` | `params` | 📖 |
| GET | `/newborn/status/my` | — | 📖 |
| POST | `/exam/add` | body | 📖 |
| GET | `/questionCatalogue/list` | `params` | 📖 |
| GET | `/stu/pager-all` \| `/user-byUnit` \| `/stu-list` | `params` | 📖 |
| GET | `/talk-detail` \| `/talk-save` | `params`/body | 📖 |
| POST | `/talk-booking/{id}/student-confirm` \| `/student-reject` \| `/student-feedback` \| `/complete` | body | 📖 |
| GET | `/talk-booking/admin/pager` \| `/admin/dashboard` \| `/admin/month-quota` | `params` | 📖 |
| GET | `/talk-booking/student/{id}` | — | 📖 |
| POST | `/talk-coffee-product`、`PUT /talk-coffee-product/{id}`、`POST /talk-coffee-product/{id}/status` | body | 📖 |

### 4.6 文件上传

| 方法 | 路径 | 参数 | 等级 | 备注 |
| --- | --- | --- | --- | --- |
| GET | `/oss/generateSigne` | `params` | 📖 | 拿 OSS 上传签名（注意拼写就是 `Signe`） |
| GET | `/oss/delete` | `params` | 📖 | |

---

## 5. 未证实与已知缺口

> 下面前六项靠**[issue #1](https://github.com/hdufuck/skl/issues/1)**跟踪：
> 需要一次**真实有效签到码**下的完整签到（建议用安卓模拟器/容器或官方页面抓包），
> 才能把 ⚠️ / 📖 升级为 ✅。

| 项 | 状态 |
| --- | --- |
| `captcha-verify` 成功响应结构 | 只有字段名（源码），无实测样本 |
| `captcha-verify` 是否**强制**人机验证 | 无法用无效签到码证伪（见 3.2） |
| `checkIn/code-check-in` 完整参数集 | 仅知 `code`/`id` 可到达业务逻辑 |
| `/checkIn/stu-check-count` 的 `list` 元素 | 实测为 `[]` |
| `/check-in-student-detail/*` 响应元素 | 实测为 `[]` |
| 各接口的角色权限边界 | 未逐个验证；403 文案为「没有权限」 |
| `CheckInCount` 中课程信息字段 | 前端整体展开，按命名惯例补齐，未逐字段实测 |
| `checkCodeDto` 内部结构 | 完全未知 |

---

## 6. 如何自己验证

```bash
go test ./...                                   # 离线单测（含假 CAS 站点）

# 真机集成测试（只读，不含签到）
HDU_USER=2427xxxx HDU_PASS=... go test -tags integration -run Integration -v ./...

# 只用已有 token
SKL_TOKEN=<localStorage.sessionId> go test -tags integration -run TokenOnly -v ./...
```

手工探测时注意：**每个请求都要新的 `skl-ticket`**，否则会拿到
`200 + 空 body` 而误以为接口正常。签到类接口不要拿有效签到码试探——
它会真的签到。
