# skl

杭电学勤系统（`skl.hdu.edu.cn`）的非官方 Go 客户端。

从两份钉钉手机端 Reqable 抓包（2026-09-14）、skl 前端构建产物、以及**真机验证**三方
交叉确认后，把会话获取、nonce 管理、以及 skl 特有的失败模式封装成可复用的 Go 包。

> **证据来源提醒**：两份 HAR 里**不包含** skl 的 CAS 登录链
> （唯一的 `cas.hdu.edu.cn` 字样出现在 i.hdu.edu.cn 门户页里被注释掉的 `<script>` 中），
> 登录链是先从 `/api/userinfo` 的 401 契约与前端源码推导、再真机跑通的。
> 哪些事实来自抓包、哪些来自前端源码、哪些来自真机验证，见
> `doc.go` 的「证据来源」一节。

## 状态一览

| 能力 | 状态 |
| --- | --- |
| CAS/SSO 登录 → session token | ✅ 真机验证（非抓包） |
| token 注入 / 持久化 / 401 自动重登 | ✅ 已验证 |
| 只读接口（用户、课表、考勤统计、考核项） | ✅ 已验证 |
| skl-ticket 一次性 nonce 语义 | ✅ 已验证 |
| 签到（`captcha-verify`） | ⚠️ 协议已封装；真值 `captchaVerifyParam` 由浏览器取参（`internal/chromecaptcha`），待窗口实测 |
| 签到（遗留无验证码路径） | ⚠️ 可调用，但现行前端已不再使用，且探针只能作单边证据 |
| 一次性签到探针（`cmd/signinprobe`） | ⚠️ 已实现且单测覆盖；只在真实窗口跑过才算 ✅ |
| 钉钉免登（exempt-login）鉴权 | ❌ 未实现（需应用内 OAuth code） |
| 钉钉 JSAPI（扫一扫、精确定位等） | ❌ 不在网络层，无法复现 |

## 鉴权模型

skl **不使用 cookie**，会话完全靠两个请求头：

```text
X-Auth-Token: <uuid>         会话凭据 = 浏览器 localStorage.sessionId
skl-ticket:   <nanoid(21)>   每请求一次性防重放 nonce
```

`X-Auth-Token` 的取得链路（已在真机跑通）：

```text
GET /api/userinfo            （不带 token）
  → 401 {"url":"https://cas.hdu.edu.cn/cas/login?state=..&service=.."}
GET  <cas url>               → 302 转发到 sso.hdu.edu.cn（cas 只是转发壳）
POST <sso login>             → AES-ECB 加密密码，302 带 ticket=ST-..
GET  /api/cas/login?ticket=..
  → 302 https://skl.hdu.edu.cn/index.html#?token=<uuid>&t=<ms>
                                     ^^^^^ token 藏在 URL fragment 里
```

前端读到 fragment 里的 token → 存进 `localStorage.sessionId` → 用
`history.replaceState` 抹掉地址栏里的 token → 之后每个请求带 `X-Auth-Token`。

关键实现细节：`sso.Auth` 会把最后一跳的 URL 丢掉，而 token 恰好在那一跳的
fragment 里。本包为此在 **Transport 层**记录整条重定向链（同时记录每一跳的
`Location` 头作为兜底），再倒序提取 `token=` 参数。

登录环节复用 [`hduwebvpn`](https://github.com/U1traVeno/hduwebvpn) 的
`pkg/sso`（`cas.hdu.edu.cn` 与 `sso.hdu.edu.cn` 共用同一套 flowkey/AES 表单）。

> **不需要 WebVPN**：`skl.hdu.edu.cn` 公网可直连，钉钉容器里也是直连。

## 使用

```go
import skl "github.com/hdufuck/skl"

client, err := skl.NewClient(
    skl.WithCredentials("24000000", "password"),
    // token 持久化，避免每次启动都走一遍 CAS
    skl.WithOnToken(func(tk string) { _ = os.WriteFile(".token", []byte(tk), 0o600) }),
)
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

// 首次调用会在收到「带 url 的 401」时自动完成 CAS 登录
user, err := client.UserInfo(ctx)
fmt.Println(user.UserName, user.ClassNo, user.ID)

courses, _ := client.Courses(ctx, time.Now())
for _, course := range courses {
    counts, _ := client.CheckInCountByCourse(ctx, course.CourseID)
    _ = counts
}
```

只用外部 token（不走登录）：

```go
client, _ := skl.NewClient(skl.WithToken(token))
```

尚未类型化的接口走逃生口：

```go
resp, err := client.Raw(ctx, http.MethodPost, "/api/checkIn/update", query, body)
```

## 签到

签到有两条路径，都必须由调用方显式选择——本包**不做自动降级**，
因为两条路的语义和风险不同。

### 一、`SignIn`（当前前端使用，需要人机验证）

```go
result, err := client.SignIn(ctx, skl.SignInRequest{
    Code:      "1212",
    Latitude:  30.123456,   // 坐标系必须与前端一致（前端向 coordinate 传 0，其语义尚未证实，见「定位信息」）
    Longitude: 120.654321,
})
```

`captchaVerifyParam` 必须由阿里云验证码 SDK 产出。注入方式：

```go
// 方式 1：人工从 DevTools 复制（一次性）
client, _ := skl.NewClient(
    skl.WithCredentials(u, p),
    skl.WithCaptchaProvider(skl.StaticCaptchaProvider{Value: captured}),
)

// 方式 2：无头浏览器取参数
client, _ := skl.NewClient(
    skl.WithCaptchaProvider(skl.CaptchaProviderFunc(func(ctx context.Context, scene skl.CaptchaScene) (string, error) {
        return myBrowser.DriveCaptcha(ctx, scene) // 见 README「人机验证」一节
    })),
)
```

### 二、`SignInLegacy` / `SignInLegacyAnalyze`（遗留接口，不需要验证码参数）

```go
result, err := client.SignInLegacyAnalyze(ctx, skl.AnalyzeRequest{
    SignInRequest: skl.SignInRequest{Code: "1212", Latitude: 30.123456, Longitude: 120.654321},
})
if result.OK() { /* 100/200 */ }
if result.CaptchaRequired() { /* 400：服务端要求滑块 */ }
```

> ⚠️ **不要拿它们当「只校验签到码」的探针。** 这两个接口的语义是
> 「校验并签到」。传入有效签到码可能会直接签到成功。

## 人机验证（最大风险点）

`captchaVerifyParam` 形如：

```json
{"sceneId":"2q42bw25","certifyId":"..","deviceToken":"V0VCI2Fi..","data":"JRMlgg1E.."}
```

| 子字段 | 来源 |
| --- | --- |
| `certifyId` | `POST https://cr5a57.captcha-open.aliyuncs.com`（会话初始化） |
| `deviceToken` | `POST https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com`（设备指纹） |
| `data` | SDK 内部混淆代码加密的风控载荷，另有 `upload.captcha-open.aliyuncs.com` 遥测上传 |

三者均由阿里云侧签名，与 SceneId、站点域名绑定，且 SDK 会轮换算法。
**结论：不要在 Go 里重实现这套协议。** 本仓库的做法是：用真 Chrome 加载
阿里云官方 SDK（`internal/chromecaptcha`），从 `captchaVerifyCallback` 里取出真值，
再交给库的 `SignIn` 提交——只借道官方 SDK，不碰协议。

```text
1. chromecaptcha：在真实源下交付极简页 → 加载 AliyunCaptcha.js → 点一次触发按钮
2. 拿到真值 captchaVerifyParam（一次性，90s 内要用掉）
3. client.SignIn{Code, Latitude, Longitude, CaptchaVerifyParam: 真值}
```

完整流程、相位预算与手机端配合见 [`docs/signin-probe.md`](docs/signin-probe.md)。

### 未能证实的部分

实测**签到码校验发生在人机验证之前**：用无效签到码请求时，无论
`captchaVerifyParam` 缺失、伪造还是完全不给，服务端都返回同一个
`401 {"code":0,"msg":"签到码不存在，不要玩我"}`。

因此「无效签到码」永远无法区分验证码是否真的被校验。要证实，
必须在一个真实有效的签到码上试一次——那会直接产生考勤记录，
所以本包没有替你决定。

同理，遗留接口 `checkIn/code-check-in` 与 `ali-nvc/check-code-analyze`
也**不能在拿到有效签到码前证伪**。但要注意：bundle 级检索显示它们**不是**「官方页面也会走的备用路」——
`code-check-in` 零调用者，`check-code-analyze` 所在路由 `/sign/location` 不可达
（且它传的 `code` 是定位就绪标志的布尔值，不是签到码）。所以用它们做探针只能得到**单边证据**：
成功才算证明不强制，失败不可解释。

**完整的判定方法与操作手册见 [`docs/signin-probe.md`](docs/signin-probe.md)**：

| 档 | 内容 |
| --- | --- |
| 1 | `check-code-analyze`（`a=0`，无人机凭证、无定位） |
| 2 | `code-check-in`（无人机凭证、带定位） |
| 3 | 有效码 + **缺失** `captchaVerifyParam`（直接回答「是否强制」） |
| 4 | 有效码 + **结构合法但伪造**的凭证（把参数层与人机层分开） |
| 5 | 有效码 + **官方 SDK 真值** → 库的 `SignIn`（验证库的封装路径） |

预置清单、30 秒相位预算、写入闸门、读回判读表、脱敏规则、以及手机端
（钉钉 + Reqable 上报服务器）要做的每一步，都在那份手册里。
这套实验的约束与取舍——为什么允许从本机发探针、为什么本机失败只作弱证据、
为什么继续排除模拟器——见
[`docs/adr/0002-本机探针与浏览器取参的取舍.md`](docs/adr/0002-本机探针与浏览器取参的取舍.md)。

## 未覆盖的鉴权路径：钉钉免登

HAR#2 里会出现另一条 SSO 流程，本包**没有实现**：

```text
GET /sso.hdu.edu.cn/clientredirect?client_name=dingDingWlan&service=..
GET /sso.hdu.edu.cn/public/exempt-login/dingding.html
    ?corpId=..&appid=..&open=true&response_type=code&scope=snsapi_auth
GET /sso.hdu.edu.cn/login?code=<钉钉 OAuth code>&client_name=dingDingWlan
  -> 302 ...&ticket=ST-..
```

这条路的 `code` 是钉钉开放平台在**应用内部**下发的 OAuth 授权码，服务端没有
账号密码环节，包外无法复现（拿不到 code）。本包改为走账号密码的
CAS/SSO 表单，效果等价。**但如果学校改成只保留免登、关闭密码登录，本包会失效。**

同理，下面这些能力**不存在于网络层**，抓包不可能复现：

- 钉钉 JSAPI 桥（`dd.*`：`device.geolocation.get`、`biz.util.scan`、`biz.chat.*`）。
- 验证码 `data` / `deviceToken` 的生成过程（其依赖的 HTTP 调用在抓包里可见，
  但真正的设备指纹采集与签名在原生/SDK 内部完成）。

## 定位信息

签到是地理位置绑定的，而**定位完全由客户端提供**。

### 定位从哪来

前端分两条路（看 UA 里有没有 `DingTalk`）：

```js
// 钉钉内
dd.device.geolocation.get({
    targetAccuracy: 50,        // 期望精度 50m（官方推荐 200m）
    coordinate: 0,             // 0 = 标准坐标(WGS-84)，1 = 高德坐标(GCJ-02)
    withReGeocode: false,
    useCache: false,           // 不用客户端 2 分钟缓存
})

// 钉钉外
navigator.geolocation.getCurrentPosition(..., {
    enableHighAccuracy: true, timeout: 5000, maximumAge: 0,
})
```

`coordinate: 0` 的语义来自钉钉官方文档（1=高德坐标，0=标准坐标）。但文档同时说
“Android 客户端返回坐标是高德坐标”，所以 `coordinate: 0` 在 Android 上能否真的
拿到标准坐标**存疑**。前端**不做任何坐标系转换**（产物里搜不到 gcj/wgs/bd09 转换）。

### 定位去哪

| 谁 | 请求 | 定位 |
| --- | --- | --- |
| 学生签到 | `POST /api/ali-nvc/captcha-verify` | `latitude`/`longitude`（HAR 实测） |
| 教师生成签到码 | `POST /api/checkIn/create-code` | 请求体带 `{courseId, courseSchemaId, recordDate, latitude, longitude, expiresIn}` |
| 遗留 `/sign/ali` | `GET /api/ali-nvc/check-code-analyze` | **完全不传定位**（只报 userid/code/t/token/a） |

关键：**老师生成签到码时所在的定位，就是这次签到的地理围栏中心**。

### 服务端确实在算距离，但不拒签

`POST /api/checkIn/history-list`（教师端考勤历史）返回的每条学生记录都带
`distance` 字段（米），教师端 UI 把 `distance < 2000` 显示为绿色、
`>= 2000` 显示为红色 +「异常」。

关键：**服务端对所有距离都照记不误，不会因距离超限拒绝签到**
（此条由项目所有者、本校学生确认，非抓包推断）。

所以 2000m 只是**教师端展示阈值**：伪造坐标不会让签到失败，
但可能换来一条在教师端被标成「异常」的考勤记录。

### 信息在客户端就被丢掉了

钉钉定位回调还会返回 `accuracy`、`isFromMock`（仅 Android：是否为模拟定位）、
`provider`、`isGpsEnabled`。skl 前端**只取 latitude/longitude，其余全部丢弃**，
也没有上报给后端 ⟹ 设备层能识别模拟定位，但**后端拿不到这个信号**，
它看到的永远只是两个 float。

### 对调用方的要求

- 本包**不代取定位**，`Latitude`/`Longitude` 必须由你提供；缺失会让签到失败。
- **坐标系要与前端一致**（前端向 `coordinate` 传 `0`）。混用高德与标准坐标会有
  数百米级偏移，足以让记录在教师端被标为「异常」。注意 `coordinate: 0` 到底对应
  哪种坐标系**尚未证实**，详见上文。
- 服务端不向未签到的人提供教室坐标，**无法在签到前自检距离**。

### 抓包里的定位旁路流量

`dualstack-a.apilocate.amap.com`（高德定位 SDK）、`cloudauth-device-dualstack`
（阿里云设备指纹）这些属于**原生 SDK 的定位与风控链路**，和本包无关——
我们直接给数值。

## 其它已实测的行为约束

- **`skl-ticket` 是一次性 nonce。** 受控实验：同一个值首次请求正常返回，
  第二、三次立即变成 `HTTP 200 + 空 body`；换成新生成的 nanoid 连续 6 次全部正常。
  失败不能用状态码判断，本包因此把它翻译成 `ErrEmptyBody`。
  重试请求时必须重新构造 `Request`，不要复用。
- **空 body 的其它成因未能证实。** 另有 1 次无法解释的同类空响应，当时在短时间
  内连续压测该接口；曾略怀疑 User-Agent，但用同一 Android UA 连测 3 次均正常，
  **该假设已被证伪**。可能来自限流，但没有证据。本包不自动重试空 body，
  请把 `ErrEmptyBody` 当作退避信号。
- **服务端不因距离超限拒签。** 见下「定位信息」。定位可以由客户端任意提供，
  不会导致签到失败，但会让记录在教师端被标为「异常」。
- **`/api/dingtalk/jsapi_ticket` 会合法地返回空 body。** HAR#2 里该请求就是
  200 + 0 字节（同一账号在 HAR#1 里返回了完整 JSON）。`JsapiTicket()` 因此
  显式允许空 body，并把它翻译成带上下文的 `ErrEmptyBody`，而不是解析失败。
- **401 有双重语义。** 会话失效与业务校验失败（如「签到码不存在」）
  都用 401。判据是响应体是否带 `url` 字段：带 `url` 才是会话失效。
  `Do` 的自动重登与 `APIError.NeedLogin()` 用的是同一判据。
- **定位由客户端上报。** `latitude`/`longitude` 服务端只做数值校验，
  缺失则签到失败。
- **token 生命周期未知**：无 cookie、无过期信息，实测隔夜仍可用（> 1 天）。
- **登录依赖 SSO 表单结构**：共享 `hduwebvpn/pkg/sso`，学校改版需先升级它。
- **钉钉 JSAPI 超出能力范围**：`jsapi_ticket` 在钉钉外可调用，但签名
  无法驱动任何 JSAPI。`dd.*` 的能力不存在于网络层，抓包无法复现。

完整风险清单见 `doc.go` 的「风险与未解项」。

## 已探明的 API 面

前端 `index-BjaCUYRh.js` 里注册的全部端点（本包已类型化的标注 ✅）。
注意：这张表来自**前端构建产物**，其中大部分并未出现在两份 HAR 里。

| 域 | 端点 |
| --- | --- |
| 鉴权 | `GET /api/userinfo` ✅、`GET /api/cas/login`、`GET /api/dingtalk/jsapi_ticket` ✅ |
| 基础 | `GET /api/school-year/all` ✅、`GET /api/course` ✅、`GET /api/common/all-school-unit` ✅、`GET /api/campus/list`、`GET /api/user/search` |
| 考勤 | `GET /api/checkIn/stu-course-check-in-count` ✅、`GET /api/checkIn/stu-check-count` ✅、`GET /api/check-in-student-detail/my` ✅、`POST /api/checkIn/create-code`、`POST /api/checkIn/list`、`POST /api/checkIn/history-list`、`POST /api/checkIn/update`、`POST /api/checkIn/update-all`、`POST /api/checkIn/reset`、`GET /api/checkIn/delete-code`、`GET /api/checkIn/create-code-img` ✅、`GET /api/checkIn/valid-code` ✅ |
| 签到 | `POST /api/ali-nvc/captcha-verify` ✅、`GET /api/checkIn/code-check-in` ✅、`GET /api/ali-nvc/check-code-analyze` ✅ |
| 考核 | `GET /api/mark/stu-mark-items` ✅、`GET /api/mark/item-detail`、`GET /api/mark/mark-record`、`POST /api/mark/submit`、`/api/mark/group/*`、`/api/mark/extension-*`、`POST /api/teacher-mark/save` |
| 请假 | `POST /api/leave/add`、`/api/leave/audit`、`/api/leave/batch-audit`、`/api/leave/courseAudit`、`GET /api/leave/detail`、`/api/leave/course-tech-list`、`/api/leave/student-list`、`/api/leave/tech-list` |
| 其它 | `/api/paper/*`、`/api/talk-booking/*`、`/api/talk-coffee-*`、`/api/psy-counselor/*`、`/api/counseling-schedule/book`、`/api/ai-call/*`、`/api/stat/stu/user`、`/api/course/group/{id}`、`/api/course/teacher-list`、`/api/counselor-team/student-satisfaction/*` |

## 测试

```bash
go test ./...                       # 单元测试，全部离线

# 集成测试（会真实登录，只跑只读接口，不含签到）
HDU_USER=2427xxxx HDU_PASS=... go test -tags integration -run Integration -v ./...

# 只用已有 token
SKL_TOKEN=<localStorage.sessionId> go test -tags integration -run TokenOnly -v ./...
```

单元测试用 `httptest` 搭了一个假的 skl 站点，覆盖 CAS 转发、SSO 登录页、
CAS 回调与 token 下发，因此**整条登录链是可以离线测试的**。

判定「人机验证是否强制」并验证库的签到封装路径是一次性的现场实验，
**不在测试套件里**：按 [`docs/signin-probe.md`](docs/signin-probe.md) 执行——
预置清单、30 秒相位预算、探针顺序、读回判读表、手机端操作与脱敏规则都写在那里，
不要临场发挥。探针工具是 [`cmd/signinprobe`](cmd/signinprobe/main.go)：

```bash
export HDU_USER=2427xxxx HDU_PASS=...
go run ./cmd/signinprobe            # 默认 headless、Reqable hook :8080、30s 预算
```

> ⚠️ **不要把真实数据写进代码或文档。** 本文库会公开，而抓包/真机调试很容易
> 顺手把真实学号、姓名、手机号、**当时的 GPS 坐标**、以及**仍然有效的会话 token**
> 粘进测试用例或文档示例。目前仓库里一律使用合成占位值
> （学号 `24000000`、坐标 `30.123456,120.654321`、token `11111111-2222-...`）。
> `*.har` 与 `.env` 已在 `.gitignore` 中屏蔽。
>
> 唯一例外是签到探针的默认围栏中心 `30.313816,120.343228`：它是**刻意写死的
> 公开校园坐标**（功能常量，覆盖教学楼范围），不是从抓包里抄下来的个人定位。

## 合规

代签/自动签到通常违反学校考勤规定。本包只提供协议封装，使用者自行承担后果。
