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
| 签到（`captcha-verify`） | ⚠️ 协议已封装，但依赖阿里云验证码参数，见下 |
| 签到（遗留无验证码路径） | ⚠️ 可调用，但语义未能证实 |
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
    Latitude:  30.123456,   // 必须与前端同坐标系：coordinate:0 = 标准/WGS-84
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
**结论：不要在 Go 里重放这套协议。** 推荐用无头浏览器：

```go
// chromium + chromedp 思路（不引入依赖，仅示意）
// 1. 打开 https://skl.hdu.edu.cn/sign/in
// 2. 注入 localStorage.setItem("sessionId", token)  ← 关键，页面靠它鉴权
// 3. 输入 4 位签到码（页面自己会调 captcha-verify）
// 4. 等待跳转到 /sign/in/detail
// 这条路径完全不碰验证码协议，最稳。
```

### 未能证实的部分

实测**签到码校验发生在人机验证之前**：用无效签到码请求时，无论
`captchaVerifyParam` 缺失、伪造还是完全不给，服务端都返回同一个
`401 {"code":0,"msg":"签到码不存在，不要玩我"}`。

因此「无效签到码」永远无法区分验证码是否真的被校验。要证实，
必须在一个真实有效的签到码上试一次——那会直接产生考勤记录，
所以本包没有替你决定。

同理，遗留接口 `checkIn/code-check-in` 与 `ali-nvc/check-code-analyze`
是「最可能不需要验证码」的路径（后者是阿里云 NVC 的风险自适应形态，
前端平时直接上报 `a=0`），但同样无法在拿到有效签到码前证伪。

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

### 服务端确实在做距离比对

`POST /api/checkIn/history-list`（教师端考勤历史）返回的每条学生记录都带
`distance` 字段（米），教师端 UI 把 `distance < 2000` 显示为绿色、
`>= 2000` 显示为红色 +「异常」。

所以坐标偏得越远越可能被标「异常」。但 2000 只是**前端展示阈值**，
不能当作服务端的接受阈值。

### 信息在客户端就被丢掉了

钉钉定位回调还会返回 `accuracy`、`isFromMock`（仅 Android：是否为模拟定位）、
`provider`、`isGpsEnabled`。skl 前端**只取 latitude/longitude，其余全部丢弃**，
也没有上报给后端 ⟹ 设备层能识别模拟定位，但**后端拿不到这个信号**，
它看到的永远只是两个 float。

### 对调用方的要求

- 本包**不代取定位**，`Latitude`/`Longitude` 必须由你提供；缺失会让签到失败。
- **坐标系要与前端一致**（`coordinate: 0`，标准/WGS-84）。混用高德坐标会有
  数百米级偏移，足以改变围栏判定。
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

## 合规

代签/自动签到通常违反学校考勤规定。本包只提供协议封装，使用者自行承担后果。
