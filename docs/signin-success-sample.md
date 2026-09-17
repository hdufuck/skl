# 成功签到样本：`POST /api/ali-nvc/captcha-verify`

本文记录**唯一一次**在真实有效 `SignInCode` 上抓到的签到**成功**响应，补齐
[issue #1](https://github.com/hdufuck/skl/issues/1) 的第一块空白（成功响应结构）。
人机验证是否**强制**仍未被证明（见第 7 节），本文不回答那个问题。

- **采集 id**：`skl.hdu.edu.cn2.har`（下称 `har#3`；38.3 MB、112 条、3 个 page、
  全程约 115 秒）
- **采集方式**：桌面 Chromium 浏览器**网页签到**（非钉钉客户端），DevTools 导出 HAR，
  过程中**有人工操作**（不是脚本）
- **证据分级**沿用 [`api.md`](./api.md) 的约定：✅ 已实测 / 📖 源码 / ⚠️ 未证实。
  本文所有 ✅ 都指「在这份 HAR 的第 N 条里逐字节可见」，条号即 `log.entries` 下标
- **打码**：见第 8 节。`X-Auth-Token`、`skl-ticket`、`deviceToken`、`data` 的完整值
  **不入本文**；**人名、学号、课程、具体日期与钟点一律打码**。
  原始 HAR 与 `probe-results/` 均 gitignored

**时间怎么写。** 本文不写任何真实日历日期与钟点：字段值中的时间一律用
**Go 参考时间格式**（`2006-01-02T15:04:05.000Z`）占位；涉及证据的时序一律给出
**相对偏移** `t+<秒>`（`t=0` 是本 HAR 第 0 条的起始时刻），需要起止关系时再给
**时长/差值**。这样「谁在哪天几点签的」不可追踪，而「谁比谁早、早多少」这条证据链一分不少。

> ⚠️ 一个**未被隔离的变量**：HAR 里落盘的 UA 是
> `Mozilla/5.0 (X11; Linux x86_64) … Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0`，
> 而同期截图显示的是 macOS 上的 Chromium 浏览器。二者矛盾（UA 伪装或抓包取自另一台机器），
> 本采集无法排除它对阿里云风控评分的影响（第 4.2 节那个 `F001` 可能与此有关）。

---

## 1. 成功响应全文 ✅

`POST /api/ali-nvc/captcha-verify` → **HTTP 200**，`application/json`，533 字节，
耗时 535.6 ms（**第 101 条**，`t+112.954s`）：

```json
{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{"code":"<有效码>","courseId":"<32 位大写 hex，已打码>","courseName":"<课程名，已打码>","courseSchemaId":"<21 字符，已打码>","expiresDate":"2006-01-02T15:04:05.000Z","expiresIn":20000,"id":"<记录主键，已打码>","latitude":30.313072,"longitude":120.341896,"recordDate":"2006-01-01T16:00:00.000Z","requestLatitude":30.31878,"requestLongitude":120.339417,"studentId":"24*****4","teachName":"张三","teacherId":"<教师工号，已打码>","totalCheckInRecord":null,"week":1}}
```

### 1.1 顶层三个键

| 键 | 类型 | 本样本值 | 说明 | 等级 |
| --- | --- | --- | --- | --- |
| `captchaVerifyResult` | bool | `true` | 服务端对本次 `CaptchaVerifyParam` 的判定 | ✅ |
| `captchaVerifyCode` | string | `"T001"` | **新字段**，此前完全未知。成功 = `T001`，失败 = `F001` | ✅ |
| `checkCodeDto` | object | 非空 | 成功时是 `CheckInRecord` 详情；失败时**整个键不存在** | ✅ |

> 前端消费方式（`assets/index-new-dX4pM4CL.js`，📖 源码）：
> `P={captchaResult:g.captchaVerifyResult,bizResult:!0}` 且
> `g.checkCodeDto&&f.setSignDetail(g.checkCodeDto)`；
> 严格 `=== true` 时 SDK 回调 `onBizResultCallback(true)`，页面才 `replace("/sign/in/detail")`。
> 本样本正是这条路径：成功后立即加载 `complete-B0lF1L3O.js`、`dashBoard-*.js`（第 103–108 条）。

### 1.2 `checkCodeDto` 的 17 个字段

| 字段 | 类型 | 本样本值 | 判读 | 等级 |
| --- | --- | --- | --- | --- |
| `id` | string | `<记录主键，已打码>` | 本次 `CheckInRecord` 的主键（21 字符，非 nanoid 形状） | ✅ |
| `code` | string | `"<有效码>"` | 回显提交的 `SignInCode`（4 位数字） | ✅ |
| `studentId` | string | `"24*****4"` | 回显提交的 `userid`，即学号（8 位） | ✅ |
| `courseId` | string | `<32 位大写 hex，已打码>` | 32 位大写 hex，与签到码绑定 | ✅ |
| `courseSchemaId` | string | `<21 字符，已打码>` | 21 字符 | ✅ |
| `courseName` | string | `<课程名，已打码>` | 课程名（**不在** `stu-course-check-in-count` 的响应里） | ✅ |
| `teachName` | string | `张三` | 与 `create-code` 时的教师一致（占位名，见第 8 节） | ✅ |
| `teacherId` | string | `<教师工号，已打码>` | | ✅ |
| `week` | number | `1` | 教学周 | ✅ |
| `recordDate` | string | `"2006-01-01T16:00:00.000Z"` | **ISO-8601 串**，语义是**当天 00:00（北京时间）**：样本里 16:00Z 正是北京次日 00:00。不是时刻 | ✅ |
| `expiresIn` | number | `20000` | **时长 20 秒**（不是时间戳）。`expiresDate − expiresIn` 反推出签到码创建时刻 | ✅ |
| `expiresDate` | string | `"2006-01-02T15:04:05.000Z"` | ISO-8601，签到码失效时刻 | ✅ |
| `latitude` | number | `30.313072` | **教师生成签到码时的围栏中心**。真实响应是 **16 位有效数字**，本文只留 6 位 | ✅ |
| `longitude` | number | `120.341896` | 同上 | ✅ |
| `requestLatitude` | number | `30.31878` | **回显提交的定位**（与 query 里的 `latitude` 逐字节相同） | ✅ |
| `requestLongitude` | number | `120.339417` | 同上 | ✅ |
| `totalCheckInRecord` | null | `null` | 本样本为 `null`；语义 ⚠️ | ✅ 字段 / ⚠️ 语义 |
| `distance` | — | **不存在** | 围栏距离**不在这条响应里**（`history-list` 才有） | ✅ |

**由本样本可确定的**：`captcha-verify` 的成功响应同时携带「围栏中心」与「学生上报点」，
但**不含**二者的距离。判「`distance` 超限是否拒签」仍需教师端 `history-list` 或专门探针。

---

## 2. 同一路径的四种形态（只有一种成功）✅

这条接口的成败**不能**用状态码判断，四种形态都在本采集里出现过：

| 形态 | 条号 / 时刻 | 响应体 | 判读 |
| --- | --- | --- | --- |
| `200` + 成功 | 101 / `t+112.954s` | `{"captchaVerifyResult":true,"captchaVerifyCode":"T001","checkCodeDto":{…}}` | 成功 |
| `200` + **人机被拒** | 98 / `t+110.577s` | `{"captchaVerifyResult":false,"captchaVerifyCode":"F001"}` | **阿里云风控不通过**（官方措辞：「疑似攻击请求，风险策略不通过」）；无 `checkCodeDto` |
| `401` + 业务失败 | 1 / `t+0.090s` | `{"code":0,"msg":"签到码不存在，不要玩我"}` | 签到码校验**先于**人机校验 |
| `414` + 网关 | 6 / `t+63.828s`；10 / `t+99.380s` | `URI too long\n`（`text/plain`，13 字节） | 请求行超长，被**网关**挡下，未到应用 |

第 98 条是本次最有价值的一条**负面**证据：它提交的是**同一个有效签到码**
（与成功的第 101 条逐字节相同、都是 `<有效码>`），只是 `CaptchaVerifyParam` 换了
另一个 `certifyId`（`c5` → 见第 4 节）——结果人机判定 `false`。
所以「有效签到码 + 人机不通过」的确切报错是
**`200 {"captchaVerifyResult":false,"captchaVerifyCode":"F001"}`**，而不是 401。

> 归因未知：第 98 条的参数本身是**真值**（第 83 条 `InitCaptcha` 出的 `certifyId`，
> 距提交仅 4.25 s），不是伪造也不是明显过期。它为何被判 `F001`，本采集**无法解释**。
> `F001`/`T001` 这三个字面量在全部前端产物里都**不存在**（对 `har#3` 里全部前端产物做
> 字面检索，0 命中），即它由服务端产生、前端只透传 `captchaVerifyResult`。

---

## 3. 请求形状 ✅

**请求行**（第 101 条）：

```text
POST /api/ali-nvc/captcha-verify?captchaVerifyParam=…&userid=…&code=<有效码>
     &latitude=30.31878&longitude=120.339417&t=<13 位毫秒 epoch> HTTP/1.1
Content-Type: application/x-www-form-urlencoded   ← 但 body 为空（无 postData）
```

| 参数 | 值 | 说明 |
| --- | --- | --- |
| `captchaVerifyParam` | JSON 串（本样本 4442 字符） | 见第 5 节 |
| `userid` | `24*****4`（8 位学号） | 与 `userinfo.id`、`checkCodeDto.studentId` 一致 |
| `code` | `<有效码>` | 4 位 `SignInCode` |
| `latitude` / `longitude` | `30.31878` / `120.339417` | 学生上报定位，5/6 位小数 |
| `t` | 13 位毫秒 epoch | = 本条请求发起前 1 ms（与前端 `Date.now()` 一致） |

| 请求头 | 观测 | 等级 |
| --- | --- | --- |
| `X-Auth-Token` | 36 字符 UUID；**等于**第 46 条 CAS 跳转 `https://skl.hdu.edu.cn/?token=<同一 UUID>` 上的 `token` 查询参数 | ✅ |
| `skl-ticket` | 每次请求都带，且逐条不同；本采集 9 个值**全部**匹配 `/^[A-Za-z0-9_-]{21}$/`（nanoid urlAlphabet） | ✅ |
| `Content-Type` | `application/x-www-form-urlencoded`（**body 为空**时也带） | ✅ |
| `Origin` / `Referer` | `https://skl.hdu.edu.cn` / `https://skl.hdu.edu.cn/` | ✅ |
| `Accept` | `application/json, text/plain, */*` | ✅ |
| Cookie | **整个 HAR（112 条）零 `Cookie` 请求头、零 `Set-Cookie` 响应头** | ✅ |

> `X-Auth-Token` = `?token=` 这条链现在是 ✅（此前是 📖 推断）；
> nanoid(21) 与 `nonce.go` 的实现一致 ✅。

---

## 4. 完整时序：一次网络波动 + 一次人机降级

> 时刻一律用 `t+<秒>`（相对本 HAR 第 0 条），不含任何真实钟点。

### 4.1 五次提交，只有最后一次成功

| 提交 | 时刻 | `certifyId` | 该 `certifyId` 的 `CaptchaType` | 参数长度 | 结果 |
| --- | --- | --- | --- | --- | --- |
| 第 1 条 | `t+0.090s` | `c1` | ⚠️ 其 `InitCaptcha` 早于录制起点 | 5306 | `401 签到码不存在`（`<无效码>`） |
| 第 6 条 | `t+63.828s` | `c2` | **TRACELESS**（第 3 条 init） | **27998** | **414 URI too long**（`<无效码>`⚠️ 未达应用，故其有效性未知） |
| 第 10 条 | `t+99.380s` | `c3` | **TRACELESS**（第 7 条 init） | **26806** | **414 URI too long**（`<无效码>`⚠️ 同上） |
| 第 98 条 | `t+110.577s` | `c5` | **TRACELESS**（第 83 条 init） | 4278 | `200 F001`（`<有效码>`，真码） |
| 第 101 条 | `t+112.954s` | `c6` | **CHECK_BOX**（第 99 条 init） | 4442 | **`200 T001` 成功**（`<有效码>`） |

`InitCaptcha` 响应里的 `CaptchaType` 逐条实测（`cr5a57.captcha-open.aliyuncs.com`；
`certifyId` 已按同一映射换成 `cN`）：

```text
第   3 条 t+  0.494s  {"CertifyId":"c2",…,"StaticPath":"3.29.0/cx.098…","CaptchaType":"TRACELESS"}
第   7 条 t+ 64.564s  {"CertifyId":"c3",…,"StaticPath":"3.29.0/cx.094…","CaptchaType":"TRACELESS"}
第  11 条 t+100.412s  {"CertifyId":"c4",…,"StaticPath":"3.29.0/cx.095…","CaptchaType":"TRACELESS"}
第  83 条 t+106.328s  {"CertifyId":"c5",…,"StaticPath":"3.29.0/cx.081…","CaptchaType":"TRACELESS","DeviceConfig":"27FRpz…=="}
第  99 条 t+110.952s  {"CertifyId":"c6",…,"StaticPath":"3.29.0/cx.081…","CaptchaType":"CHECK_BOX"}
第 102 条 t+114.501s  {"CertifyId":"c7",…,"StaticPath":"3.29.0/cx.088…","CaptchaType":"TRACELESS"}
```

两个关键观测：

1. **`CaptchaType` 是每次 init 由阿里云现判的**，同一次会话里会变；
   第 83 与第 99 条返回**同一个 `StaticPath`**（`cx.081…`），但类型从
   `TRACELESS` 升级成了 `CHECK_BOX`。
2. **第 99 条是全采集唯一携带 `CertifyId` 的 `InitCaptcha`**（值 = 上一次的 `c5`）
   —— 这是 SDK 的**重初始化**（`reInitCaptcha`）特征：把上一次的 `certifyId` 带回去，
   阿里云据此把无痕模式升级为显式交互。

### 4.2 因果链（可直接对账浏览器「网络」面板）

```text
t+104.646s  page_3 打开 https://skl.hdu.edu.cn/?token=<UUID>（CAS 带 token 落地）
t+104.628s  第 43 条 InitCaptcha（DeviceData）→ HAR 未留存 body（brotli 未落盘），
            但同一元素的第 83 条响应 581 B，形状可对账
t+106.328s  第 83 条 InitCaptcha → c5 / TRACELESS（带 DeviceConfig）
t+106.503s  第 91 条 加载 FeiLin 设备指纹 JS（576 KB）
t+106.504s  第 92 条 加载 cx.081 交互模块（448 KB）
t+107.334s  第 96 条 cloudauth 设备指纹 Log2；t+110.506s 第 97 条 Log3
t+110.577s  第 98 条 提交 → 200 {"captchaVerifyResult":false,"captchaVerifyCode":"F001"}
t+110.952s  第 99 条 SDK 自动 reInitCaptcha（带 CertifyId=c5）→ c6 / CHECK_BOX
t+111.270s  第 100 条 UploadLog
t+112.954s  第 101 条 用户勾选「确认您不是机器人」后提交 → 200 T001 成功
t+114.501s  第 102 条 InitCaptcha（成功后 SDK 仍重置）
t+114.503s  第 103–108 条 加载 /sign/in/detail 的 complete-*、dashBoard-* 资源
t+115.206s  第 111 条 GET /api/checkIn/stu-course-check-in-count?courseId=<已打码> → rightCount:1
```

**时间窗口极紧**（这里只需要差值，所以照给）：由 `expiresIn=20000` 与 `expiresDate`
反推，签到码创建于 `t+103.739s`、失效于 `t+123.739s`；成功提交在 `t+112.954s`
⟹ 老师生成到学生提交**只剩 9.215 s**，提交到失效只剩 **10.785 s**。
中间还吃了一次 `F001` 重来。

### 4.3 边界（务必不要过度外推）

**`CHECK_BOX` 是浏览器路径的现象，不能当成钉钉客户端的行为。**
本采样端是桌面 Chromium（云端风控评分把它从无痕升级为显式交互）；
按项目所有者陈述，**钉钉客户端的人机验证是静默（TRACELESS）的**。
两种形态共用同一个 `SceneId=2q42bw25` / `prefix=cr5a57` / `exec mode=popup`，
且成功响应结构与 `CaptchaType` **无关**（服务端只看 `captchaVerifyResult`）。
因此第 1 节的结构对两条路径都成立，第 4 节的过程**只**属于浏览器路径。

---

## 5. `CaptchaVerifyParam` 内部结构与 414 的真实原因

### 5.1 结构 ✅

五个提交样本的 JSON 都是同一组四个键（顺序固定）：

```json
{"sceneId":"2q42bw25","certifyId":"<10 字符>","deviceToken":"<1332/1360 字符>","data":"<base64>"}
```

| 提交 | `data` 长度 | `deviceToken` 长度 | 参数总长 | 结果 |
| --- | --- | --- | --- | --- |
| 第 1 条 | 3900 | 1332 | 5306 | 401（错码） |
| 第 6 条 | **26592** | 1332 | **27998** | 414 |
| 第 10 条 | **25372** | 1360 | **26806** | 414 |
| 第 98 条 | 2872 | 1332 | 4278 | 200 F001 |
| 第 101 条 | 3036 | 1332 | 4442 | **200 T001** |

- `data` 是 **base64（`A-Za-z0-9+/=`）高熵载荷**（≈7.6 bit/byte），解码后不以 16 取整，
  不是明文、不是 gzip/zlib/deflate 流 —— 即不可解析、不可合成 ✅
- `deviceToken` 是 FeiLin 设备指纹令牌（`window.um.getToken()`），**同一会话内复用**：
  第 3/7/11 条逐字节相同，第 99/102 条逐字节相同（是第二个会话）✅

### 5.2 414 是网关拒绝超长请求行，不是应用拒绝 ✅

| 证据 | 观测 |
| --- | --- |
| 响应头 | 两个 414 **独有** `X-Kong-Response-Latency: 2`；正常响应没有它 |
| 响应形态 | `text/plain; charset=utf-8`、`Connection: close`、body 恰为 `URI too long\n`，**无** CORS / `Vary` / JSON |
| 对比 | 同一时刻的 200/401 响应都带 `Access-Control-Allow-Origin: https://skl.hdu.edu.cn` 与 `application/json` |
| 时钟 | 两个 414 的响应头 `Date` 比浏览器时钟**早约 465.5 s**（正常响应在 ±0.6 s 内），说明是另一个网络元素应答 |
| `Server` | 所有 skl 响应都是 `nginx/1.251`，**不区分**层 |

**请求行长度包线**（本条是从本采集可证的**最紧**界）：

```text
请求行：  5615 ≤ L < 27839
完整 URL：5623 ≤ L < 27847    （完整 URL = 请求行 + 8）
```

即第 1 条（请求行 5615 / 完整 URL 5623）被接受、拿到业务 401，第 10 条（27839 / 27847）被拒。
代码里 `LongestAcceptedURLLen = 5623` 比的是**完整 URL**。
落在区间里的常见值（如 nginx 默认 `large_client_header_buffers 4 8k` = 8192）**无法**由本采集证实。

> **这是对库最要紧的一条**：`TRACELESS` 的 `data` 会随时间/行为膨胀到 25 KB 量级，
> 而 `CHECK_BOX` 与短会话的 `TRACELESS` 都在 4.3 KB 量级。
> 也就是说**同样的代码会随机踩中 414**，且它在第 2 节里既不是 401 也不是 200 ⟹
> 必须显式识别（第 6 节）。

---

## 6. 本采集对现有文档与代码的修正清单

`docs/api.md` / `docs/signin-probe.md` / 代码里曾经**与证据冲突**或**可升级**的条目。
下表已全部落地（同一次提交），留在这里是为了让每一条修正都能追回原始证据。

| 位置 | 修正前 | 已改为 | 落在哪 |
| --- | --- | --- | --- |
| `docs/api.md` §3.2 / §5 | 「抓包里的两次签到都 401，成功响应未实测」⚠️ | ✅ 全文 + 17 字段表（本文 §1） | `docs/api.md` §3.2、§5 |
| `docs/api.md` §1.3 | 「时间戳：毫秒（`recordDate`、`expiresIn`、`t`）」 | `recordDate`/`expiresDate` 是 **ISO-8601 串**（`recordDate` 时刻恒为零点）；`expiresIn` 是**时长 ms**；只有 `t` 是毫秒 epoch | `docs/api.md` §1.3 |
| `docs/api.md` §1.2 响应形态表 | 缺「`200` + JSON 也可能是**人机拒签**」与网关 `414` | 增两行（`F001` / `URI too long`） | `docs/api.md` §1.2 |
| `docs/signin-probe.md` §1.5 | 「窗口长度：很可能 ~300s ✅」「`expiresIn` 实际传的是 `Date.now()`」 | **实测可只有 20 s**（`expiresIn=20000`）；默认预算 31s 可能超窗，需收紧 | `docs/signin-probe.md` §1.5、§2.1 |
| `docs/signin-probe.md` §0 / §3 人工判读参考 | 无「网关拒请求行」这一类 | 新增判读 `uri_too_long`（强指网关，不是服务端策略） | `probe.go`；两份文档的观测表 |
| `docs/signin-probe.md` §1.2 | 引 `index-new-COcfVClM.js`，无 `getInstance`/`slideStyle` | 已换为 `har#3` 里的 `index-new-dX4pM4CL.js` 原文（多了两个键与 `catch` 分支） | `docs/signin-probe.md` §1.2 |
| `docs/signin-probe.md` §2 阶梯 | 真值档只打一枪 | 失败自动换新参数重取（默认 3 次，`--genuine-attempts`），逐次落 `attempts` | `runner.go`、`report.go`、`main.go` |
| `docs/signin-probe.md` §3 读回 | 只看 `/check-in-student-detail/my` | 补上「UI 实际读 `/checkIn/stu-course-check-in-count`」这条局限与人工核对方法 | `docs/signin-probe.md` §3 |
| `signin.go` `SignInResult` | 注释「未观察到成功响应」；无 `captchaVerifyCode`；`200 + false` 无法与成功区分 | 加 `CaptchaVerifyCode` 字段与 **`SignInResult.OK()`**，注释改为实测形状 | `signin.go` |
| `types.go` `CheckInCount` | 「其余课程信息字段按命名惯例补齐」 | 改注释：实测是**身份字段**（`id/userId/classNo/name/major/unitCode/unitName/grade/studyLevel`）而非 `courseCode` 系；`absentTimeCount` 实测为零值浮点 | `types.go`（结构本身未动，见 §7） |
| `client.go` | 空 body 时**不设** `Content-Type` | `Request.ContentType` 显式覆盖；`SignIn` 与官方请求逐字节一致 | `client.go`、`signin.go` |
| `probe.go` 打码 | 学号留前 4 位、姓名留姓氏 | 学号只留**前 2 + 后 1**（`24*****4`）；姓名**一位不留**，换成 `张三` | `probe.go`、`probe_test.go` |
| `doc.go` 证据来源 | 只列两份失败的签到 | 补上 `har#3` 的成功样本与 `414`/`F001`/20s 窗口 | `doc.go`、`README.md` |

### 6.1 未动的两项（有意）

| 项 | 为何不动 |
| --- | --- |
| `errors.go` 的 `ErrURITooLong` 哨兵 | 目前靠 `StatusCode`/判读层就能归因，还没到需要公开哨兵的时候；先把信号从 `unattributable` 里拆出来 |
| `types.go` `CheckInCount` 的字段集与 `AbsentTimeCount` 类型 | 改字段集/类型会影响库消费者（`int` → `float64` 是破坏性变更），而写入检测并不依赖它。先只把注释改对，等一次专门实测 |

---

## 7. 本次明确**未**证明（照 ADR 0001 的要求列出）

| 项 | 原因 |
| --- | --- |
| **`CaptchaEnforcement`（人机是否强制）** | 本采集**没有**「有效签到码 + 缺失 `captchaVerifyParam`」的尝试；issue #1 的核心问题仍未答 |
| `captchaVerifyParam` 一次性 / 有效期 | 五个样本的 `certifyId` **各用一次**，无重放；只有「`InitCaptcha` 会把上次 `certifyId` 带回」这一个侧证 |
| `F001` 的成因 | 参数是真值（距 init 仅 4.25 s）却被人机拒；风控评分、UA 矛盾、前两次 414 都可能是原因，**不可区分** |
| 遗留端点（`/checkIn/code-check-in`、`/ali-nvc/check-code-analyze`） | 本采集零调用 |
| `coordinate: 0` 的坐标系 | 本采集走 `navigator.geolocation` 分支（`{enableHighAccuracy:true,timeout:5000,maximumAge:0}`，**不含** `coordinate`）；`coordinate:0` 仍只在钉钉 `device.geolocation.get` 分支（📖 源码） |
| `distance` 超限是否拒签 | 成功响应不含距离（本文 §1.2） |
| **本次是否真的写入了 `CheckInRecord`** | 第 111 条 `rightCount:1` 只在**成功后**读了一次，**无基线**；成功 + 跳转 `/sign/in/detail` 是强旁证，但不是写入的直接证明 |
| 钉钉客户端的人机形态 | 本采集是浏览器；钉钉侧「静默」为所有者陈述，非本 HAR 证据 |
| 414 的确切长度阈值 | 只有 5 个数据点，只能给出区间（请求行 `[5615, 27838]`）；`413` 完全未实测 |

---

## 8. 打码规则与复现方式

### 8.1 本文打了哪些码

| 对象 | 处理 |
| --- | --- |
| `X-Auth-Token`、`skl-ticket`、`Cookie` | **永不粘贴**（沿用 [`signin-probe.md` §4.4](./signin-probe.md)） |
| `deviceToken`、`data` | 只留长度 |
| **学号** | 只留**前 2 位与最后 1 位**：`24*****4` |
| **人名** | **一位不留**，统一换成 `张三`（不用「姓氏 + `*`」这种半遮） |
| **课程** | `courseName` / `courseId` / `courseSchemaId` 全部换成占位符 |
| **日期与钟点** | 字段值用 **Go 参考时间格式**（`2006-01-02T15:04:05.000Z`）；时序用 `t+<秒>` 相对偏移；只保留**差值/时长** |
| `CheckInRecord` 主键、教师工号、签到码 | 占位符（`<记录主键，已打码>` / `<教师工号，已打码>` / `<有效码>`、`<无效码>`） |
| `certifyId` | 按**同一映射**换成 `c1`…`c7`（同一占位符 = 同一个值，所以「第 99 条带回了第 83 条的值」这条证据仍在） |
| 围栏中心坐标 | 真实 16 位有效数字 → 6 位 |
| 上报定位 | 保留原值（它就是请求里发出去的 5–6 位小数） |
| SDK 版本、`StaticPath`、参数长度、响应头、状态码 | 保留（协议事实，不指向人） |

> 「采集 id」保留为一个**文件名**（`har#3` = `skl.hdu.edu.cn2.har`）而不是日期：
> ADR 0001 要求标注结论出自哪一次采集，文件名足够满足这一点，而日历日期本身就是可追踪信息。

**打码的判据只有一条：这份内容会进 git 才需要打码**（详见
[`signin-probe.md` §4.4](./signin-probe.md)）。脚本据此把打码放在**落盘的 `md` 草稿**
上，终端输出**不打码**（含真值，供当场核对，且不得整段外传）；`*.har` 与
`probe-results/*.json` 是本地原始证据，不打码。本文与其它 `docs/**`、`README.md`、
`*.go` 注释会持久化，因此上表的打码是**必须**的。

### 8.2 复现

```bash
# 1) 只看骨架：条目号 / 相对时刻 / 状态 / 原始 URL 长度（不加载 body）
python3 - <<'EOF'
import json, datetime
from urllib.parse import urlsplit
d=json.load(open('skl.hdu.edu.cn2.har'))
es=d['log']['entries']
t0=datetime.datetime.fromisoformat(es[0]['startedDateTime'].replace('Z','+00:00'))
for i,e in enumerate(es):
    r,resp=e['request'],e['response']
    if 'hdu.edu.cn' not in r['url']: continue
    dt=(datetime.datetime.fromisoformat(e['startedDateTime'].replace('Z','+00:00'))-t0).total_seconds()
    print(f"[{i:3d}] t+{dt:7.3f}s {resp['status']:3d} "
          f"urlLen={len(r['url']):6d} {urlsplit(r['url']).path}")
EOF
```

```bash
# 2) 取单条请求/响应的形状（含 captchaVerifyParam 的四键结构与各字段长度）
#    换出想要的下标即可；不要打印 deviceToken / data 的完整值
python3 - <<'EOF'
import json
from urllib.parse import urlsplit, parse_qsl
d=json.load(open('skl.hdu.edu.cn2.har'))
for i in (1,6,10,98,101):
    e=d['log']['entries'][i]
    q=dict(parse_qsl(urlsplit(e['request']['url']).query))
    p=json.loads(q['captchaVerifyParam'])
    print(i, e['response']['status'],
          {k:(len(v) if isinstance(v,str) else v) for k,v in p.items()},
          e['response'].get('content',{}).get('text','')[:120])
EOF
```

脚本输出里仍是真实值（HAR 在本地、已 gitignore），**要粘贴进仓库前先按 §8.1 打码**。
