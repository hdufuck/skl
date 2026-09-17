# 签到探针手册：判定 `CaptchaEnforcement` 并验证库的签到封装路径

本文是**唯一**的签到实验文档，取代旧的 `signin-experiment.md`，并吸收了一份
未入库的浏览器取参研究草稿。它同时承担三件事：

1. 当前认知总纲（契约、参数形状、风控形态、窗口长度）；
2. `cmd/signinprobe` 的操作手册（预置、相位、读回记录、落盘）；
3. 浏览器取参（chromedp）的技术附录。

> **只能做一次。** 只能用真实有效的 `SignInCode` 判定，而它由现场生成、有效期未知、
> 无法事后复现；实验本身会写入真实 `CheckInRecord`。窗口之前必须把第 4.1 节的预置
> 全部练完。相关决定见 [`adr/0002`](adr/0002-本机探针与浏览器取参的取舍.md)。

## 📱 抓包端配置速查（完整步骤见 [§4.3](#43-抓包端要做什么逐步)）

Reqable 手机 App 有两种模式，**上报服务器要配在「流量真正被捕获的那一端」**：

| 手机 App 侧边栏顶部 | 模式 | 在哪配 |
| --- | --- | --- |
| 显示已连接电脑（如 `veno-macbook 172.16.51.105:9000`）、`记录模式 (VPN)` 变灰 | **协同模式**（手机流量转发到电脑） | **电脑端** Reqable |
| 未连电脑、`记录模式 (VPN)` 可用 | **独立模式**（手机自己抓） | **手机端** Reqable |

两者都是：新建一条上报规则 → URL 匹配 `*captcha-verify*` → 服务端地址指向脚本打印的 hook。

- **电脑端**（协同模式，推荐）：Reqable → **工具 → 报告服务器**；
  地址用 `http://127.0.0.1:8080/hook`（电脑与脚本同机）。
- **手机端**（独立模式）：Reqable → **⋮ → 更多 → 上报服务器**
  （需 Reqable **≥ v2.20.0**）；地址用 `http://<Mac局域网IP>:8080/hook`。
- 需要登录一个免费 Reqable 账号（Community 档 1 条上报规则足够）。

**窗口内**：脚本打印「现在请在手机上完成一次官方签到」后 → 用钉钉打开该课程
签到页 → 输入同一个 4 位签到码 → 提交（人机静默完成，无滑块）。

> 若手机 App 里**找不到「更多 / 上报服务器」**：先看是不是协同模式（上表），
> 再看 Reqable 是否 ≥ v2.20.0。仍找不到就把菜单截图发给维护者，改这一节。

## 0. 判据与证据分级

等级沿用 `docs/api.md` 的约定：✅ 已实测 / 📖 源码 / ⚠️ 未证实。

| 判据 | 强度 |
| --- | --- |
| 阶梯中「未携带真凭证」的档位让**到课**记录增加（`rightCount`） | **强**（唯一的干净归因来源） |
| 响应体明确指向风控（`captchaVerifyResult===false`、`captchaVerifyCode==="F001"`） | **强**（但只证明「阿里云风控拒了」，见 §0.1） |
| 响应体明确指向参数层（活路径 `400` + 参数缺失/非法） | **强** |
| 真值档（官方 SDK 参数 + 库 `SignIn`）成功 | **强**（证明库的封装路径可用） |
| `414` + `text/plain` `URI too long`（带 `X-Kong-Response-Latency`） | **强指网关**：请求行超长，应用层没收到 —— 既不是人机层也不是参数层，必须单独判。`413` 同类但未实测 |
| 遗留端点 `/checkIn/code-check-in`、`/ali-nvc/check-code-analyze` 成功 | 强（证明不强制）；**失败不可解释**（单边证据） |
| 本机发出的探针失败 | **弱**：可能是客户端指纹/WAF 导致，不足以单独定论（见 ADR 0002） |
| `401 签到码不存在` | **无**：签到码校验先于风控校验 |
| `200 + 空 body`、超时、文案不明 | 无（工具/网络层） |

**归因规则**：本机探针与手机端官方客户端结论冲突时，**以手机端为准**。

### 0.1 阿里云验证码错误码（原文摘要）

**证据等级：📖 官方文档**（阿里云《客户端返回数据说明》，由本轮手抄摘要；仓库里不留原始链接，
但码值本身在 `har#4` 的响应体里可交叉验证：`F001` / `F002` / `F014` 都实测到了）。

`captchaVerifyCode` 是**阿里云验证码**的码（不是 skl 的）。判定 F001 时按官方措辞读，
**不要**读成「人机层单独拒签」：

| 码 | 官方含义 |
| --- | --- |
| `T001` | 客户端校验通过 |
| `T005`/`T006` | 控制台测试模式 / 白名单 |
| `F001` | **疑似攻击请求，风险策略不通过** |
| `F004` | 控制台测试模式判不通过 |
| `F008` | 验证数据重复提交（同一笔只允许提交一次） |
| `F009` | **检测到虚拟设备环境**（vmware/virtualbox/…、模拟器、冒牌浏览器、桌面浏览器模拟移动设备） |
| `F010` | 同 IP 访问频率超限 |
| `F011` | 同设备访问频率超限 |
| `F014` | **无初始化记录**（间隔超 20 分钟或不存在初始化记录） |
| `F015` | 验证交互不通过 |
| `F016` | URL 验证策略 |
| `F017` | 协议或参数异常 |
| `F022` | V3 加密模式校验失败 |
| `F024` | **检测到自动化脚本模拟点击、滑动** |
| `F025` | Qwen 大模型智能分析检出的异常请求 |

> 服务端侧另有一个不属于这张表的码：`F002` = `CaptchaVerifyParam` 参数为空
> （`har#4` 里「缺失参数」那档实测到它）。

## 1. 当前认知（事实）

### 1.1 三条签到路径 ✅/📖

| 路径 | 形态 | 现行前端里的地位 |
| --- | --- | --- |
| `POST /api/ali-nvc/captcha-verify` | query：`captchaVerifyParam`、`userid`、`code`、`latitude`、`longitude`、`t`(ms)；body 为空 | **唯一活着的路径** ✅ |
| `GET /api/checkIn/code-check-in` | `code`、`id`（`latitude`/`longitude` ⚠️） | axios 里有定义，**零调用者** 📖 |
| `GET /api/ali-nvc/check-code-analyze` | `userid`、`code`、`t`、`token`、`a`、`callback`(JSONP)，**完全不传定位** | 只被 `/sign/location` 调用，而该路由**不可达**；且它传的 `code` 是定位就绪标志（布尔），与签到码无关 📖 |

`a=0` 表示「未做人机验证」（`e.enable === false` 时前端直接拼 `0`）。

> ⚠️ 工具**不再调用** `check-code-analyze`：已确认它即使拿到有效签到码也只回
> `{"result":{"code":800}}`（被拒），且失败不可解释。它仍保留在
> `pkg/signin.Analyze` 里作为可显式调用的路径，但不进探针阶梯。

### 1.2 `captchaVerifyCallback` 契约 📖 + ✅

`/sign/in` 路由懒加载 `assets/index-new-dX4pM4CL.js`（**`har#3` 抓包的版本**；
本手册早期引的 `index-new-COcfVClM.js` 已被上游换掉），其初始化原文：

```js
window.initAliyunCaptcha({
  SceneId: "2q42bw25", prefix: "cr5a57", mode: "popup",
  element: "#captcha-container", button: "#captcha-trigger-btn",
  captchaVerifyCallback: R, onBizResultCallback: L,
  getInstance: a => { k.value = a },
  slideStyle: { width: Math.min(360, window.innerWidth - 40), height: 50 },
  language: "cn"
});

const R = async a => {
  try {
    const i = { captchaVerifyParam: a, userid: B.value?.id, code: s.value,
                latitude: u.value, longitude: d.value, t: Date.now() };
    const g = (await X.post("/ali-nvc/captcha-verify", null, { params: i })).data;
    g.checkCodeDto && f.setSignDetail(g.checkCodeDto), Z.closeToast();
    return { captchaResult: g.captchaVerifyResult, bizResult: true };
  } catch (e) {
    // 失败路径：把 msg 弹 toast，并告诉 SDK「人机没问题、业务失败」
    return { captchaResult: true, bizResult: false };
  }
};
const L = a => { a && z.replace("/sign/in/detail") };
```

要点：

- 页面拿到的回调入参 `a` **原样**作为 `captchaVerifyParam` 提交，不做任何加工 ✅。
- 与早期版本相比多了 `getInstance` 与 `slideStyle` 两个键（前者是取参就绪信号，
  见附录 A 的踩坑）；`catch` 分支返回 `{true, false}` 而不是 `{false, true}`。
- `onBizResultCallback(true)` **只在 `captchaVerifyResult === true` 时**才被 SDK 调用
  ⟹ 跳 `/sign/in/detail` 的条件就是「服务端判 true」（不是 HTTP 200）。
  收到 `false` 时 SDK 会 `reInitCaptcha` 重开人机验证 —— 抓包第 98→101 条
  就是「`F001` → 重开 → 再提交 → `T001` 成功」。
- `{true, undefined|true}` = 成功；`{true, false}` = 失败 + `reInitCaptcha`；
  `false`/`undefined` = 提示 + `reInitCaptcha` 📖（分支表见 §3 末尾）。
- `onFallback` 给的降级参数**没有 `data`**，不要当正常参数用 ⚠️。

### 1.3 参数形状与生命周期

```json
{"sceneId":"2q42bw25","certifyId":"kVBJ80iOKt","deviceToken":"V0VCI2Fi…","data":"JRMlgg1E…"}
```

- `certifyId` 来自 `cr5a57.captcha-open.aliyuncs.com` 的 `InitCaptcha`；
  `deviceToken` 来自设备指纹采集；`data` 是 SDK 内部混淆后的风控载荷。
  三者均由阿里云侧签名、与 SceneId 和域名绑定，**纯 Go 无法合成** 📖。
- **只有客户端 JS 能生成它**；阿里云没有任何语言的客户端生成 SDK。
  Go 的 `alibabacloud-go/captcha-20230305` 是**服务端校验** SDK
  （`VerifyIntelligentCaptcha`），只把它当输入 📖。
- **一次性**：重放返回 `F008`（V3 下 `F018`）；初始化后 20 分钟失效；
  V3 要求「行为验证 → 业务验签」间隔 ≤ **90 秒**（`F019`）📖。

### 1.4 人机形态：TRACELESS，无滑块 ✅

用 `Fetch.fulfillRequest` 在**真实源** `https://skl.hdu.edu.cn/index.html` 下交付极简页、
加载官方 SDK 并以真实 `SceneId`/`prefix` 初始化，实测：

| 配置 | `CaptchaType` | 是否拿到参数 |
| --- | --- | --- |
| headless + 移动端 Safari UA | `TRACELESS` | ✅ len≈1690 |
| headless + 默认 UA（未伪装） | `TRACELESS` | ✅ len≈1694 |

三次独立运行全部 `TRACELESS`，`navigator.webdriver=false`。
⟹ **没有滑块**；但 `initAliyunCaptcha` 只做初始化，**必须点一次触发按钮**才有参数 ✅；
而且必须等 **`getInstance` 回调**（SDK 把构造完成的实例交回来，实测 init 后
300–550ms）之后才能点——更早的点击会被直接丢掉（不是「没反应」，而是那时按钮上
根本没有点击处理器）✅。

> ⚠️ **上表只回答「能不能拿到参数」，不回答「参数能不能被接受」。**
> 早期把它读成「UA 伪不伪装都无所谓」是读错了对象：`har#4` 里探针每次铸造参数与
> 上报设备指纹都带着 `HeadlessChrome/…` 与 headless 默认的 800×600 / dpr 1 屏幕，
> 而窗口是手机尺寸 —— 这正是 `F009` 点名的「桌面浏览器模拟移动设备」。
> 现在预热会自动把自称换成一台自洽的桌面 Chrome（附录 A.2），
> 决定见 [`adr/0003`](adr/0003-浏览器自称与真实平台自洽.md)。

风险 ⚠️：`TRACELESS` 是风控评分结果，会随 IP/时间/频次/设备指纹变化；
阿里云有 `F024`「检测到自动化脚本模拟点击、滑动」，自动点击理论上可命中。

### 1.5 窗口长度：实测可以只有 **20 秒** ✅

教师端生成签到码**没有有效期下拉**；前端兜底值是 **300 秒**、上限 3600 秒，
真实值来自后端 `expiresIn`/`expiresDate`（`POST /checkIn/create-code`）。
前端解析函数把 ≤300 当「秒」、≤300000 当「毫秒」、更大当「时间戳」📖。

**`har#3` 的浏览器抓包给出了第一个实测值**：`checkCodeDto.expiresIn=20000`、
`expiresDate=10:32:00.685Z`，反推签到码创建于 `10:31:40.685Z`，成功提交于
`10:31:49.900Z` —— 学生只剩 **10.8 秒**，中间还被人机拒了一次重来。

⟹ `expiresIn` 是**时长（毫秒）**，不是时间戳（旧文档此处写反了）。
⟹ **不能再假设窗口宽裕**：脚本的默认预算是 `8s（阶梯）+ 23s（真值档）= 31s`，
比一个 20 秒的窗口还长。窗口前按 `--ladder-deadline` / `--captcha-deadline`
自己收紧（例如 `4s + 12s`），或先把真值档的取参链路演练到稳定。
真值档现在默认最多跑 3 次（每次重取一个新 `captchaVerifyParam`），见第 2 节。

## 2. 角色分工与阶梯

三个消费者，职责不重叠：

| 消费者 | 提供什么 |
| --- | --- |
| **前置三档（本机 Go）** | 复现「遗留 `code-check-in` / 缺失凭证 / 伪造凭证」三条请求形状，并把每档之后的考勤记录原样记下来 |
| **真值档（chromedp 真值 → 库 `SignIn`）** | 回答「库的 `SignIn` 封装路径能否走通」+ 取得活路径成功样本 |
| **手机（钉钉 + Reqable）** | 独立的、**权威的**官方成功样本（acceptance criterion 的保险） |

阶梯按「越依赖人机越靠后」排列，顺序即开火顺序：

| # | 档位 ID | 请求 | 凭证 |
| --- | --- | --- | --- |
| 1 | `code-check-in` | `GET /checkIn/code-check-in`，带定位 | 无 |
| 2 | `captcha-verify-missing` | `POST /ali-nvc/captcha-verify` | **缺失** |
| 3 | `captcha-verify-forged` | 同上 | **伪造**（结构合法、等长） |
| 4 | `captcha-verify-genuine` | 同上，走库的 `SignIn` | 官方 SDK **真值**（失败则换新参数，最多 3 次） |

**顺序可以用 `--ladder` 改**（`all`｜`genuine`｜`junk`｜逗号分隔的档位 ID）：
前置三档会向同一个 `userid`+`scene` 打进去几次风控不通过的提交，紧接着就是真值档，
是「真值档为什么 F001」的混淆因子。**真窗口建议 `--ladder genuine`**（只跑真值档，
把前置三档留给 `--no-browser` 的演练），这样报告里那一条 T001 就是干净的。

### 2.1 时间预算（T0 = 签到码输入完成）

| 相位 | 预算 | 超时行为 |
| --- | --- | --- |
| 前置三档 | ≤ 8s | 跳过剩余、继续 |
| 真值档（浏览器取参 + 提交，含最多 3 次重取） | ≤ 23s | 放弃浏览器、优先保手机 |
| 手机官方签到 | ≥ 7s | — |
| 等 Reqable 上报 | ≤ 10s | 记 `hookMissing: true`，不阻塞 |

> ⚠️ 上面的默认值合计 **31s**，而 `har#3` 实测过一个 **20s** 的窗口（见 1.5）。
> 真窗口比 31s 短时，靠 `--ladder-deadline` / `--captcha-deadline` 收紧；
> 真值档的 `--genuine-attempts`（默认 3）也直接吃这段预算。

### 2.0 真值档为什么要重取参数

`har#3` 抓包的完整因果链（三段提交才成功一次）：

| 提交 | `CaptchaType` | 参数总长 | 结果 |
| --- | --- | --- | --- |
| 第 6 条 | `TRACELESS` | 27998 | **`414 URI too long`**（网关，未达应用） |
| 第 10 条 | `TRACELESS` | 26806 | **`414 URI too long`**，同上 |
| 第 98 条 | `TRACELESS` | 4278 | `200 {"captchaVerifyResult":false,"captchaVerifyCode":"F001"}` |
| **第 101 条** | **`CHECK_BOX`** | 4442 | **`200 T001` 成功** |

两种失败换一个新参数都大概率能过（官方 SDK 自己也在 `F001` 后 `reInitCaptcha`），
所以真值档现在**只在**这两种观测上重取：HTTP `414`（`413` 同类），或 `200` + 人机判定 false。
前者是**长度彩票**（换一个参数的 `data` 会重掷一次），后者只是照做官方 SDK 的动作——
`F001` 的成因至今不可归因（见第 5 节）。
重取次数、每次的 URL 长度与失败原因都写进报告的 `attempts`。

> 另：`CaptchaType` 是每次 `InitCaptcha` 由阿里云**现判**的，同一次会话里会变。
> `har#3` 那次是 `TRACELESS` → `F001` → 升级成 `CHECK_BOX`（显式勾选）才成功。
> **那个升级是浏览器路径的现象**；钉钉客户端侧一直是静默的。

浏览器在 T0 前**已预热**（页面加载、SDK 初始化完成），T0 后只点一次触发按钮
（≈2–5s 出参）。

### 2.2 不做判读、不做闸门

工具**只记录**：每档请求之后把当时的今日考勤记录原样抄进报告，不判成败，
也不因写入而停。一次真实窗口的代价太高，默认把前置三档 + 真值档全部打完，
由人事后看报告。

> 只想要前三档就加 `--no-browser`；工具不再有写入闸门 / `--stop-after-write`。

## 3. 读回：只记录，不判读

- 每档请求之后调用 `GET /api/check-in-student-detail/my?startDate=<今天>&endDate=<今天>`，
  把返回的**原始 JSON 数组**原样记进该档的 `afterRequest`（`.md` 草稿按 §4.4 打码）。
  不解析、不比对、不判成败。
- T0 前另记一次基线条数（`baselineCount`）。
- 元素形态从未实测（HAR 里恒为 `[]`；真实窗口里观察到过 1 条且**没有 `id`**、状态未知），
  所以工具刻意不去解释它。
- 事后若想判「这一档是否真的签到成功」，权威信号是另一条：
  `GET /api/checkIn/stu-course-check-in-count?courseId=<id>` 的 `rightCount`
  （前端标签「正常」）增加。`har#3` 抓包第 111 条：签到成功后返回 `[{"rightCount":1,…}]`。
  ⚠️ 窗口开启本身就可能给相关学生生成一条**非到课**记录，因此「明细多了一条」
  **不等于**签到成功（首跑那次就是这条假阳性，见附录 B）。

人工判读时可以参考这些观测（工具**不再**自动产出结论）：

| 观测 | 含义 |
| --- | --- |
| 无真凭证档让 `rightCount` 增加，且该档响应自身表明成功 | 该路径**不强制**人机验证 |
| `captchaVerifyResult===false`（或 `captchaVerifyCode==="F001"`）、文案含「人机/滑块/验证码」 | 指向**风控**（`F001` 的官方措辞是「疑似攻击请求，风险策略不通过」，见 §0.1） |
| 活路径 `400` + 参数缺失/非法 | 指向参数层 |
| `401` 文案含「签到码」 | 签到码校验先于风控，无信息 |
| `200` + 空 body | skl-ticket 重放或限流（网关/工具层） |
| `414` + `text/plain` `URI too long` | **网关**拒了请求行，应用层没收到 |
| 明细多了一条但**不是到课** | 多半是窗口开启生成的占位记录，不可归因 |

## 4. 操作手册

### 4.1 窗口前预置（全部可在无效签到码上演练，零风险）

1. **环境**：macOS 上装好 Google Chrome；`go build ./cmd/signinprobe`。
2. **凭据**：`export HDU_USER=… HDU_PASS=…`（或已有 `SKL_TOKEN`）。
3. **定位**：默认写死 `30.313816, 120.343228`（覆盖杭电教学楼 2km 半径），
   可用 `--lat/--lon` 或 `SKL_LAT/SKL_LON` 覆盖。
4. **伪造样本**：把一份含真实 `captchaVerifyParam` 的 HAR 放在当前目录，
   脚本会自动提取并让伪造值等长（也可 `--sample-file`）。
5. **Reqable 上报服务器**（完整步骤见 4.3）：按抓包模式二选一——
   - 协同模式（手机连电脑）：**电脑端** Reqable → 工具 → 报告服务器 → 添加配置；
   - 独立模式（手机自抓）：**手机端** Reqable → ⋮ → 更多 → 上报服务器（需 ≥ v2.20.0）。
   规则都填：URL 匹配 `*captcha-verify*`；接收地址填脚本打印的 hook 地址
   （电脑端 `http://127.0.0.1:8080/hook`，手机端 `http://<Mac局域网IP>:8080/hook`）。
   需要登录一个免费 Reqable 账号（Community 档 1 条规则足够）。
6. **演练**：用**无效**签到码完整跑一遍脚本，确认
   - 读回端点能解析（打印出「读回预热成功」）；
   - 前置三档都在 8s 内返回 `401 签到码不存在`；
   - **真值档也拿到了 HTTP 状态**（无效码同样是 `401 签到码不存在`）——
     只看到「官方验证码 SDK 已就绪」不算通过：那条日志只证明预热成功，
     不证明 `New` 返回之后浏览器还活着；
   - 手机上报能在 10s 内到达（`hookMissing` 为 false）。
   演练会实际发出探针请求，但无效签到码不会写入任何记录。
   真值档若连 HTTP 状态都没拿到，脚本会额外打印
   「⚠ 真值档是 transport_error：请求根本没发出去」，照它修链路再进窗口。

### 4.2 T0 流程

```bash
go run ./cmd/signinprobe            # 默认：headless=new + 桌面 Chrome 自称、hook :8080、全部四档
# 真窗口推荐（只跑真值档，避免前置三档污染 F001 归因）：
#   go run ./cmd/signinprobe --ladder genuine
# 可选：--headed  --profile <目录>  --no-browser  --hook ""  --out probe-results
#      --ladder all|genuine|junk|<档位ID列表>  --mobile  --ua '<UA 字符串>'
#      --client-ua browser|'<UA 字符串>'  （默认：项目自报名，不对齐）
#      --ladder-deadline 4s  --captcha-deadline 12s  --genuine-attempts 2
```

补充说明：

- **自称默认是「一台自洽的桌面 Chrome」**：UA 取自本机真 Chrome 去掉 `HeadlessChrome`
  标记，客户端提示（`Sec-CH-UA*`）与屏幕几何（1280×832 @2x）都跟真实值一致，不碰触摸。
  `--mobile` 换成 Android 手机自称（UA、客户端提示、430×932 视口、触摸一起换）；
  `--ua` 直接给一串 UA（例如手机端钉钉那串，配 `--mobile` 用）。
  为什么这样选见 [`adr/0003`](adr/0003-浏览器自称与真实平台自洽.md)。
- **预热会多等一步**：等设备指纹上传（cloudauth-device 的 Log2/Log3）落地才宣布「可以点了」，
  免得 certifyId 引用的设备记录还没落库就去提交。它发生在 T0 之前，不占窗口预算。
- **默认就复用持久化 profile**（`$XDG_CACHE_HOME`/`~/Library/Caches` 下的
  `signinprobe/chrome-profile`），让设备指纹「热」起来；`--profile` 可改路径。
- 签到码**主路径是 stdin 交互输入**；`--code <4位>` 只是给演练/自动化用的显式覆盖
  （签到码本身无隐私，见 Q6），真实窗口建议仍用交互输入。
- `--no-browser` 只跑前置三档（演练用，不需要 Chrome）。

T0 后的时序：

1. 脚本登录、预热读回、预热浏览器、起 hook 服务，打印 Reqable 接收地址；
2. 提示 `请输入老师公布的 4 位签到码（输入后立即开始计时）`；
3. 你输入 4 位码 → **T0**；
4. 前置三档自动打完（约 3–5s），每档之后记录一次当时的考勤记录；
5. 真值档：浏览器点触发按钮 → 静默出参 → 库 `SignIn` 提交；
6. **脚本提示「现在请在手机上完成一次官方签到」** → 你立刻去手机操作（见 4.3）；
7. 最多等 10s 收手机 HAR；
8. 输出 `probe-results/<时间戳>.json`（原始、gitignored）与 `.md`（脱敏草稿）。

### 4.3 抓包端要做什么（逐步）

#### 先判断模式

看手机 Reqable 侧边栏顶部：

- **显示已连接电脑**（例如 `veno-macbook 172.16.51.105:9000`）、`记录模式 (VPN)` 是灰的
  → **协同模式**：手机流量经电脑端的 Reqable 出去，捕获在电脑端，
  **上报服务器要在电脑端配**。
- **未连电脑**、`记录模式` 可选 VPN → **独立模式**：手机自己抓，上报服务器在手机端配。

> 这是最容易踩的坑：**协同模式下手机端根本不会出现「上报服务器」入口**。
> Reqable 官方文档只写了移动端 `⋮` → `更多` 那条路径（且需 ≥ v2.20.0），
> 没有区分两种模式。

#### 前置（窗口前做完）

1. 确认证书已装好、能解密 HTTPS（协同模式会把电脑根证书同步到手机，装一下即可）。
2. 登录一个免费 Reqable 账号（新建上报规则需要账号，Community 档允许 1 条）。
3. 新建上报规则：
   - **电脑端（协同模式，推荐）**：Reqable → 工具 → 报告服务器 → 添加配置。
     - 名称：`skl-captcha`
     - URL 匹配：`*captcha-verify*`
     - 服务端地址：`http://127.0.0.1:8080/hook`（脚本与电脑端同机）
     - 压缩：`gzip`（或 `none`）。脚本能解 gzip/deflate；**不要选 brotli/zstd**，
       这两种会记一条「不支持的压缩算法」日志并被忽略。
   - **手机端（独立模式）**：Reqable → ⋮ → 更多 → 上报服务器 → 新建（需 ≥ v2.20.0）。
     - 服务端地址改成 `http://<脚本打印的Mac局域网IP>:8080/hook`
     - 手机必须与 Mac 同一局域网。
4. 在手机钉钉里打开 skl 签到页，保持登录态。

#### 窗口内

1. 脚本打印「现在请在手机上完成一次官方签到」后，进钉钉进入该课程的签到页；
2. 输入**同一个 4 位签到码**；
3. 点提交（人机验证会静默完成，无需滑块）；
4. 看到签到成功后**不用管脚本**——Reqable 会把那条 `captcha-verify`
   请求/响应以 HAR 格式 POST 给脚本，脚本自动并入报告。

没收到上报时：先确认「规则配在了真正捕获流量的那一端」（见上），再查 URL 匹配规则、
地址里的 IP/端口；桌面端 `127.0.0.1` 若不通，改用 `http://<Mac局域网IP>:8080/hook`。
原始抓包始终在 Reqable 里，可事后人工抄录（只抄响应体即可）。

### 4.4 脱敏规则（照抄进提交物）

**打码的判据**：会进 git 的内容才需要打码。脚本把这条判据落在「**落盘的草稿**」上，
而**不**落在终端输出上 —— 终端是给你当场核对真值用的：

| 内容 | 会进 git | 打码 |
| --- | --- | --- |
| 终端输出（`logf` 那些） | 否（瞬时） | **不打码**：含真实姓名/学号，方便核对「是不是本人、是不是本次窗口」 |
| `probe-results/*.json`（原始报告） | 否（gitignore） | **不打码**：它是原始证据，只在本机 |
| `probe-results/*.md`（脱敏草稿） | 否，但**它是往 `docs/` 抄的原料** | **打码**，规则与本仓库文档一致 |
| `docs/**`、`README.md`、`*.go` 注释 | 是 | **打码** |
| `*.har`、`.env`、`token.txt` | 否（gitignore） | 不管 |

> ⚠️ **不要把脚本的终端输出整段复制出去**（issue、群、文档都不要）。
> 那一份是**未打码**的：真实姓名、学号、课程、精确时间、完整响应体都在里面。
> 要带走就用 `probe-results/<时间戳>.md` —— 它已按本节的规则打码。
> 脚本启动时也会把这条提示打在终端上。

草稿里实际被打码的字段（`probe.RedactBody` / `probe.MaskID`）：学号（只留前 2 后 1）、
`teachName`/`teacherName`/`teacherId`、`courseName`/`courseId`/`courseSchemaId`、
考勤记录主键（响应体里的 `id`、读回 diff 里的 `id:` 标识）、`expiresDate`/`recordDate`
（换成 Go 参考时间格式）、**运行时刻**（草稿抬头不再写日期，精确时间看文件名或 `.json`）、
以及全部会话凭据。**签到码、周次、经纬度、参数长度不打码**：签到码本身无隐私（见 §4.2），
其余是协议事实。

提交前必查：

- `X-Auth-Token`、`skl-ticket`、`Cookie`、`token=`、`sessionId` **永不粘贴**；
- `deviceToken` 只留长度与前 20 字符；
- `captchaVerifyParam` 的 `sceneId`/`certifyId` 可留，`data` 只留前 20 字符；
- 人名、学号、课程名/`courseId`/`courseSchemaId`、**具体日期与钟点**一律不入库
  —— 时间值用 Go 参考时间格式（`2006-01-02T15:04:05.000Z`）占位，
  时序用相对偏移，文档里的采集出处用采集编号（`har#1`/`har#2`/`har#3`，
  图例见 `doc.go` 的证据来源）。可照本文件所在的仓库自查：

  ```bash
  # 应在 docs/ README.md *.go 里零命中
  git grep -nE '2026-0[0-9]|<真实课程名>|<真实学号>|<真实姓名>'
  ```

### 4.5 落盘

窗口结束后：

1. 打开 `probe-results/<时间戳>.md`，逐字核对；
2. 按判读结果升级 `docs/api.md` 的对应条目（把 ⚠️/📖 改成 ✅），
   并**逐字引用**最小必要片段（成功响应全文、请求形状、`captchaVerifyParam` 首段）；
3. 把本次结论与「未证明」项补回本文第 5 节；
4. 报告里**不提交任何 HAR**：只保留「如何获取」（即本文）。

## 5. 本次明确不证明

| 项 | 原因 |
| --- | --- |
| **`CaptchaEnforcement`（人机是否强制）** | `har#3` 的采集**没有**「有效签到码 + 缺失 `captchaVerifyParam`」的尝试；只证明了「有效码 + 人机不通过」= `200 F001` |
| `captchaVerifyParam` 一次性 / 有效期 | 5 个 `certifyId` 各用一次，无重放；只能确认 `InitCaptcha` 会把上次的 `certifyId` 带回去（`reInitCaptcha`） |
| 人机判 `F001` 的成因 | 参数是真值（距 init 仅 4.25 s）却被人机拒；官方措辞只是「疑似攻击请求，风险策略不通过」（见 §0.1），风控评分、环境自称、前两次 414 都可能，**不可区分**。`har#3` 里一台真桌面 Edge 也先吃过一次才成功 ⟹ 环境自称缺陷**不是充分原因**。本轮已把能看见的自相矛盾去掉（附录 A.2），这仍然只是「没理由不修」，不是因果 |
| 本次成功是否**真的写入**了记录 | 成功后的 `rightCount:1` 只在成功后读了一次，**无基线**；成功 + 跳转 `/sign/in/detail` 是强旁证而非写入证明 |
| `414` 的确切阈值 | 只有 5 个数据点，可证 `5615 ≤ 请求行上限 < 27839`（字节）；`413` 未实测 |
| 服务端是否校验 `t` | 需要专门探针，且不影响库的形态 |
| `coordinate: 0` 的坐标系语义 | 需要教师端 `distance` 列；且浏览器路径根本不传它（走 `navigator.geolocation`） |
| `distance` 超限是否拒签 | 需伪造远端坐标，且已由项目所有者确认，无证据债 |
| 遗留端点「失败」的归因 | 单边证据：成功才算证明；失败可能是请求形状本来就不对 |
| 本机探针失败的因果归因 | 客户端指纹/WAF 与「服务端策略」不可区分（ADR 0002） |

## 附录 A：chromedp 取参技术细节

**方案**：不在 Go 里重实现任何协议；启动真 Chrome，用 CDP
`Fetch.fulfillRequest` 在**真实源** `https://skl.hdu.edu.cn/index.html` 下交付一个极简页，
加载官方 `AliyunCaptcha.js`，用真实 `SceneId=2q42bw25` / `prefix=cr5a57` 初始化，
在 `captchaVerifyCallback` 里把参数存到 `window.__captchaVerifyParam`，
再用 **CDP 输入事件**（受信任点击，不是 JS `el.click()`）点一次
`#captcha-trigger-btn`，轮询取值。

**为什么这样**：`captchaVerifyParam` 只能由客户端 JS 生成，且与源/场景绑定；
把极简页交付在真实源下即可满足绑定。用真 Chrome 而非模拟器（符合 ADR 0002 的底线）。

**兜底**：同时挂 `network.EventRequestWillBeSent`，从
`/api/ali-nvc/captcha-verify` 的完整 URL 里 parse query 作为交叉校验。

**踩坑**：

- chromedp 用 `exec.CommandContext(ctx)` 起 Chrome，**首次 `chromedp.Run` 的 ctx
  就是浏览器的生命周期**：把它挂在一个带超时的子 ctx 上、再在 `New` 返回时
  `defer cancel()`，浏览器会在预热成功的那一刻被杀掉，之后每次取参都只能拿到
  `触发验证码失败: context canceled`（真值档退化成 `transport_error`）。
  启动预算要用看门狗（超时才 `Close`）表达，首次 Run 必须直接跑在浏览器自己的
  ctx 上；反过来，`Param` 那层的 rung 预算取消的是子 ctx，不会连带杀掉浏览器。
- `initAliyunCaptcha` 返回 ≠ 可以点：SDK 是在 `init`/`bindEvents` 之后才通过
  `getInstance` 把实例交回来的（实测 init 后 300–550ms）。就绪标志必须挂在
  `getInstance` 上；挂在 `initAliyunCaptcha` 返回之后，T0 后的第一次点击会落在
  空处，真值档一路超时、退化成 `transport_error`（演练表格里就是一个「-」）。
  `Param` 另有「3s 没出参就补点一次」的兜底。
- 反过来，**就绪之后点击很快**：实测等 `getInstance` 再点，100–200ms 就出参。
- `ListenTarget` 回调是**同步**执行的，里面必须另起 goroutine 发 CDP 命令，否则死锁；
- `initAliyunCaptcha` 只做初始化，**不点触发按钮永远没有参数**；
- 当前 cdproto 的 `network.Request` 已无 `PostData` 字段（改 `PostDataEntries`），
  且本接口 body 为空，不需要；
- 启动参数需显式关自动化特征：`headless`、`enable-automation=false`、
  `disable-blink-features=AutomationControlled`、`excludeSwitches=enable-automation`。

**chromedp vs playwright-go**：选 chromedp。它纯 Go、`CGO_ENABLED=0` 可编译、
只依赖系统已装 Chrome；playwright-go 运行时仍需 Node 驱动，对本任务
（hook 一个 JS 回调）没有任何额外收益。若将来掉到 SLIDING 且必须自动过滑块，
再考虑 playwright-go 的精细轨迹能力。

**风控风险**：`TRACELESS` 是评分结果，不是保证。同 IP 高频、异常指纹或
`F024`（自动化点击）都可能让它转成需要人工交互的形态。因此：
`--headed` + 持久化 `--profile` 是掉形态时的逃生舱。

### A.2 浏览器自称（反 headless 指纹）

`har#4` 复盘里唯一能看见的硬缺陷：探针每次铸造参数（`cr5a57.captcha-open.aliyuncs.com`
的 `InitCaptcha`）和设备指纹上报（`cloudauth-device-*` 的 Log2/Log3）都带着：

```text
user-agent:          … HeadlessChrome/153.0.0.0 Safari/537.36
sec-ch-ua-platform:  "macOS"    sec-ch-ua-mobile: ?0
window.innerWidth:   500   outerHeight: 932   screen: 800×600   dpr: 1
```

即「headless 桌面 Chrome + 800×600 屏」，而窗口是手机尺寸（视口比屏幕还高，
物理上不可能）。阿里云把这类组合点名过（`F009`「桌面浏览器模拟移动设备」）。

现在的做法（`internal/chromecaptcha/presentation.go`）：

1. 先落到真实源上，用 `navigator.userAgentData.getHighEntropyValues(...)` 读出**真实**自称；
2. `Emulation.setUserAgentOverride` 换上真实 UA 去 `HeadlessChrome` 后的字符串
   **并带上 `userAgentMetadata`**；
3. `Emulation.setDeviceMetricsOverride` 把屏幕换成这台机器的真实内建屏（1280×832 @2x）；
4. `--mobile` 时额外换 Android UA/客户端提示、430×932 视口与 `setTouchEmulationEnabled`。

三个已踩过的坑（都有离线护栏：`presentation_test.go`）：

- **只改 UA 字符串会让 Chrome 停发全部 `Sec-CH-UA-*`**（本机实测）。
  `userAgentMetadata` 必须一起给，否则就是把一个矛盾换成另一个更显眼的。
- **`navigator.userAgentData` 只在安全上下文里存在**：在 `about:blank` 上读出来是
  `undefined`（本机实测）。所以极简页**不自动初始化 SDK**，只定义
  `window.__loadAndStartSDK`，由 Go 在换好自称之后点火；否则第一次 `InitCaptcha`
  就带着 headless 指纹发出去了。
- **移动端视口不能小于 ~393px**：本机实测 360×800 时 Chrome 会把视口缩成
  368×818（scale 0.978），`innerWidth` 又跑到 `screen.width` 之上。默认用 430×932。

**设备指纹落地才叫预热完**。`deviceToken` 铸在 SDK 初始化那一刻，而设备指纹数据是
之后分 Log2/Log3 上传的（`har#4` 时序：`InitCaptcha` +0.18s → Log2 +0.49s →
Log3 +3.42s → 第一次点击 +3.45s）。页面刚 `getInstance` 就去点，我们的 certifyId
引用的设备记录可能还没落库。现在 `New` 会等到「一段时间没有新的设备指纹请求」
（默认 settle 4s，上限 20s）才算就绪；`deviceToken` 已缓存（整条链路没有
cloudauth-device 请求）时只等 grace 1.5s。⚠️ 这一步**只消除竞态**，不声称是 F001 的成因。

## 附录 B：实验记录

| 实验 | 位置 | 结论 |
| --- | --- | --- |
| 真实窗口首跑（**不完整、不可归因**；当时用的是旧版工具） | `probe-results/<首跑那次的>.md`（未提交，已 gitignore） | `analyze-a0`（旧版阶梯的第 1 档，现已从工具移除）→ `200 {"result":{"code":800}}`（**被拒**）；同一时刻明细读回 `0→1`，但那条**不是到课记录**（用户确认本人未被标记到课，手机当时钉钉卡住也没签上）⟹ 新增很可能只是窗口开启时生成的占位记录，**不能归因**于该档。旧版写入闸门（未按 `c`）停在档 1，未跑到真值档，**本跑不产生任何结论**。它暴露的「新增记录 = 成功」假阳性，是后来把工具改成只记录、不判读的直接原因（见 §3） |
| HAR 解析 | `skl.hdu.edu.cn_2026_09_14_10_50_57.har` | 参数在 query、body 空；`CaptchaType:"TRACELESS"` |
| **成功签到样本** | `skl.hdu.edu.cn2.har`（`har#3` 浏览器） | **`200 {captchaVerifyResult:true, captchaVerifyCode:"T001", checkCodeDto:{17 字段}}`**；同一次采集里另有 `414×2` 与 `200 F001`。全文与字段表见 [`signin-success-sample.md`](./signin-success-sample.md) |
| 请求形状 | 同上 | 空 body + `Content-Type: application/x-www-form-urlencoded`；`skl-ticket` 21 字符全部匹配 `[A-Za-z0-9_-]{21}`；`X-Auth-Token` = CAS `?token=` 的 UUID |
| 窗口长度 | 同上 | `expiresIn=20000`（**20 秒**），不是 ~300s |
| 人机形态升级 | 同上 | `TRACELESS` → `F001` → 同 `StaticPath` 升级为 `CHECK_BOX` → 成功（**浏览器路径特有**） |
| 页面源码 | `assets/index-new-COcfVClM.js`（路由 `/sign/in`） | 回调契约与「原样透传」 |
| SDK 源码 | `AliyunCaptcha.js` + 动态 chunk | `captchaVerifyCallback(param, next)` |
| hook 截获 | 临时 chromedp 程序 | `__captchaHookOk=true`，参数 len≈1690 |
| 形态判定 | 同上，headless | `TRACELESS` ×3，`webdriver=false` |
| 网络事件 | 临时 chromedp 程序 | `EventRequestWillBeSent.URL` 含完整 query |
| 演练回归 | `internal/chromecaptcha/browser_test.go` | 首次 Run 的 ctx 即浏览器生命周期（启动预算改用看门狗）；就绪信号必须是 `getInstance`。桩 SDK 离线复刻真实时序，`New` → `Param` 全链路可测 |
| 就绪信号 | `internal/chromecaptcha/integration_test.go` | `getInstance` ≈ init 后 300–550ms；等它再点，100–200ms 出参（3/3），且每次参数都是现取的（指纹/certifyId 各不相同） |
| 端到端演练 | `internal/probe/signinprobe_integration_test.go` | 真浏览器取参 + 假服务端：真值档拿到 HTTP 401（1.5s），不再是 `transport_error` |
| 依赖 | `go build` / `CGO_ENABLED=0` | 纯 Go，静态二进制 |
| **真实窗口第 2 跑**（探针 + 手机两条链路） | `har#4`（`~/Documents/skl.hdu.edu.cn_<时间戳>.har`，不入库） | 手机端 T001 成功并写入；探针四档全败（`F002` / `F014` / `F001`×3）。**唯一能看见的硬缺陷**是自称：UA 是 `HeadlessChrome/…`、屏幕是 headless 默认的 800×600 / dpr 1，而窗口是手机尺寸。另：`deviceToken` 可长期复用（手机那个 token 内嵌时间戳早于成功提交 20.94 分钟仍 T001），受「20 分钟 / 一次性」约束的是 `certifyId`（`F014`） |
| 自称实测（本机） | `internal/chromecaptcha/presentation_test.go`（离线护栏）+ 临时程序（已删） | `--headless=new` 的 UA 是 `HeadlessChrome/153.0.0.0`；屏幕 800×600 / dpr 1；`setUserAgentOverride` **不带** metadata 时 `Sec-CH-UA-*` 整批消失；`navigator.userAgentData` 在 `about:blank` 上是 `undefined`；移动端视口 <393px 会被 Chrome 自己缩放 |
| 设备指纹时序 | `har#4` | `InitCaptcha` +0.18s（铸 `deviceToken`）→ Log2 +0.49s → Log3 +3.42s → 第一次点击 +3.45s ⟹ 预热要等「落地」，见附录 A.2 |
| 阿里云错误码 | 官方《客户端返回数据说明》 | `F001` = 「疑似攻击请求，风险策略不通过」（不是「人机层单独拒签」）；`F009` 点名「桌面浏览器模拟移动设备」。全表见 §0.1 |
| 阶梯顺序 | `internal/probe/ladder_test.go` | `--ladder` 可选档位；真窗口建议只跑真值档，避免前置三档的失败提交污染 F001 归因 |
