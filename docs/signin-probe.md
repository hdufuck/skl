# 签到探针手册：判定 `CaptchaEnforcement` 并验证库的签到封装路径

本文是**唯一**的签到实验文档，取代旧的 `signin-experiment.md`，并吸收了一份
未入库的浏览器取参研究草稿。它同时承担三件事：

1. 当前认知总纲（契约、参数形状、风控形态、窗口长度）；
2. `cmd/signinprobe` 的操作手册（预置、相位、判读、落盘）；
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
| 阶梯中「未携带真凭证」的档位**写入了记录** | **强**（唯一的干净归因来源） |
| 响应体明确指向人机层（`captchaVerifyResult===false`、文案含「人机」） | **强** |
| 响应体明确指向参数层（活路径 `400` + 参数缺失/非法） | **强** |
| 真值档（官方 SDK 参数 + 库 `SignIn`）成功 | **强**（证明库的封装路径可用） |
| 遗留端点 `/checkIn/code-check-in`、`/ali-nvc/check-code-analyze` 成功 | 强（证明不强制）；**失败不可解释**（单边证据） |
| 本机发出的探针失败 | **弱**：可能是客户端指纹/WAF 导致，不足以单独定论（见 ADR 0002） |
| `401 签到码不存在` | **无**：签到码校验先于风控校验 |
| `200 + 空 body`、超时、文案不明 | 无（工具/网络层） |

**归因规则**：本机探针与手机端官方客户端结论冲突时，**以手机端为准**。

## 1. 当前认知（事实）

### 1.1 三条签到路径 ✅/📖

| 路径 | 形态 | 现行前端里的地位 |
| --- | --- | --- |
| `POST /api/ali-nvc/captcha-verify` | query：`captchaVerifyParam`、`userid`、`code`、`latitude`、`longitude`、`t`(ms)；body 为空 | **唯一活着的路径** ✅ |
| `GET /api/checkIn/code-check-in` | `code`、`id`（`latitude`/`longitude` ⚠️） | axios 里有定义，**零调用者** 📖 |
| `GET /api/ali-nvc/check-code-analyze` | `userid`、`code`、`t`、`token`、`a`、`callback`(JSONP)，**完全不传定位** | 只被 `/sign/location` 调用，而该路由**不可达**；且它传的 `code` 是定位就绪标志（布尔），与签到码无关 📖 |

`a=0` 表示「未做人机验证」（`e.enable === false` 时前端直接拼 `0`）。

### 1.2 `captchaVerifyCallback` 契约 📖 + ✅

`/sign/in` 路由懒加载 `assets/index-new-COcfVClM.js`，其初始化原文：

```js
window.initAliyunCaptcha({
  SceneId: "2q42bw25", prefix: "cr5a57", mode: "popup",
  element: "#captcha-container", button: "#captcha-trigger-btn",
  captchaVerifyCallback: R, onBizResultCallback: L, language: "cn"
});

const R = async a => {
  const i = { captchaVerifyParam: a, userid: B.value?.id, code: s.value,
              latitude: u.value, longitude: d.value, t: Date.now() };
  const g = (await X.post("/ali-nvc/captcha-verify", null, { params: i })).data;
  return { captchaResult: g.captchaVerifyResult, bizResult: true };
};
```

要点：

- 页面拿到的回调入参 `a` **原样**作为 `captchaVerifyParam` 提交，不做任何加工 ✅。
- `captchaVerifyCallback(captchaVerifyParam: string, next: Function)`；
  也可 `return {captchaResult, bizResult}`（真实页面用 return）✅。
- `{true, undefined|true}` = 成功；`{true, false}` = 失败 + `reInitCaptcha`；
  `false`/`undefined` = 提示 + `reInitCaptcha` 📖。
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
⟹ **没有滑块**；但 `initAliyunCaptcha` 只做初始化，**必须点一次触发按钮**才有参数 ✅。

风险 ⚠️：`TRACELESS` 是风控评分结果，会随 IP/时间/频次/设备指纹变化；
阿里云有 `F024`「检测到自动化脚本模拟点击、滑动」，自动点击理论上可命中。

### 1.5 窗口长度：很可能 ~300s ✅（推翻 20–30s 直觉）

教师端生成签到码**没有有效期下拉**；前端兜底值是 **300 秒**、上限 3600 秒，
真实值来自后端 `expiresIn`/`expiresDate`（`POST /checkIn/create-code`，
`expiresIn` 实际传的是 `Date.now()`，命名疑似历史遗留）。
前端解析函数把 ≤300 当「秒」、≤300000 当「毫秒」、更大当「时间戳」📖。

⟹ 脚本仍按 **30s 墙钟**设硬闸（最坏情况保守），但真实窗口大概率宽裕得多。

## 2. 角色分工与阶梯

三个消费者，职责不重叠：

| 消费者 | 提供什么 |
| --- | --- |
| **档 1–4（本机 Go）** | 回答「是否强制人机验证」（弱归因，见第 0 节） |
| **档 5（chromedp 真值 → 库 `SignIn`）** | 回答「库的 `SignIn` 封装路径能否走通」+ 取得活路径成功样本 |
| **手机（钉钉 + Reqable）** | 独立的、**权威的**官方成功样本（acceptance criterion 的保险） |

阶梯按「越依赖人机越靠后」排列，顺序即开火顺序：

| # | 档位 ID | 请求 | 凭证 |
| --- | --- | --- | --- |
| 1 | `analyze-a0` | `GET /ali-nvc/check-code-analyze`，`a=0`，JSONP | 无 |
| 2 | `code-check-in` | `GET /checkIn/code-check-in`，带定位 | 无 |
| 3 | `captcha-verify-missing` | `POST /ali-nvc/captcha-verify` | **缺失** |
| 4 | `captcha-verify-forged` | 同上 | **伪造**（结构合法、等长） |
| 5 | `captcha-verify-genuine` | 同上，走库的 `SignIn` | 官方 SDK **真值** |

### 2.1 时间预算（T0 = 签到码输入完成）

| 相位 | 预算 | 超时行为 |
| --- | --- | --- |
| 档 1–4 | ≤ 8s | 跳过剩余、继续 |
| 档 5（浏览器取参 + 提交） | ≤ 23s | 放弃浏览器、优先保手机 |
| 手机官方签到 | ≥ 7s | — |
| 等 Reqable 上报 | ≤ 10s | 记 `hookMissing: true`，不阻塞 |

浏览器在 T0 前**已预热**（页面加载、SDK 初始化完成），T0 后只点一次触发按钮
（≈2–5s 出参）。

### 2.2 写入闸门

每档之后做读回 diff；一旦发现**新增记录**：

- 默认（交互）：命令行打印告警，**5 秒倒计时**；`c` 回车继续，回车/超时则停止。
- `--continue-after-write`：不询问，跑完全部档位。
- 停止时报告记 `stoppedAt`。

> 只用命令行文字提示，**不响铃**。

## 3. 读回与判读

- 读回端点：`GET /api/check-in-student-detail/my?startDate=<今天>&endDate=<今天>`。
- T0 前的基线计入报告；每档之后再读一次，按 `id`（缺 `id` 时按内容哈希）求新增。
- 已知局限：若手机先签、服务端又按「课程+日期+学生」去重，则本机成功档可能**看不到新增**。
  因此脚本同时在报告里保留**响应体判读**作为降级判据（低置信）。

判读表：

| 观测 | 判读 | 强度 |
| --- | --- | --- |
| 无真凭证档写入记录 | `written_without_captcha` | 强 |
| 真值档写入记录，或 `captchaVerifyResult===true` 且 `checkCodeDto` 非空 | `success` | 强 |
| `captchaVerifyResult===false`、文案含「人机/滑块/验证码」 | `captcha_layer_rejected` | 强 |
| 活路径 `400` + 参数缺失/非法 | `param_layer_rejected` | 强 |
| `401` 文案含「签到码」 | `code_rejected` | 无 |
| `200` + 空 body | `empty_body`（换新 `skl-ticket` 重发一次，不计入尝试） | 无 |
| 其它 | `unattributable` | 无 |

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
   - 档 1–4 都在 8s 内返回 `401 签到码不存在`；
   - 浏览器预热成功（打印「官方验证码 SDK 已就绪」）；
   - 手机上报能在 10s 内到达（`hookMissing` 为 false）。
   演练会实际发出探针请求，但无效签到码不会写入任何记录。

### 4.2 T0 流程

```bash
go run ./cmd/signinprobe            # 默认：headless=new、hook :8080、30s 预算
# 可选：--headed  --profile <目录>  --no-browser  --hook ""  --out probe-results
```

补充说明：

- **默认就复用持久化 profile**（`$XDG_CACHE_HOME`/`~/Library/Caches` 下的
  `signinprobe/chrome-profile`），让设备指纹「热」起来；`--profile` 可改路径。
- 签到码**主路径是 stdin 交互输入**；`--code <4位>` 只是给演练/自动化用的显式覆盖
  （签到码本身无隐私，见 Q6），真实窗口建议仍用交互输入。
- `--no-browser` 只跑档 1–4（演练用，不需要 Chrome）。

T0 后的时序：

1. 脚本登录、预热读回、预热浏览器、起 hook 服务，打印 Reqable 接收地址；
2. 提示 `请输入老师公布的 4 位签到码（输入后立即开始计时）`；
3. 你输入 4 位码 → **T0**；
4. 档 1–4 自动打完（约 3–5s）；若某档写入，按第 2.2 节处理；
5. 档 5：浏览器点触发按钮 → 静默出参 → 库 `SignIn` 提交；
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
     - 压缩：`gzip`（脚本能解；HAR 本身仍是 JSON）
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

- `X-Auth-Token`、`skl-ticket`、`Cookie`、`token=`、`sessionId` **永不粘贴**；
- `deviceToken` 只留长度与前 20 字符；
- `captchaVerifyParam` 的 `sceneId`/`certifyId` 可留，`data` 只留前 20 字符；
- `*.har` 已在 `.gitignore`，`probe-results/` 同样 gitignore；
  **只提交手动脱敏后的 markdown 片段**，不提交原始报告。

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
| 服务端是否校验 `t` | 需要专门探针，且不影响库的形态 |
| `coordinate: 0` 的坐标系语义 | 需要教师端 `distance` 列 |
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

## 附录 B：实验记录

| 实验 | 位置 | 结论 |
| --- | --- | --- |
| HAR 解析 | `skl.hdu.edu.cn_2026_09_14_10_50_57.har` | 参数在 query、body 空；`CaptchaType:"TRACELESS"` |
| 页面源码 | `assets/index-new-COcfVClM.js`（路由 `/sign/in`） | 回调契约与「原样透传」 |
| SDK 源码 | `AliyunCaptcha.js` + 动态 chunk | `captchaVerifyCallback(param, next)` |
| hook 截获 | 临时 chromedp 程序 | `__captchaHookOk=true`，参数 len≈1690 |
| 形态判定 | 同上，headless | `TRACELESS` ×3，`webdriver=false` |
| 网络事件 | 临时 chromedp 程序 | `EventRequestWillBeSent.URL` 含完整 query |
| 依赖 | `go build` / `CGO_ENABLED=0` | 纯 Go，静态二进制 |
