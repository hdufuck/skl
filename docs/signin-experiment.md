# 签到实验手册：判定 `CaptchaEnforcement`

判定「服务端在写入考勤之前是否要求一次通过校验的 `CaptchaVerifyParam`」（定义见 `CONTEXT.md`）。

> **只能做一次。** 只能用真实有效的 `SignInCode` 判定，而它由现场生成、有效期未知、无法事后复现；实验本身会写入真实 `CheckInRecord`。窗口之前必须把第 1 节的预置全部练完。

## 0. 判据与优先级

| 判据 | 强度 |
| --- | --- |
| 活路径 `POST /api/ali-nvc/captcha-verify` 的单变量探针 | **强**（唯一能干净归因的来源） |
| 遗留端点 `/api/checkIn/code-check-in`、`/api/ali-nvc/check-code-analyze` | **单边**：成功=强证据（证明不强制）；失败**不可解释** |

遗留端点为什么是单边的：现行前端里 `code-check-in` **零调用者**，`check-code-analyze` 所在路由 `/sign/location` **不可达**（只在路由表里出现一次，无 `push`/`replace`/tab，因为它没有 `meta.level`），而且它传的 `code` 是定位就绪标志的布尔值——真正接收 4 位签到码的输入框从未被 render 引用。也就是说没有任何官方客户端会发出"合法形状"的遗留签到请求，所以它失败时无法区分"服务端要求人机验证"与"请求形状本来就不对"。

## 1. 预置（窗口前做完，全部可在无效签到码上演练，零风险）

1. **读回端点预热**：先跑一次
   `GET /api/check-in-student-detail/my?startDate=<当天>&endDate=<当天>`，
   确认 gzip 的 JSON 数组能正常解析，并记下**基线**（当前应为 `[]`）。
   同时确认 `GET /api/checkIn/stu-course-check-in-count?courseId=<本课程>` 也是 `[]`。
   HAR 里这两个端点返回的都是 gzip 编码的 `[]`——窗口内第一次解析失败就等于把唯一一次机会浪费在工具问题上。
2. **探针规则**（每条都要能在无效码上演练出 401「签到码不存在」）：
   - **R-缺失**：Rewrite → Modify Request，**删除** query 参数 `captchaVerifyParam`
   - **R-伪造**：Modify Request，把 `captchaVerifyParam` 的值替换为**结构合法但伪造**的 JSON（同一个 `sceneId`，`certifyId`/`data`/`deviceToken` 换成等长垃圾）
   - **R-重放**：Modify Request，正则把该参数的值替换为**第 1 步官方请求里那个已用过的值**
   - 匹配 URL 一律 `*/api/ali-nvc/captcha-verify*`；三条规则**默认全部停用**，窗口内逐条启用。
3. **脱敏规则**（照抄进最终文档）：`X-Auth-Token`、`skl-ticket`、`Cookie`、`token=`、`sessionId` **永不粘贴**；`deviceToken` 只留长度与前 20 字符；`captchaVerifyParam` 的 `sceneId`/`certifyId` 可留，`data` 只留前 20 字符。`*.har` 已在 `.gitignore` 里，原始抓包**不入库**。

## 2. 环境

真机钉钉（`AliApp(DingTalk/..)` + `UWS` 内核，`X-Requested-With: com.alibaba.android.rimet`）+ Reqable 桌面版做代理。

> 注意：被代理的 HTTPS 由桌面 Reqable 终止后再向服务器发起，所以**官方签到与探针的出口 IP 是同一个**（都是桌面 Reqable 的出口）。真正会引入客户端差异的是从**别的机器**直接 `curl` 或跑 Go 客户端——那才是被排除的做法，不是"手机 vs 桌面"。

## 3. 矩阵（顺序固定，先做官方签到）

| # | 探针 | 单变量改动 | 观测 | 停止条件 |
| --- | --- | --- | --- | --- |
| 1 | 官方正常签到 | 无 | 成功响应**全文** + 读回出现记录 | 拿不到成功样本 → **立刻终止整个矩阵** |
| 2 | **缺失** `captchaVerifyParam` | 删掉该参数 | 见第 5 节判读表 | 若写入记录 → 停止（已证明不强制） |
| 3 | **伪造**（结构合法） | 该参数的值换成等长垃圾 | 同上 | 若写入记录 → 停止 |
| 4 | **重放**（用第 1 步的值） | 该参数的值换成已用过的值 | 同上 | — |

**顺序理由**：2 直接回答"强制"；3 把"参数层拒绝"与"人机层拒绝"分开——两者成对才是完整证据；4（是否一次性）信息量最低，且它不影响库的形态，放最后。每条探针都会消耗窗口的剩余有效期，所以按信息量降序。

**单变量纪律**：除该字段外**逐字节沿用官方请求**——headers 原样、经纬度固定（沿用官方那次的坐标，不伪造远端位置）、`t` 用当前毫秒时间戳、`skl-ticket` 用新生成的值。

## 4. 触发机制（二选一）

- **(a) 页面上重走**：启用一条 Rewrite 规则 → 手机上再输一次签到码、再过一次滑块 → 规则自动改包 → 观测。
  优点：`t`、`skl-ticket`、UA 全部由页面生成，单变量最纯。缺点：每条探针一次人工输码 + 一次滑块，受签到码有效期限制。
- **(b) 桌面重发**：在 traffic 列表里对第 1 步的那条请求「编辑并重发」，只改 `captchaVerifyParam`，并把 `skl-ticket` 换成新随机值、`t` 换成当前毫秒。
  优点：秒级，四条探针可在一分钟内发完。缺点：要自己造 `skl-ticket`（21 字符，任意新值即可，服务端只判"是否用过"）与 `t`；需确认你的 Reqable 版本有这个菜单项。

## 5. 判读表

| 观测 | 归因 | 强度 |
| --- | --- | --- |
| `400` + 参数缺失/非法文案 | 参数层就要求人机凭证 | 强 |
| `401`/`200` 且 `captchaVerifyResult === false`，文案指向人机 | 人机层拒绝 | 强 |
| `200` + `captchaVerifyResult === true` + 读回出现记录 | **不强制** | 强 |
| 其余（超时、空 body、文案不明） | 不可归因 | 记入"未证明" |

## 6. 应急

- 读回端点**看不见记录**时的降级判据：`HTTP 200 ∧ captchaVerifyResult === true ∧ checkCodeDto 非空`，标记为**低置信**，并交叉读 `stu-course-check-in-count` 与 `stu-check-count`。
- 出现 `200` + 空 body：优先怀疑 `skl-ticket` 被复用，换新值重发一次，不要当成"服务端拒绝"。

## 7. 本次明确不证明

| 项 | 原因 |
| --- | --- |
| 服务端是否校验 `t` | 需要专门探针，且不影响库的形态 |
| `coordinate: 0` 的坐标系语义 | 需要教师端 `distance` 列，已排除 |
| `distance` 超限是否拒签 | 需伪造远端坐标，会写入一条位置异常的记录；且该条主张已由项目所有者确认，无证据债 |
| 遗留端点是否"免验证码" | 单边证据：成功才算证明，失败不可解释 |

## 8. 落盘

窗口结束后，`docs/api.md` 的对应条目按判读结果升级，并**逐字引用**最小必要片段（成功响应全文、请求形状、`captchaVerifyParam` 的首段），人手脱敏。**不提交任何 HAR**：只保留"如何获取"（即本手册）。
