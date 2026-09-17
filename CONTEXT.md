# skl 客户端

杭电学勤系统（`skl.hdu.edu.cn`）的学生端/教师端 API 封装。本文件只定义这个上下文特有的语言，不含实现细节。

## Language

**签到码 SignInCode**:
教师在课堂上生成、学生在签到页输入的 4 位数字码，过期即废。
_Avoid_: code、签到口令、验证码

**人机凭证 CaptchaVerifyParam**:
阿里云验证码前端 SDK 为一次签到生成、随签到请求提交的参数串（JSON 文本）。
_Avoid_: captcha、验证码参数、token

**人机判定 CaptchaVerifyResult**:
服务端对本次签到所提交的人机凭证给出的判定结果，是签到响应里的一个字段。
_Avoid_: 验证码结果、captchaResult

**人机验证强制 CaptchaEnforcement**:
服务端在写入考勤之前，是否要求一次通过校验的人机凭证。**「强制」只在这个定义下使用**；它与「能否被逆向」是两件事，不得混用。
_Avoid_: 是否需要验证码、能否绕过验证码

**考勤记录 CheckInRecord**:
一次成功签到在服务端留下的出勤数据，按课程与日期归属到学生。
_Avoid_: 打卡、签到成功、attendance

**围栏距离 Distance**:
教师生成签到码时的定位与学生签到定位之间的距离（米）。服务端照记不因此拒签。
_Avoid_: 距离校验、范围校验

**定位就绪标志**:
遗留路径 `/ali-nvc/check-code-analyze` 的 `code` 查询参数，与签到码无关。
_Avoid_: code

**会话令牌 SessionToken**:
登录后长期复用的凭据（`localStorage.sessionId`，请求头 `X-Auth-Token`）。
_Avoid_: token、sessionId、X-Auth-Token

**请求票据 SklTicket**:
每个请求一次性生成的 21 字符防重放头 `skl-ticket`；复用同一个值会得到 `200` + 空 body。
_Avoid_: ticket、nonce、skl-ticket

**签到方式 Method**:
`pkg/signin` 里一条可枚举的签到路径，ID 与探针阶梯的档位逐字对应（`analyze-a0` / `code-check-in` / `captcha-verify-missing` / `captcha-verify-forged` / `captcha-verify-genuine`）。**例外**：`analyze-a0` 只是库里的可显式调用路径，探针阶梯已不再走它——它即使拿到有效签到码也只回 `{"result":{"code":800}}`（被拒），失败不可解释。
_Avoid_: rung、阶梯档位（那是探针内部的说法）

**签到结果 Outcome**:
`pkg/signin` 对一次签到调用的统一返回：状态码、原始响应，以及解好的 `SignInResult` 或 `AnalyzeResult`。**不含判读**——「是否强制人机」不在里面。
_Avoid_: Verdict、判定结果

**SSO 鉴权器 SSOAuthenticator**:
根包里可注入的 SSO 登录实现，默认是 `hduwebvpn/pkg/sso.Auth`；学校改版或换认证通道时替换它而不改签到路径。
_Avoid_: 登录器、auth provider
