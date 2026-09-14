// Package skl 是杭电学勤系统（skl.hdu.edu.cn）的非官方 Go 客户端。
//
// 数据来源：两份钉钉手机端 Reqable 抓包（2026-09-14）加真机验证。
// 鉴权流程、请求头、nonce 语义均已实测确认；签到的人机验证部分是本次
// 逆向的边界，详见「风险与未解项」。
//
// # 鉴权模型
//
// skl 的会话完全靠**请求头**维持，没有任何 cookie：
//
//	X-Auth-Token: <uuid>         会话凭据，等同浏览器 localStorage 的 sessionId
//	skl-ticket:   <nanoid(21)>   每请求一次性防重放 nonce
//
// 其中 X-Auth-Token 的取得链路（已在真机验证）：
//
//	GET /api/userinfo（不带 token）
//	  -> 401 {"url":"https://cas.hdu.edu.cn/cas/login?state=..&service=.."}
//	GET  <cas url>            -> 302 转发到 sso.hdu.edu.cn（cas 只是壳）
//	POST <sso login>          -> AES 加密密码，302 带 ticket=ST-..
//	GET  /api/cas/login?ticket=..
//	  -> 302 https://skl.hdu.edu.cn/index.html#?token=<uuid>&t=<ms>
//	                                    ^^^^^ 会话 token 在 **fragment** 里
//
// 前端读到 fragment 里的 token 后存进 localStorage.sessionId，
// 再用 history.replaceState 把 token 从地址栏抹掉。登录这一步复用
// github.com/U1traVeno/hduwebvpn/pkg/sso。
//
// # 为什么不需要 WebVPN
//
// skl.hdu.edu.cn 在公网可直接访问，钉钉容器里走的也是直连。
// 因此本包不依赖 webvpn 隧道，只在 SSO 登录环节复用 hduwebvpn 的 sso 包。
//
// # 最小用例
//
//	client, err := skl.NewClient(
//	    skl.WithCredentials("24000000", "password"),
//	    skl.WithOnToken(func(tk string) { os.WriteFile(".token", []byte(tk), 0o600) }),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	user, err := client.UserInfo(ctx)   // 首次调用会自动完成 CAS 登录
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(user.UserName, user.ClassNo)
//
//	courses, err := client.Courses(ctx, time.Now())
//
// # 主要类型
//
//   - Client：会话、登录、重登、nonce 与错误翻译。可并发使用。
//   - Request / Response：一次调用的输入输出；Do 是通用逃生口。
//   - CaptchaProvider：签到所需人机验证参数的注入点。
//   - APIError：把 skl 的 `{"code":0,"msg":".."}` 业务错误、以及
//     401 的双重语义（会话失效 vs 业务校验失败）翻译成结构化错误。
//
// # 风险与未解项
//
// 以下内容按影响程度排序。前两条是「做不到 / 未能证实」的部分，
// 其余是需要调用方知情的行为约束。
//
// ## 1. 签到的人机验证无法用纯 Go 合成（最大的硬边界）
//
// `POST /api/ali-nvc/captcha-verify` 必须携带 `captchaVerifyParam`，
// 该值由阿里云验证码 3.x 前端 SDK（抓包版本 3.29.0）生成：
//
//	{"sceneId":"2q42bw25","certifyId":"..","deviceToken":"V0VCI2Fi..","data":"JRMlgg1E.."}
//
// 三个子字段分别来自：
//
//   - certifyId：POST https://cr5a57.captcha-open.aliyuncs.com（会话初始化）
//   - deviceToken：POST https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com
//     （设备指纹采集，含长期设备标识与签名）
//   - data：SDK 内部混淆代码加密后的风控载荷，另有 upload.captcha-open.aliyuncs.com
//     上传遥测
//
// 三者都由阿里云侧签名，与 SceneId、站点域名强绑定，且 SDK 会轮换算法。
// 结论：**不要试图在 Go 里重放这套协议**，维护成本高且随时失效。
//
// 可采用的三条路（按推荐度）：
//
//  1. 无头浏览器直接跑官方签到页：加载 https://skl.hdu.edu.cn/sign/in，
//     先把 token 写进 localStorage.sessionId，再输入 4 位签到码，
//     让官方页面自己完成 captcha 与签到。完全不需要碰验证码协议。
//  2. 无头浏览器只用来取参数：在同一页面调用 window.initAliyunCaptcha(...)，
//     从 captchaVerifyCallback 里把参数回传，配 StaticCaptchaProvider 使用。
//  3. 人工从 DevTools 复制一次 captchaVerifyParam，一次性使用。
//
// 本包把这部分隔离为 CaptchaProvider 接口，上述任何一种都可接进来。
//
// ## 2. 人机验证到底是否被强制，尚未证实
//
// 实测：签到码校验发生在人机验证**之前**。用无效签到码请求时，
// 缺失、伪造、乃至完全不传 captchaVerifyParam，服务端都返回同一个业务错误：
//
//	401 {"code":0,"msg":"签到码不存在，不要玩我"}
//
// 因此「无效签到码」永远无法区分验证码是否被校验。要证实这一点，
// 必须在一个**真实有效的签到码**上试一次——这会直接产生考勤记录，
// 所以本包没有替你决定，也没有把探测逻辑硬编码进去。
//
// ## 3. 遗留接口可能是绕过人机验证的通道，但同样未能证实
//
// 抓到的前端构建里已经没有调用方、但服务端仍然可用的两条老接口：
//
//	GET /api/checkIn/code-check-in?code=&id=&latitude=&longitude=
//	GET /api/ali-nvc/check-code-analyze?userid=&code=&token=&a=&callback=
//
// 后者是阿里云 NVC 的「风险自适应」形态：前端平时直接上报 a=0
// （表示未做人机验证），只有服务端返回 result.code==400 时才弹滑块。
// 这使它成为**最可能不需要人机验证**的路径。
//
// 但注意其语义是「校验并签到」而不是「只校验」：
//
//	⚠️ 用一个有效签到码调用 SignInLegacy / SignInLegacyAnalyze，
//	   可能会直接签到成功。不要把它们当作「只看签到码是否有效」的探针。
//
// 相关业务码：100/200 成功，400 需要滑块，800/900 被拒。
//
// ## 4. skl-ticket 是一次性 nonce，重放会静默失败
//
// 服务端按一次性值校验 skl-ticket，重复使用会返回
//
//	HTTP 200 + 空 body
//
// 也就是说**失败不能用状态码判断**。本包的做法是每个请求生成新 nonce，
// 并把 200+空 body 翻译成 ErrEmptyBody 而不是当作成功。
// 调用方若自行重试请求，务必重新构造 Request（不要复用）。
//
// ## 5. 存在前置 WAF / 限流
//
// 除 nonce 重放外，还观察到符合「被拦截」特征的 200+空 body 响应
// （例如带某些 User-Agent 时）。本包不会自动重试空 body 响应，
// 调用方应把 ErrEmptyBody 视为需要退避的信号，而不是立刻重试。
//
// ## 6. 定位由客户端上报，服务端只做数值校验
//
// 签到请求的 latitude/longitude 由客户端提供（钉钉内是
// `device.geolocation.get`，浏览器里是 navigator.geolocation）。
// 服务端拿到的就是这两个数，因此理论上可以伪造。
// 这属于使用者的责任边界，本包只提供参数透传。
// 注意缺失定位会导致签到直接失败。
//
// ## 7. 会话 token 的生命周期未知
//
// token 无 cookie、无服务端下发的过期信息。实测抓包中的 token
// 隔夜后仍可用（> 1 天）。本包因此在收到「带 url 的 401」时
// 才重新登录，并用 WithOnToken 让调用方持久化，避免频繁登录。
//
// ## 8. 登录依赖 SSO 表单结构
//
// 登录链共用 hduwebvpn/pkg/sso：它依赖 sso.hdu.edu.cn 登录页的
// `#login-page-flowkey` / `#login-croypto` 两个元素以及 AES-ECB 密码加密。
// 学校一旦改版，需要先升级 hduwebvpn。这是本包唯一的外部鉴权依赖。
//
// ## 9. 钉钉 JSAPI 无法在钉钉之外使用
//
// `/api/dingtalk/jsapi_ticket` 在非钉钉环境下也能调用成功，但返回的签名
// 无法驱动任何 JSAPI（扫一扫、精确定位、打开会话等）。
// 这些能力**不存在于网络层**，因此也就无法被抓包复现——
// 凡是依赖 dd.* 的功能都超出了本包的能力范围。
//
// ## 10. 合规提示
//
// 代签/自动签到通常违反学校考勤规定。本包仅提供协议封装，
// 使用者需自行承担由此产生的后果。
package skl
