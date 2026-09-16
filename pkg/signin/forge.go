package signin

import (
	"encoding/json"
	"strings"

	"github.com/hdufuck/skl"
)

// ForgeDefaults 是找不到真实样本时，伪造 CaptchaVerifyParam 所用的字段长度。
//
// 长度取自真实值量级，目的是让伪造值在长度维度上与真值一致，
// 避免被「长度异常」这一条单独拒掉。
var ForgeDefaults = struct {
	CertifyIDLen   int
	DeviceTokenLen int
	DataLen        int
}{CertifyIDLen: 10, DeviceTokenLen: 220, DataLen: 120}

// ForgeCaptchaParam 构造一个「结构合法但内容伪造」的 CaptchaVerifyParam。
//
// sample 是一份真实的 CaptchaVerifyParam（可为空）。给了样本时逐字段沿用
// 其长度、只把内容换成等长的 'A'；没给样本时用 ForgeDefaults。
// sceneId 始终沿用真值，样本缺失时用 skl.DefaultCaptchaSceneID。
//
// 探针（cmd/signinprobe）与库共用这一份实现，保证两边不会漂移。
//
// ⚠️ 结构合法不代表会被接受：伪造值提交到 captcha-verify 后，服务端很可能
// 在人机层拒签；它的用途正是把「参数层拒绝」与「人机层拒绝」分开。
// 提交它可能写入真实 CheckInRecord，后果由使用者承担。
func ForgeCaptchaParam(sample string) string {
	var parsed struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}
	_ = json.Unmarshal([]byte(sample), &parsed)

	sceneID := parsed.SceneID
	if sceneID == "" {
		sceneID = skl.DefaultCaptchaSceneID
	}
	certifyLen := len(parsed.CertifyID)
	deviceLen := len(parsed.DeviceToken)
	dataLen := len(parsed.Data)
	if sample == "" || certifyLen == 0 {
		certifyLen = ForgeDefaults.CertifyIDLen
	}
	if sample == "" || deviceLen == 0 {
		deviceLen = ForgeDefaults.DeviceTokenLen
	}
	if sample == "" || dataLen == 0 {
		dataLen = ForgeDefaults.DataLen
	}

	forged := struct {
		SceneID     string `json:"sceneId"`
		CertifyID   string `json:"certifyId"`
		DeviceToken string `json:"deviceToken"`
		Data        string `json:"data"`
	}{
		SceneID:     sceneID,
		CertifyID:   strings.Repeat("A", certifyLen),
		DeviceToken: strings.Repeat("A", deviceLen),
		Data:        strings.Repeat("A", dataLen),
	}
	out, err := json.Marshal(forged)
	if err != nil {
		return ""
	}
	return string(out)
}
