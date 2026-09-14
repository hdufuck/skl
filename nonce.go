package skl

import (
	"crypto/rand"
	"io"
)

// nanoidAlphabet 是 nanoid 的 urlAlphabet。
//
// 该字符串取自 skl 前端 vendor bundle（`grep useandom vendor-*.js`），
// 说明 skl 前端用 `nanoid()` 生成 skl-ticket，默认长度 21。
const nanoidAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"

// TicketSize 是 skl-ticket 的长度。前端使用 nanoid 默认值 21。
const TicketSize = 21

// newTicket 生成一个 nanoid 兼容的随机串。
//
// 实现与 nanoid 的 customRandom 一致：因为 len(alphabet) 恰为 64（2 的幂），
// 直接对随机字节做 `& 63` 掩码即可得到均匀分布，无需拒绝采样。
func newTicket(size int, r io.Reader) (string, error) {
	if size <= 0 {
		return "", ErrInvalidTicketSize
	}

	const mask = len(nanoidAlphabet) - 1 // 63

	out := make([]byte, size)
	buf := make([]byte, size)
	for written := 0; written < size; {
		n := min(size-written, len(buf))
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return "", err
		}
		for _, b := range buf[:n] {
			out[written] = nanoidAlphabet[int(b)&mask]
			written++
		}
	}
	return string(out), nil
}

// NewTicket 生成一个新的 skl-ticket。
//
// skl-ticket 是一次性（anti-replay）随机串：服务端会拒绝重复值，
// 且拒绝方式是 `HTTP 200 + 空 body`（见 Response 与 ErrEmptyBody）。
// 因此每个请求都必须使用全新的值。
func NewTicket() (string, error) {
	return newTicket(TicketSize, rand.Reader)
}
