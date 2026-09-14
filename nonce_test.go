package skl

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewTicket(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 1024)
	for range 1024 {
		tk, err := NewTicket()
		if err != nil {
			t.Fatalf("NewTicket: %v", err)
		}
		if len(tk) != TicketSize {
			t.Fatalf("len(NewTicket()) = %d, want %d (%q)", len(tk), TicketSize, tk)
		}
		for _, r := range tk {
			if !strings.ContainsRune(nanoidAlphabet, r) {
				t.Fatalf("NewTicket() produced %q, which is outside the nanoid alphabet", r)
			}
		}
		if _, dup := seen[tk]; dup {
			t.Fatalf("NewTicket() repeated value %q", tk)
		}
		seen[tk] = struct{}{}
	}
}

func TestNewTicketSizeValidation(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, -1} {
		if _, err := newTicket(size, bytes.NewReader(nil)); err == nil {
			t.Fatalf("newTicket(%d) = nil error, want ErrInvalidTicketSize", size)
		}
	}
}

// deterministicReader feeds a fixed byte stream so masking can be checked exactly.
type deterministicReader struct {
	b []byte
	i int
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, bytes.ErrTooLarge
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func TestNewTicketMasking(t *testing.T) {
	t.Parallel()

	// bytes 0,1,63,64,65 -> indices 0,1,63,0,1
	r := &deterministicReader{b: []byte{0, 1, 63, 64, 65}}
	got, err := newTicket(5, r)
	if err != nil {
		t.Fatalf("newTicket: %v", err)
	}
	want := string([]byte{
		nanoidAlphabet[0],
		nanoidAlphabet[1],
		nanoidAlphabet[63],
		nanoidAlphabet[0],
		nanoidAlphabet[1],
	})
	if got != want {
		t.Fatalf("newTicket = %q, want %q", got, want)
	}
}
