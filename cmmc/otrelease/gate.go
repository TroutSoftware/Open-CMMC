package otrelease

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// The content gate is the first 3.14.2 control on the return path.
// Signature AV on G-code is weak evidence on its own (scope § 4), so
// before anything reaches ClamAV a returned file must look like what a
// controller legitimately produces: an allow-listed extension, a sane
// size, text content, and no executable or archive magic. Each check
// is a separate error so the audit reason is specific.

// GateError is returned by Gate.Check with a stable, audit-friendly
// reason code.
type GateError struct {
	Code   string
	Detail string
}

func (e *GateError) Error() string { return "otrelease: gate: " + e.Code + ": " + e.Detail }

// Reason codes.
const (
	GateExtension = "extension"
	GateSize      = "size"
	GateMagic     = "magic"
	GateBinary    = "binary"
	GateQuota     = "quota"
	GateName      = "name"
)

// magics are byte prefixes that never appear in NC programs but do
// appear in the things an attacker would drop through a return share.
var magics = []struct {
	name   string
	prefix []byte
}{
	{"pe/mz", []byte("MZ")},
	{"elf", []byte{0x7f, 'E', 'L', 'F'}},
	{"zip/office", []byte("PK\x03\x04")},
	{"zip-empty", []byte("PK\x05\x06")},
	{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
	{"gzip", []byte{0x1f, 0x8b}},
	{"bzip2", []byte("BZh")},
	{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}},
	{"rar", []byte("Rar!")},
	{"macho", []byte{0xfe, 0xed, 0xfa, 0xce}},
	{"macho64", []byte{0xfe, 0xed, 0xfa, 0xcf}},
	{"macho-fat", []byte{0xca, 0xfe, 0xba, 0xbe}},
	{"pdf", []byte("%PDF")},
	{"ole/msi", []byte{0xd0, 0xcf, 0x11, 0xe0}},
	{"shebang", []byte("#!")},
}

// maxBinaryRatio is the share of non-text bytes above which a file is
// treated as binary. NC programs are pure ASCII; 1% tolerates the odd
// stray byte from a serial-era controller without letting a blob
// through.
const maxBinaryRatio = 0.01

// sniffLen bounds how much of a file the text heuristic reads.
const sniffLen = 1 << 20

// CheckContent applies the extension, size, magic and text checks. It
// reads at most sniffLen bytes. size is the file's full length.
func CheckContent(cell *Cell, name string, size int64, r io.Reader) error {
	if !safeName(name) {
		return &GateError{GateName, name}
	}
	ext := strings.ToLower(filepath.Ext(name))
	if !contains(cell.Extensions(), ext) {
		return &GateError{GateExtension, fmt.Sprintf("%q not in allow-list", ext)}
	}
	if size > cell.MaxBytes() {
		return &GateError{GateSize, fmt.Sprintf("%d > %d bytes", size, cell.MaxBytes())}
	}
	head, err := io.ReadAll(io.LimitReader(r, sniffLen))
	if err != nil {
		return err
	}
	for _, m := range magics {
		if bytes.HasPrefix(head, m.prefix) {
			return &GateError{GateMagic, m.name}
		}
	}
	if len(head) > 0 && !looksLikeText(head) {
		return &GateError{GateBinary, "non-text content"}
	}
	return nil
}

// looksLikeText accepts valid UTF-8 (or plain ASCII) where the share
// of control bytes other than tab / CR / LF / FF / ESC stays under
// maxBinaryRatio. ESC is tolerated because some controllers emit it
// as a block delimiter; NUL is never tolerated.
func looksLikeText(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	bad := 0
	if utf8.Valid(b) {
		for _, r := range string(b) {
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' && r != '\f' && r != 0x1b {
				bad++
			} else if r == 0x7f {
				bad++
			}
		}
	} else {
		// Not UTF-8: accept only if it is 7-bit ASCII with the same
		// control-byte tolerance (old controllers, no code page).
		for _, c := range b {
			if c >= 0x80 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != 0x1b) || c == 0x7f {
				bad++
			}
		}
	}
	return float64(bad)/float64(len(b)) <= maxBinaryRatio
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Quota counts accepted files per machine per UTC day. In-memory: a
// restart resets the day's count, which errs toward accepting — the
// quota is a flood brake, not an access control.
type Quota struct {
	mu     sync.Mutex
	day    string
	counts map[string]int
	now    func() time.Time
}

// NewQuota returns an empty counter.
func NewQuota() *Quota {
	return &Quota{counts: map[string]int{}, now: time.Now}
}

// Peek reports whether machine still has quota today without
// consuming it.
func (q *Quota) Peek(machine string, limit int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.roll()
	if q.counts[machine] >= limit {
		return &GateError{GateQuota, fmt.Sprintf("%s reached %d files today", machine, limit)}
	}
	return nil
}

// Take consumes one unit for machine if under limit; returns a
// GateError otherwise.
func (q *Quota) Take(machine string, limit int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.roll()
	if q.counts[machine] >= limit {
		return &GateError{GateQuota, fmt.Sprintf("%s reached %d files today", machine, limit)}
	}
	q.counts[machine]++
	return nil
}

func (q *Quota) roll() {
	day := q.now().UTC().Format("2006-01-02")
	if day != q.day {
		q.day = day
		q.counts = map[string]int{}
	}
}

// IsGateError reports whether err is a content-gate rejection.
func IsGateError(err error) bool {
	var g *GateError
	return errors.As(err, &g)
}

// statSize is a small helper shared by intake and tests.
func statSize(p string) (int64, error) {
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}
