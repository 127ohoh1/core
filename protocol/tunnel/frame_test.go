package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func enc(t testing.TB, f Frame) []byte {
	t.Helper()
	b, err := AppendFrame(nil, f, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	frames := []Frame{
		{Type: TypeHello, Payload: []byte(`{"v":1}`)},
		{Type: TypeOpen, Stream: 1, Payload: []byte("meta")},
		{Type: TypeData, Stream: 3, Payload: bytes.Repeat([]byte{1}, 1000)},
		{Type: TypeHalfClose, Stream: 3},
		WindowUpdate(0, 65536), WindowUpdate(5, 1),
		ResetFrame(7, CodeCancel), PingFrame(TypePing, 42), GoAwayFrame(9, CodeShutdown),
		ErrorFrame(CodeProtocolError, "bad"),
	}
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(enc(t, f))
	}
	for i, want := range frames {
		got, err := ReadFrame(&buf, 1<<16)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if got.Type != want.Type || got.Stream != want.Stream || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("#%d: got %+v want %+v", i, got, want)
		}
	}
	if _, err := ReadFrame(&buf, 1<<16); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func hdr(ver, typ, flags, rsv byte, stream, length uint32) []byte {
	b := []byte{ver, typ, flags, rsv}
	b = binary.BigEndian.AppendUint32(b, stream)
	return binary.BigEndian.AppendUint32(b, length)
}

func TestDecoderRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"bad version", hdr(9, 9, 0, 0, 1, 1), ErrBadVersion},
		{"unknown type", hdr(1, 99, 0, 0, 0, 0), ErrUnknownType},
		{"type zero", hdr(1, 0, 0, 0, 0, 0), ErrUnknownType},
		{"flags set", hdr(1, 14, 1, 0, 0, 8), ErrBadHeader},
		{"reserved set", hdr(1, 14, 0, 1, 0, 8), ErrBadHeader},
		{"oversize length", hdr(1, 9, 0, 0, 1, 1<<20), ErrFrameTooLarge},
		{"u32 max length", hdr(1, 9, 0, 0, 1, 0xffffffff), ErrFrameTooLarge},
		{"stream frame with id 0", hdr(1, 9, 0, 0, 0, 1), ErrBadStreamID},
		{"conn frame with id", hdr(1, 14, 0, 0, 5, 8), ErrBadStreamID},
		{"stream high bit", hdr(1, 9, 0, 0, 0x80000001, 1), ErrBadStreamID},
		{"window update short", hdr(1, 13, 0, 0, 0, 3), ErrBadPayload},
		{"empty data", hdr(1, 9, 0, 0, 1, 0), ErrBadPayload},
		{"halfclose with payload", append(hdr(1, 10, 0, 0, 1, 1), 0), ErrBadPayload},
		{"reset wrong size", append(hdr(1, 12, 0, 0, 1, 2), 0, 0), ErrBadPayload},
	}
	for _, c := range cases {
		if _, err := ReadFrame(bytes.NewReader(c.in), 1<<16); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// Truncated payload.
	in := append(hdr(1, 9, 0, 0, 1, 10), 1, 2, 3)
	if _, err := ReadFrame(bytes.NewReader(in), 1<<16); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated: %v", err)
	}
}

// The decoder must reject an absurd declared length without reading or
// allocating it: an io.Reader that would panic if asked for the payload proves it.
type headerOnly struct {
	h   []byte
	pos int
}

func (r *headerOnly) Read(p []byte) (int, error) {
	if r.pos >= len(r.h) {
		panic("decoder tried to read payload of an oversize frame")
	}
	n := copy(p, r.h[r.pos:])
	r.pos += n
	return n, nil
}

func TestNoAllocationFromUntrustedLength(t *testing.T) {
	r := &headerOnly{h: hdr(1, 9, 0, 0, 1, 0x7fffffff)}
	if _, err := ReadFrame(r, 1<<16); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
}

func TestEncoderRejectsOversizeAndBadIDs(t *testing.T) {
	if _, err := AppendFrame(nil, Frame{Type: TypeData, Stream: 1, Payload: make([]byte, 101)}, 100); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if _, err := AppendFrame(nil, Frame{Type: TypeData, Stream: 0, Payload: []byte{1}}, 100); !errors.Is(err, ErrBadStreamID) {
		t.Fatal(err)
	}
}

func TestParseWindowUpdateBounds(t *testing.T) {
	for _, v := range []uint32{0, 0x80000000, 0xffffffff} {
		p := binary.BigEndian.AppendUint32(nil, v)
		if _, err := ParseWindowUpdate(p); err == nil {
			t.Errorf("accepted increment %d", v)
		}
	}
	if v, err := ParseWindowUpdate(binary.BigEndian.AppendUint32(nil, 0x7fffffff)); err != nil || v != 0x7fffffff {
		t.Fatal(err)
	}
}

func TestErrorFrameTruncates(t *testing.T) {
	f := ErrorFrame(CodeInternalError, strings.Repeat("x", 5000))
	if len(f.Payload) != 4+256 {
		t.Fatalf("len %d", len(f.Payload))
	}
}

func FuzzReadFrame(f *testing.F) {
	for _, fr := range []Frame{{Type: TypeOpen, Stream: 1, Payload: []byte("x")}, WindowUpdate(0, 5), PingFrame(TypePing, 1)} {
		b, _ := AppendFrame(nil, fr, 1<<16)
		f.Add(b)
	}
	f.Add(hdr(1, 9, 0, 0, 1, 0xffffffff))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for i := 0; i < 8; i++ {
			fr, err := ReadFrame(r, 4096)
			if err != nil {
				return
			}
			if len(fr.Payload) > 4096 {
				t.Fatalf("payload %d exceeds limit", len(fr.Payload))
			}
			// Anything accepted must re-encode to a frame that decodes identically.
			out, err := AppendFrame(nil, fr, 4096)
			if err != nil {
				t.Fatalf("accepted frame does not re-encode: %v", err)
			}
			back, err := ReadFrame(bytes.NewReader(out), 4096)
			if err != nil || back.Type != fr.Type || back.Stream != fr.Stream || !bytes.Equal(back.Payload, fr.Payload) {
				t.Fatalf("round trip mismatch")
			}
		}
	})
}
