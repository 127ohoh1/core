package redisc

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseURL(t *testing.T) {
	for _, ok := range []string{"redis://127.0.0.1:6379", "redis://h:1/3", "redis://:pw@h:1/0"} {
		if _, err := ParseURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://h:1", "redis://", "redis://h:1/x", "127.0.0.1:6379"} {
		if _, err := ParseURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestReadReply(t *testing.T) {
	cases := map[string]any{
		"+OK\r\n": "OK", ":42\r\n": int64(42), "$5\r\nhello\r\n": "hello", "$0\r\n\r\n": "",
	}
	for in, want := range cases {
		got, err := readReply(bufio.NewReader(strings.NewReader(in)), 0)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := readReply(bufio.NewReader(strings.NewReader("-ERR nope\r\n")), 0); err == nil {
		t.Error("error reply not surfaced")
	}
	if _, err := readReply(bufio.NewReader(strings.NewReader("$-1\r\n")), 0); err != ErrNil {
		t.Errorf("nil bulk: %v", err)
	}
	for _, bad := range []string{"", "x", "$99999999\r\n", "*99999\r\n", "*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n:1\r\n", "?\r\n", "$3\r\nab\r\n"} {
		if _, err := readReply(bufio.NewReader(strings.NewReader(bad)), 0); err == nil {
			t.Errorf("accepted malformed reply %q", bad)
		}
	}
}

// A hostile Redis (or a desynchronised stream) must produce a bounded error,
// never a panic, a hang or an unbounded allocation.
func FuzzReadReply(f *testing.F) {
	for _, s := range []string{"+OK\r\n", ":1\r\n", "$3\r\nabc\r\n", "*2\r\n:1\r\n$1\r\nx\r\n", "-ERR\r\n", "$-1\r\n", "*-1\r\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = readReply(bufio.NewReader(strings.NewReader(string(in))), 0)
	})
}
