package tunnel

import (
	"errors"
	"strings"
	"testing"
)

func TestRequestMetaRoundTripAndValidation(t *testing.T) {
	m := RequestMeta{Method: "GET", Target: "/a?b=c", Host: "x.127ohoh1.com", Header: map[string][]string{"Accept": {"*/*"}}, ContentLength: -1}
	b, err := EncodeRequestMeta(m, MetaLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequestMeta(b, MetaLimits{})
	if err != nil || got.Target != "/a?b=c" || got.ContentLength != -1 {
		t.Fatalf("%+v %v", got, err)
	}
	bad := []RequestMeta{
		{Method: "GET", Target: "http://evil/"},
		{Method: "GET", Target: "*"},
		{Method: "GET", Target: ""},
		{Method: "CONNECT", Target: "/"},
		{Method: "GE T", Target: "/"},
		{Method: "GET", Target: "/a b"},
		{Method: "GET", Target: "/a\r\nX: y"},
		{Method: "GET", Target: "/", Header: map[string][]string{"Bad Name": {"x"}}},
		{Method: "GET", Target: "/", Header: map[string][]string{"X": {"a\r\nInjected: 1"}}},
	}
	for i, m := range bad {
		if _, err := EncodeRequestMeta(m, MetaLimits{}); !errors.Is(err, ErrMetaInvalid) {
			t.Errorf("#%d accepted: %v", i, err)
		}
	}
}

func TestMetaLimits(t *testing.T) {
	big := map[string][]string{"X": {strings.Repeat("a", 3000)}}
	if _, err := EncodeRequestMeta(RequestMeta{Method: "GET", Target: "/", Header: big}, MetaLimits{MaxBytes: 1024}); !errors.Is(err, ErrMetaTooLarge) {
		t.Fatal(err)
	}
	many := map[string][]string{}
	for i := 0; i < 20; i++ {
		many["X"+strings.Repeat("a", i)] = []string{"v"}
	}
	if _, err := EncodeRequestMeta(RequestMeta{Method: "GET", Target: "/", Header: many}, MetaLimits{MaxHeaders: 10}); !errors.Is(err, ErrMetaTooLarge) {
		t.Fatal(err)
	}
	if _, err := DecodeRequestMeta(make([]byte, 5000), MetaLimits{MaxBytes: 4096}); !errors.Is(err, ErrMetaTooLarge) {
		t.Fatal(err)
	}
}

func TestResponseMeta(t *testing.T) {
	b, err := EncodeResponseMeta(ResponseMeta{Status: 200, ContentLength: 5}, MetaLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := DecodeResponseMeta(b, MetaLimits{}); err != nil || m.Status != 200 {
		t.Fatal(err)
	}
	for _, s := range []int{0, 99, 600, -1} {
		if _, err := EncodeResponseMeta(ResponseMeta{Status: s}, MetaLimits{}); err == nil {
			t.Errorf("status %d accepted", s)
		}
	}
	if _, err := DecodeResponseMeta([]byte(`{"s":1000}`), MetaLimits{}); err == nil {
		t.Error("decoded bad status")
	}
}

func FuzzDecodeRequestMeta(f *testing.F) {
	f.Add([]byte(`{"m":"GET","t":"/","h":"a","cl":-1}`))
	f.Add([]byte(`{"m":"GET","t":"/","hd":{"A":["b"]}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeRequestMeta(b, MetaLimits{MaxBytes: 4096, MaxHeaders: 20})
		if err != nil {
			return
		}
		// Accepted metadata must satisfy every invariant the proxy relies on.
		if !strings.HasPrefix(m.Target, "/") || strings.ContainsAny(m.Target, " \r\n\x00") || m.Method == "CONNECT" {
			t.Fatalf("unsafe metadata accepted: %+v", m)
		}
		for k, vs := range m.Header {
			if !validToken(k) {
				t.Fatalf("bad header name %q", k)
			}
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n\x00") {
					t.Fatalf("bad header value %q", v)
				}
			}
		}
	})
}

func FuzzDecodeResponseMeta(f *testing.F) {
	f.Add([]byte(`{"s":200}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeResponseMeta(b, MetaLimits{MaxBytes: 4096, MaxHeaders: 20})
		if err == nil && (m.Status < 100 || m.Status > 599) {
			t.Fatalf("status %d", m.Status)
		}
	})
}
