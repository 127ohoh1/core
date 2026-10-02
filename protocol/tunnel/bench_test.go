package tunnel

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func BenchmarkAppendFrame16KiB(b *testing.B) {
	f := Frame{Type: TypeData, Stream: 1, Payload: make([]byte, 16<<10)}
	buf := make([]byte, 0, HeaderSize+len(f.Payload))
	b.SetBytes(int64(len(f.Payload)))
	for i := 0; i < b.N; i++ {
		buf, _ = AppendFrame(buf[:0], f, 64<<10)
	}
}

func BenchmarkReadFrame16KiB(b *testing.B) {
	enc, _ := AppendFrame(nil, Frame{Type: TypeData, Stream: 1, Payload: make([]byte, 16<<10)}, 64<<10)
	b.SetBytes(16 << 10)
	r := bytes.NewReader(enc)
	for i := 0; i < b.N; i++ {
		r.Reset(enc)
		if _, err := ReadFrame(r, 64<<10); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamThroughput measures the multiplexer alone (loopback TCP, no
// HTTP, no TLS): one stream moving b.N*1 MiB.
func BenchmarkStreamThroughput(b *testing.B) {
	srv, cli := pair(b, testCfg())
	done := make(chan struct{})
	go func() {
		st, err := cli.Accept(context.Background())
		if err != nil {
			return
		}
		io.Copy(io.Discard, st)
		close(done)
	}()
	st, err := srv.Open(context.Background(), []byte("m"))
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	st.CloseWrite()
	<-done
}
