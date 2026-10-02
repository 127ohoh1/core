package ingress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/127ohoh1/core/dataplane/proxy"
	proto "github.com/127ohoh1/core/protocol/tunnel"
)

// idleWatchdog ends an exchange after no progress at all for a given
// duration. One instance is shared across every direction of one exchange
// (request body, response body, or an upgraded connection's two directions)
// so "no progress in either direction" is enforced jointly, not per-phase.
type idleWatchdog struct{ t *time.Timer }

func newIdleWatchdog(d time.Duration, onExpire func()) *idleWatchdog {
	return &idleWatchdog{t: time.AfterFunc(d, onExpire)}
}

// touch resets the watchdog: call it on every chunk of progress.
func (w *idleWatchdog) touch(d time.Duration) { w.t.Reset(d) }

// stop disarms the watchdog permanently.
func (w *idleWatchdog) stop() { w.t.Stop() }

// serveUpgrade relays an accepted protocol upgrade (101 Switching Protocols):
// it hijacks the public connection, writes the raw status line and headers
// itself (http.ResponseWriter has no notion of "switch protocols and keep
// going"), then pumps bytes bidirectionally between that connection and the
// tunnel stream until either side ends. Mirrors
// net/http/httputil.ReverseProxy's handleUpgradeResponse.
//
// hijacked reports whether the public connection was successfully taken over
// (false only if the underlying ResponseWriter doesn't support Hijack, e.g.
// an HTTP/2 connection — real upgrade handshakes arrive over HTTP/1.1, so
// this is a defensive fallback, not an expected path). When hijacked is
// false, nothing has been written to the client and the caller may still
// send a normal platform error.
func (h *Handler) serveUpgrade(w *respWriter, rc *http.ResponseController, st *proto.Stream, resp proto.ResponseMeta, gate Gate, watchdog *idleWatchdog) (hijacked bool, bytesIn, bytesOut int64) {
	conn, brw, err := rc.Hijack()
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()

	status := resp.Status
	if status == 0 {
		status = http.StatusSwitchingProtocols
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for k, vs := range proxy.UpgradeResponseHeaders(resp.Header) {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	if _, err := brw.WriteString(sb.String()); err != nil {
		return true, 0, 0
	}
	if err := brw.Flush(); err != nil {
		return true, 0, 0
	}

	ctx := st.Context()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bytesIn, _ = h.copyGated(ctx, st, brw, gate, ToTunnel, watchdog)
		_ = st.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		bytesOut, _ = h.copyGated(ctx, conn, st, gate, FromTunnel, watchdog)
		closeWriteOrClose(conn)
	}()
	wg.Wait()
	return true, bytesIn, bytesOut
}

// closeWriteOrClose half-closes conn's send side if possible, otherwise
// closes it outright.
func closeWriteOrClose(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

// copyGated copies from src to dst, applying gate accounting per direction
// and touching watchdog on every chunk of progress. It stops cleanly on EOF
// (nil error) or returns the first error.
func (h *Handler) copyGated(ctx context.Context, dst io.Writer, src io.Reader, gate Gate, dir Direction, watchdog *idleWatchdog) (int64, error) {
	bp := h.bufs.Get().(*[]byte)
	defer h.bufs.Put(bp)
	buf := *bp
	var total int64
	dirName := "in"
	if dir == FromTunnel {
		dirName = "out"
	}
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			watchdog.touch(h.cfg.IdleTimeout)
			if err := gate.Wait(ctx, n); err != nil {
				return total, err
			}
			if err := gate.Account(n, dir); err != nil {
				return total, err
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
			h.m.Bytes.Add(float64(n), dirName)
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}
