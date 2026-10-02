// Package proxy holds the HTTP-semantics helpers of the edge: hop-by-hop
// handling, forwarded headers and platform-error signalling.
package proxy

import (
	"net"
	"net/http"
	"strings"
)

// ErrorHeader marks platform-generated responses so they are distinguishable
// from origin responses. Origin responses may never carry it (stripped).
const ErrorHeader = "X-127ohoh1-Error"

// InternalPrefix is reserved for platform response headers.
const InternalPrefix = "X-127ohoh1-"

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// upgradeHopByHop is hopByHop minus Connection/Upgrade: a genuine protocol
// upgrade needs those two preserved verbatim on both the request and the
// (101) response; every other hop-by-hop header is still meaningless once
// the connection stops being HTTP and is stripped as usual.
var upgradeHopByHop = []string{"Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding"}

// forwardingHeaders are never trusted from the public caller: the edge sets
// its own values from the TCP peer.
var forwardingHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-Ip", "X-Real-Port", "Via", "Traceparent", "Tracestate", "Baggage"}

// StripHopByHop removes hop-by-hop headers, including any header named by the
// Connection header, as required by RFC 9110 section 7.6.1.
func StripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// stripHopByHopKeepUpgrade removes hop-by-hop headers except Connection and
// Upgrade themselves (the Connection header's *other* named tokens, if any,
// are still dropped along with the headers they name).
func stripHopByHopKeepUpgrade(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" && !strings.EqualFold(f, "upgrade") {
				h.Del(f)
			}
		}
	}
	for _, k := range upgradeHopByHop {
		h.Del(k)
	}
}

// RequestHeaders returns the headers to forward to the origin: a copy of the
// public request's headers minus hop-by-hop and any client-supplied
// forwarding/tracing headers.
func RequestHeaders(in http.Header) http.Header {
	out := in.Clone()
	StripHopByHop(out)
	for _, k := range forwardingHeaders {
		out.Del(k)
	}
	out.Del("Host") // carried separately in metadata
	return out
}

// UpgradeRequestHeaders is RequestHeaders for a request that IsUpgrade: it
// keeps Connection/Upgrade (and whatever handshake headers, e.g.
// Sec-WebSocket-*, ride along as ordinary headers already) so the origin can
// complete the protocol switch.
func UpgradeRequestHeaders(in http.Header) http.Header {
	out := in.Clone()
	stripHopByHopKeepUpgrade(out)
	for _, k := range forwardingHeaders {
		out.Del(k)
	}
	out.Del("Host")
	return out
}

// ResponseHeaders returns headers safe to send to the public caller.
func ResponseHeaders(in http.Header) http.Header {
	out := in.Clone()
	StripHopByHop(out)
	for k := range out {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), InternalPrefix) {
			delete(out, k) // an origin must not be able to impersonate a platform error
		}
	}
	return out
}

// UpgradeResponseHeaders is ResponseHeaders for a 101 response: it keeps
// Connection/Upgrade so the public caller sees a valid protocol switch.
func UpgradeResponseHeaders(in http.Header) http.Header {
	out := in.Clone()
	stripHopByHopKeepUpgrade(out)
	for k := range out {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), InternalPrefix) {
			delete(out, k)
		}
	}
	return out
}

// HeaderBytes estimates the wire size of headers (name + value + separators).
func HeaderBytes(h http.Header) int {
	n := 0
	for k, vs := range h {
		for _, v := range vs {
			n += len(k) + len(v) + 4
		}
	}
	return n
}

// PeerIP returns the IP of a TCP peer address, or "" if unparsable.
func PeerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	return host
}

// IsUpgrade reports whether the request asks for a protocol upgrade
// (WebSocket etc.), which this reference does not support.
func IsUpgrade(h http.Header) bool {
	if h.Get("Upgrade") != "" {
		return true
	}
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "upgrade") {
				return true
			}
		}
	}
	return false
}
