// Command demo-origin is a tiny HTTP server used by the Docker Compose demo and
// the README quickstart. It is NOT part of the product.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	flag.Parse()
	host, _ := os.Hostname()
	mux := http.NewServeMux()
	// / echoes what the origin sees: proof that forwarded headers come from the edge.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hdr := map[string]string{}
		for _, k := range []string{"Host", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "Traceparent", "User-Agent"} {
			v := r.Header.Get(k)
			if k == "Host" {
				v = r.Host
			}
			hdr[k] = v
		}
		json.NewEncoder(w).Encode(map[string]any{"message": "hello from the demo origin", "origin_host": host, "method": r.Method, "path": r.URL.Path, "seen_headers": hdr})
	})
	// /bytes/N returns N bytes (for bandwidth demos), e.g. /bytes/1000000.
	mux.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/bytes/"))
		if err != nil || n < 0 || n > 1<<30 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 16<<10)
		for n > 0 {
			c := min(n, len(chunk))
			if _, err := w.Write(chunk[:c]); err != nil {
				return
			}
			n -= c
		}
	})
	// /stream emits one line per second for 10 s (response streaming demo).
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 1; i <= 10; i++ {
			fmt.Fprintf(w, "tick %d\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
	})
	log.Printf("demo-origin listening on %s", *addr)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
