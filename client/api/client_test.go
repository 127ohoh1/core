package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/protocol/auth"
)

// fakeCP issues sessions and accepts only the most recently issued one,
// modelling a control plane that restarted and forgot older sessions.
type fakeCP struct {
	logins  atomic.Int32
	current atomic.Value
	calls   atomic.Int32
	reject  atomic.Bool // refuse every session, even a fresh one
}

func (f *fakeCP) handler(t *testing.T, pub ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()
	var ch auth.Challenge
	mux.HandleFunc("POST /v1/auth/challenges", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC().Truncate(time.Second)
		ch = auth.Challenge{ID: "ch_1", Nonce: make([]byte, 32), Audience: "aud", Fingerprint: auth.Fingerprint(pub), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
		json.NewEncoder(w).Encode(map[string]any{"challenge_id": ch.ID, "nonce": auth.EncodeSig(ch.Nonce), "audience": ch.Audience,
			"issued_at": ch.IssuedAt.Format(time.RFC3339), "expires_at": ch.ExpiresAt.Format(time.RFC3339)})
	})
	mux.HandleFunc("POST /v1/auth/sessions", func(w http.ResponseWriter, r *http.Request) {
		n := f.logins.Add(1)
		tok := "session-" + string(rune('0'+n))
		f.current.Store(tok)
		json.NewEncoder(w).Encode(map[string]any{"session_token": tok, "expires_at": time.Now().Add(15 * time.Minute).Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if f.reject.Load() || r.Header.Get("Authorization") != "Bearer "+f.current.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "unauthorized", "message": "no"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"endpoints": []any{}})
	})
	return mux
}

func TestStaleSessionTriggersOneRelogin(t *testing.T) {
	dir := t.TempDir()
	id, _ := cid.Generate(dir + "/id")
	f := &fakeCP{}
	f.current.Store("none")
	srv := httptest.NewServer(f.handler(t, id.Public))
	defer srv.Close()
	c := New(srv.URL, id, nil)

	if _, err := c.ListEndpoints(bg()); err != nil {
		t.Fatal(err)
	}
	if f.logins.Load() != 1 {
		t.Fatalf("logins %d", f.logins.Load())
	}
	// The control plane "restarts" and forgets our session: the next call must
	// recover transparently with exactly one more login.
	f.current.Store("some-other-session")
	if _, err := c.ListEndpoints(bg()); err != nil {
		t.Fatalf("stale session not recovered: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins %d, want 2", f.logins.Load())
	}
	// A server that rejects *fresh* sessions must not cause a login storm.
	f.reject.Store(true)
	c2 := New(srv.URL, id, nil)
	f.logins.Store(0)
	f.calls.Store(0)
	_, err := c2.ListEndpoints(bg())
	if err == nil || !IsCode(err, "unauthorized") {
		t.Fatalf("got %v", err)
	}
	if f.logins.Load() != 1 || f.calls.Load() != 1 {
		t.Fatalf("retry storm: logins=%d calls=%d", f.logins.Load(), f.calls.Load())
	}
}

func bg() context.Context { return context.Background() }
