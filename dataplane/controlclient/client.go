// Package controlclient is the edge's HTTP client for the control plane. It
// authenticates with the edge service token and never sees payment data.
package controlclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/127ohoh1/core/dataplane/metering"
	"github.com/127ohoh1/core/protocol/auth"
	pp "github.com/127ohoh1/core/protocol/policy"
)

// Client calls the control-plane service API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a client with sane timeouts.
func New(baseURL, token string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{} // deadlines come from the per-call context (long-polls need longer ones)
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: httpc}
}

// StatusError is a non-2xx response.
type StatusError struct {
	Status int
	Code   string
}

// HTTPStatus lets callers classify errors without importing this type.
func (e *StatusError) HTTPStatus() int { return e.Status }

func (e *StatusError) Error() string {
	return fmt.Sprintf("control plane returned %d (%s)", e.Status, e.Code)
}

// Do performs a request and decodes a JSON response into out (may be nil).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		return &StatusError{Status: resp.StatusCode, Code: env.Error.Code}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Keys fetches the current verification key set.
func (c *Client) Keys(ctx context.Context) (auth.KeySet, error) {
	var out struct {
		Keys []struct {
			KID       string `json:"kid"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := c.Do(ctx, "GET", "/v1/keys", nil, &out); err != nil {
		return nil, err
	}
	ks := auth.KeySet{}
	for _, k := range out.Keys {
		pub, err := auth.ParsePublicKey(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("control plane published a bad key %q", k.KID)
		}
		ks[k.KID] = ed25519.PublicKey(pub)
	}
	if len(ks) == 0 {
		return nil, errors.New("control plane published no keys")
	}
	return ks, nil
}

// KeyCache keeps the last good key set so tunnel credentials keep verifying
// locally while the control plane is unreachable. An unknown key id (a key
// rotation) triggers a rate-limited refresh.
type KeyCache struct {
	fetch func(context.Context) (auth.KeySet, error)
	mu    sync.RWMutex
	keys  auth.KeySet
	last  time.Time
	min   time.Duration // minimum spacing of on-demand refreshes
	now   func() time.Time
}

// NewKeyCache creates a cache using fetch.
func NewKeyCache(fetch func(context.Context) (auth.KeySet, error)) *KeyCache {
	return &KeyCache{fetch: fetch, min: 5 * time.Second, now: time.Now}
}

// Refresh loads keys now. On failure the previous set is retained.
func (k *KeyCache) Refresh(ctx context.Context) error {
	ks, err := k.fetch(ctx)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.keys, k.last = ks, k.now()
	k.mu.Unlock()
	return nil
}

// Set replaces the key set directly (tests, static configuration).
func (k *KeyCache) Set(ks auth.KeySet) {
	k.mu.Lock()
	k.keys, k.last = ks, k.now()
	k.mu.Unlock()
}

// Keys returns the current key set.
func (k *KeyCache) Keys() auth.KeySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys
}

// Verify verifies a token; if its key id is unknown it refreshes once (at
// most every min) and retries.
func (k *KeyCache) Verify(ctx context.Context, token, typ, aud string, now time.Time) (auth.Claims, error) {
	c, err := k.Keys().Verify(token, typ, aud, now)
	if !errors.Is(err, auth.ErrTokenUnknownKey) {
		return c, err
	}
	k.mu.RLock()
	recent := k.now().Sub(k.last) < k.min
	k.mu.RUnlock()
	if recent {
		return c, err
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if rerr := k.Refresh(rctx); rerr != nil {
		k.mu.Lock()
		k.last = k.now() // back off even on failure
		k.mu.Unlock()
		return c, err
	}
	return k.Keys().Verify(token, typ, aud, now)
}

// Run refreshes periodically until ctx is done.
func (k *KeyCache) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = k.Refresh(rctx) // failure keeps the cached set
			cancel()
		}
	}
}

// Policy fetches the resolved policy of one endpoint.
func (c *Client) Policy(ctx context.Context, endpointID string) (pp.EndpointPolicy, error) {
	var p pp.EndpointPolicy
	if err := c.Do(ctx, "GET", "/v1/endpoints/"+endpointID+"/policy", nil, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

// HostnameStatus asks what the control plane knows about one tenant label.
// An unknown label is a *StatusError with Status 404.
func (c *Client) HostnameStatus(ctx context.Context, label string) (pp.HostnameStatus, error) {
	var h pp.HostnameStatus
	err := c.Do(ctx, "GET", "/v1/hostnames/"+url.PathEscape(label), nil, &h)
	return h, err
}

// PolicyChanges long-polls the change feed.
func (c *Client) PolicyChanges(ctx context.Context, since int64, wait time.Duration) (pp.Changes, error) {
	var out pp.Changes
	cctx, cancel := context.WithTimeout(ctx, wait+10*time.Second)
	defer cancel()
	err := c.Do(cctx, "GET", fmt.Sprintf("/v1/policies/changes?since=%d&wait=%d", since, int(wait/time.Second)), nil, &out)
	return out, err
}

// Send delivers a usage batch (implements metering.Sink). Client errors that
// retrying cannot fix are wrapped as metering.ErrPermanent so a poison batch
// cannot wedge the queue; auth and server errors stay retryable so usage is
// never dropped because of a misconfigured token or an outage.
func (c *Client) Send(ctx context.Context, b metering.Batch) (metering.Result, error) {
	var res metering.Result
	err := c.Do(ctx, "POST", "/v1/usage/batches", b, &res)
	var se *StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case 400, 413, 422:
			return res, errors.Join(metering.ErrPermanent, err)
		}
	}
	return res, err
}

// PresenceUpdate reports tunnel connectivity of one endpoint.
type PresenceUpdate struct {
	EndpointID string    `json:"endpoint_id"`
	Connected  bool      `json:"connected"`
	At         time.Time `json:"at"`
}

// Presence reports tunnel connectivity.
func (c *Client) Presence(ctx context.Context, edgeID string, updates []PresenceUpdate) error {
	return c.Do(ctx, "POST", "/v1/presence", map[string]any{"edge_id": edgeID, "updates": updates}, nil)
}
