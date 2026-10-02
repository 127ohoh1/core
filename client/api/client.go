// Package api is the Go client for the control-plane API. It performs the
// challenge-response login with the local identity and caches the resulting
// short-lived session, refreshing it transparently.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	cid "github.com/127ohoh1/core/client/identity"
	"github.com/127ohoh1/core/protocol/auth"
)

var b64 = base64.RawURLEncoding

// Client talks to the control plane.
type Client struct {
	BaseURL  string
	HTTP     *http.Client
	Identity cid.Identity

	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// New returns a client. httpc may be nil.
func New(baseURL string, id cid.Identity, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{BaseURL: baseURL, HTTP: httpc, Identity: id, now: time.Now}
}

// Error is a structured API error (the platform error envelope).
type Error struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Details   map[string]any
	Body      []byte // raw body, e.g. the full 402 offer document
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message)
}

// IsCode reports whether err is an API error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// do performs a request. For authenticated calls, a 401 that used a *cached*
// session (typically because the control plane restarted and no longer knows
// it) invalidates the session and retries exactly once with a fresh
// challenge-response login. A 401 on a freshly obtained session is final.
func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, in, out any, authed bool) error {
	fresh := false
	if authed {
		c.mu.Lock()
		fresh = c.token == "" || !c.now().Add(30*time.Second).Before(c.expires)
		c.mu.Unlock()
	}
	err := c.doOnce(ctx, method, path, headers, in, out, authed)
	var ae *Error
	if authed && !fresh && errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		c.InvalidateSession()
		return c.doOnce(ctx, method, path, headers, in, out, authed)
	}
	return err
}

// InvalidateSession drops the cached session so the next call logs in again.
func (c *Client) InvalidateSession() {
	c.mu.Lock()
	c.token, c.expires = "", time.Time{}
	c.mu.Unlock()
}

func (c *Client) doOnce(ctx context.Context, method, path string, headers map[string]string, in, out any, authed bool) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if authed {
		tok, err := c.session(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var env struct {
			Error struct {
				Code      string         `json:"code"`
				Message   string         `json:"message"`
				RequestID string         `json:"request_id"`
				Details   map[string]any `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		return &Error{Status: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message,
			RequestID: env.Error.RequestID, Details: env.Error.Details, Body: raw}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Login performs the challenge-response flow and returns a session token.
func (c *Client) Login(ctx context.Context) (string, time.Time, error) {
	var ch struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Audience    string `json:"audience"`
		IssuedAt    string `json:"issued_at"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := c.do(ctx, "POST", "/v1/auth/challenges", nil, map[string]string{"public_key": c.Identity.PublicKeyString()}, &ch, false); err != nil {
		return "", time.Time{}, err
	}
	nonce, err := b64.Strict().DecodeString(ch.Nonce)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("bad nonce from server: %w", err)
	}
	issued, err1 := time.Parse(time.RFC3339, ch.IssuedAt)
	expires, err2 := time.Parse(time.RFC3339, ch.ExpiresAt)
	if err1 != nil || err2 != nil {
		return "", time.Time{}, errors.New("bad challenge timestamps from server")
	}
	sig, err := auth.SignChallenge(c.Identity.Private, auth.Challenge{
		ID: ch.ChallengeID, Nonce: nonce, Audience: ch.Audience, Fingerprint: c.Identity.Fingerprint(),
		IssuedAt: issued, ExpiresAt: expires,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	var sess struct {
		Token     string `json:"session_token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.do(ctx, "POST", "/v1/auth/sessions", nil, map[string]string{
		"challenge_id": ch.ChallengeID, "nonce": ch.Nonce, "signature": b64.EncodeToString(sig)}, &sess, false); err != nil {
		return "", time.Time{}, err
	}
	exp, _ := time.Parse(time.RFC3339, sess.ExpiresAt)
	return sess.Token, exp, nil
}

func (c *Client) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Add(30*time.Second).Before(c.expires) {
		return c.token, nil
	}
	tok, exp, err := c.Login(ctx)
	if err != nil {
		return "", err
	}
	c.token, c.expires = tok, exp
	return tok, nil
}

// Endpoint mirrors the API's endpoint view.
type Endpoint struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	URL          string `json:"url"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Plan         string `json:"plan"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
}

// CreateEndpoint creates a random free endpoint. A non-empty idempotencyKey
// makes retries return the original endpoint.
func (c *Client) CreateEndpoint(ctx context.Context, idempotencyKey string) (Endpoint, error) {
	var e Endpoint
	h := map[string]string{}
	if idempotencyKey != "" {
		h["Idempotency-Key"] = idempotencyKey
	}
	err := c.do(ctx, "POST", "/v1/endpoints", h, map[string]string{"kind": "random"}, &e, true)
	return e, err
}

// DashboardLink is a one-time link that signs in to the web dashboard as the
// account this key belongs to.
type DashboardLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateDashboardLink asks for a one-time dashboard sign-in link.
func (c *Client) CreateDashboardLink(ctx context.Context) (DashboardLink, error) {
	var l DashboardLink
	err := c.do(ctx, "POST", "/v1/dashboard-links", nil, map[string]string{}, &l, true)
	return l, err
}

// LinkCode is a short code that links this key to an existing account when
// entered in its dashboard.
type LinkCode struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateLinkCode asks for a device-link code.
func (c *Client) CreateLinkCode(ctx context.Context) (LinkCode, error) {
	var l LinkCode
	err := c.do(ctx, "POST", "/v1/device-links", nil, map[string]string{}, &l, true)
	return l, err
}

// ListEndpoints lists the caller's live endpoints.
func (c *Client) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	var out struct {
		Endpoints []Endpoint `json:"endpoints"`
	}
	err := c.do(ctx, "GET", "/v1/endpoints", nil, nil, &out, true)
	return out.Endpoints, err
}

// GetEndpoint fetches one endpoint.
func (c *Client) GetEndpoint(ctx context.Context, id string) (Endpoint, error) {
	var e Endpoint
	err := c.do(ctx, "GET", "/v1/endpoints/"+id, nil, nil, &e, true)
	return e, err
}

// DeleteEndpoint releases an endpoint.
func (c *Client) DeleteEndpoint(ctx context.Context, id string) (Endpoint, error) {
	var e Endpoint
	err := c.do(ctx, "DELETE", "/v1/endpoints/"+id, nil, nil, &e, true)
	return e, err
}

// TunnelCredential is a short-lived credential for the edge.
type TunnelCredential struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	EndpointID string    `json:"endpoint_id"`
	Hostname   string    `json:"hostname"`
	URL        string    `json:"url"`
	Edge       struct {
		Addr     string `json:"addr"`
		Audience string `json:"audience"`
	} `json:"edge"`
}

// TunnelCredentials requests a credential for the endpoint.
func (c *Client) TunnelCredentials(ctx context.Context, endpointID string) (TunnelCredential, error) {
	var t TunnelCredential
	err := c.do(ctx, "POST", "/v1/endpoints/"+endpointID+"/tunnel-credentials", nil, nil, &t, true)
	return t, err
}

// Plan is one entry of GET /v1/plans.
type Plan struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Price struct {
		Amount   string `json:"amount"`
		Asset    string `json:"asset"`
		Interval string `json:"interval"`
		Unit     string `json:"unit"`
	} `json:"price"`
	BandwidthBytesPerSecond int64  `json:"bandwidth_bytes_per_second"`
	BurstBytes              int64  `json:"burst_bytes"`
	MonthlyTransferBytes    int64  `json:"monthly_transfer_bytes"`
	Hostname                string `json:"hostname"`
}

// Plans lists the plan catalog (no authentication needed).
func (c *Client) Plans(ctx context.Context) ([]Plan, error) {
	var out struct {
		Plans []Plan `json:"plans"`
	}
	err := c.do(ctx, "GET", "/v1/plans", nil, nil, &out, false)
	return out.Plans, err
}

// PaymentMethod is one way to pay an offer.
type PaymentMethod struct {
	Type           string `json:"type"`
	Network        string `json:"network"`
	Asset          string `json:"asset"`
	PaymentRequest string `json:"payment_request"`
	Simulated      bool   `json:"simulated"`
}

// Offer is an offer as returned by the 402 body and the offers API.
type Offer struct {
	ID     string `json:"id"`
	Plan   string `json:"plan"`
	Status string `json:"status"`
	Scope  struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"scope"`
	Price struct {
		Amount   string `json:"amount"`
		Asset    string `json:"asset"`
		Interval string `json:"interval"`
		Unit     string `json:"unit"`
	} `json:"price"`
	Limits struct {
		BandwidthBytesPerSecond int64 `json:"bandwidth_bytes_per_second"`
		MonthlyTransferBytes    int64 `json:"monthly_transfer_bytes"`
	} `json:"limits"`
	PaymentMethods []PaymentMethod `json:"payment_methods"`
	PaymentID      string          `json:"payment_id"`
	ExpiresAt      time.Time       `json:"expires_at"`
	StatusURL      string          `json:"status_url"`
	// CheckoutURL, when the server offers one, is a browser page where anyone
	// holding the link can pay this one offer with their own wallet.
	CheckoutURL string `json:"checkout_url,omitempty"`
}

// PaymentRequired is the parsed 402 response.
type PaymentRequired struct {
	Resource struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"resource"`
	Offers []Offer `json:"offers"`
}

// Reserve asks for a reserved hostname. If a payment is needed it returns
// (zero Endpoint, *PaymentRequired, nil); the caller decides whether to pay.
func (c *Client) Reserve(ctx context.Context, name, plan, idempotencyKey string) (Endpoint, *PaymentRequired, error) {
	var e Endpoint
	h := map[string]string{}
	if idempotencyKey != "" {
		h["Idempotency-Key"] = idempotencyKey
	}
	err := c.do(ctx, "POST", "/v1/endpoints/reserve", h, map[string]string{"name": name, "plan": plan}, &e, true)
	var ae *Error
	if errors.As(err, &ae) && ae.Status == http.StatusPaymentRequired {
		var pr PaymentRequired
		if jerr := json.Unmarshal(ae.Body, &pr); jerr != nil || len(pr.Offers) == 0 {
			return Endpoint{}, nil, fmt.Errorf("malformed 402 response from server")
		}
		return Endpoint{}, &pr, nil
	}
	return e, nil, err
}

// Payment is a payment document.
type Payment struct {
	ID        string `json:"id"`
	OfferID   string `json:"offer_id"`
	State     string `json:"state"`
	Amount    string `json:"amount"`
	Asset     string `json:"asset"`
	Network   string `json:"network"`
	Simulated bool   `json:"simulated"`
	Reason    string `json:"failure_reason"`
}

// OfferStatus is the offer plus its payment.
type OfferStatus struct {
	Offer   Offer   `json:"offer"`
	Payment Payment `json:"payment"`
	// Certificate is set when the service warms an HTTPS certificate for a
	// newly paid name (nil: nothing to wait for).
	Certificate *CertificateStatus `json:"certificate,omitempty"`
}

// CertificateStatus tracks the certificate for a newly paid name.
type CertificateStatus struct {
	Hostname string `json:"hostname"`
	State    string `json:"state"` // pending | ready | failed
}

// GetOffer fetches an offer and its payment.
func (c *Client) GetOffer(ctx context.Context, id string) (OfferStatus, error) {
	var o OfferStatus
	err := c.do(ctx, "GET", "/v1/offers/"+id, nil, nil, &o, true)
	return o, err
}

// SimulateSettlement triggers a simulated settlement (development mode only).
func (c *Client) SimulateSettlement(ctx context.Context, paymentID string) (Payment, error) {
	var p Payment
	err := c.do(ctx, "POST", "/v1/payments/"+paymentID+"/simulate-settlement", nil, nil, &p, true)
	return p, err
}
