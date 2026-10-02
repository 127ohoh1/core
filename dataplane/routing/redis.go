package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/127ohoh1/core/internal/redisc"
)

// Redis is the multi-edge DEVELOPMENT tunnel directory. Ownership is a short
// lease stored under two keys (endpoint -> owner JSON, hostname -> endpoint id)
// and every read-modify-write runs as a Lua script, so Claim/Heartbeat/Release
// are atomic even with several edges racing. Redis is not a source of truth:
// it is rebuilt from live sessions by heartbeats and lost leases simply expire.
type Redis struct {
	c      *redisc.Client
	prefix string
}

// NewRedis builds a directory from a redis:// URL.
func NewRedis(url string) (*Redis, error) {
	c, err := redisc.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Redis{c: c, prefix: "ohoh:"}, nil
}

// Close releases connections.
func (r *Redis) Close() { r.c.Close() }

func (r *Redis) epKey(id string) string  { return r.prefix + "ep:" + id }
func (r *Redis) hostKey(h string) string { return r.prefix + "host:" + h }

const claimScript = `
local prev = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
return prev or false
`

const heartbeatScript = `
local v = redis.call('GET', KEYS[1])
if not v then return 0 end
local o = cjson.decode(v)
if o.session_id ~= ARGV[1] then return 0 end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
redis.call('PEXPIRE', KEYS[2], ARGV[2])
return 1
`

const releaseScript = `
local v = redis.call('GET', KEYS[1])
if not v then return 0 end
local o = cjson.decode(v)
if o.session_id ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
return 1
`

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

func (r *Redis) eval(ctx context.Context, script string, keys []string, args ...string) (any, error) {
	a := []string{"EVAL", script, strconv.Itoa(len(keys))}
	a = append(a, keys...)
	a = append(a, args...)
	v, err := r.c.Do(ctx, a...)
	if errors.Is(err, redisc.ErrNil) {
		return nil, nil // Lua false -> nil bulk
	}
	return v, err
}

func (r *Redis) Claim(ctx context.Context, o Owner, ttl time.Duration) (*Owner, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	v, err := r.eval(ctx, claimScript, []string{r.epKey(o.EndpointID), r.hostKey(o.Hostname)}, string(b), o.EndpointID, ms(ttl))
	if err != nil {
		return nil, fmt.Errorf("directory claim: %w", err)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, nil
	}
	var prev Owner
	if json.Unmarshal([]byte(s), &prev) != nil {
		return nil, nil
	}
	return &prev, nil
}

func (r *Redis) Heartbeat(ctx context.Context, endpointID, sessionID string, ttl time.Duration) error {
	// The hostname key is derived from the stored owner; we only know the endpoint
	// here, so read it first for the key name (Lua cannot build keys it was not given).
	o, err := r.owner(ctx, endpointID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrSuperseded
		}
		return err
	}
	v, err := r.eval(ctx, heartbeatScript, []string{r.epKey(endpointID), r.hostKey(o.Hostname)}, sessionID, ms(ttl))
	if err != nil {
		return fmt.Errorf("directory heartbeat: %w", err)
	}
	if n, _ := v.(int64); n != 1 {
		return ErrSuperseded
	}
	return nil
}

func (r *Redis) Release(ctx context.Context, endpointID, sessionID string) error {
	o, err := r.owner(ctx, endpointID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	_, err = r.eval(ctx, releaseScript, []string{r.epKey(endpointID), r.hostKey(o.Hostname)}, sessionID, endpointID)
	return err
}

func (r *Redis) owner(ctx context.Context, endpointID string) (Owner, error) {
	v, err := r.c.Do(ctx, "GET", r.epKey(endpointID))
	if errors.Is(err, redisc.ErrNil) {
		return Owner{}, ErrNotFound
	}
	if err != nil {
		return Owner{}, err
	}
	var o Owner
	if err := json.Unmarshal([]byte(v.(string)), &o); err != nil {
		return Owner{}, fmt.Errorf("directory: corrupt owner record: %w", err)
	}
	return o, nil
}

func (r *Redis) Lookup(ctx context.Context, hostname string) (Owner, error) {
	v, err := r.c.Do(ctx, "GET", r.hostKey(hostname))
	if errors.Is(err, redisc.ErrNil) {
		return Owner{}, ErrNotFound
	}
	if err != nil {
		return Owner{}, err
	}
	return r.owner(ctx, v.(string))
}
