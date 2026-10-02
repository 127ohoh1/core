// Package redisc is a deliberately tiny Redis client (RESP2, no pipelining, a
// small connection pool) used by the development tunnel directory. It exists to
// keep the dependency set at zero; a production deployment would use a
// maintained client behind the same TunnelDirectory interface.
package redisc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNil is returned for a nil bulk reply.
var ErrNil = errors.New("redisc: nil reply")

// Client is a small pooled Redis client.
type Client struct {
	addr     string
	password string
	db       string
	timeout  time.Duration

	mu   sync.Mutex
	idle []*conn
}

type conn struct {
	c net.Conn
	r *bufio.Reader
}

// ParseURL accepts redis://[:password@]host:port[/db].
func ParseURL(raw string) (*Client, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "redis" || u.Host == "" {
		return nil, fmt.Errorf("redisc: invalid URL (want redis://host:port/db)")
	}
	c := &Client{addr: u.Host, timeout: 2 * time.Second}
	if u.User != nil {
		c.password, _ = u.User.Password()
	}
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		if _, err := strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("redisc: invalid db %q", p)
		}
		c.db = p
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (*conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	cn := &conn{c: nc, r: bufio.NewReaderSize(nc, 4096)}
	if c.password != "" {
		if _, err := c.roundTrip(cn, []string{"AUTH", c.password}); err != nil {
			nc.Close()
			return nil, err
		}
	}
	if c.db != "" {
		if _, err := c.roundTrip(cn, []string{"SELECT", c.db}); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return cn, nil
}

func (c *Client) get(ctx context.Context) (*conn, error) {
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		cn := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return cn, nil
	}
	c.mu.Unlock()
	return c.dial(ctx)
}

func (c *Client) put(cn *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.idle) < 8 {
		c.idle = append(c.idle, cn)
		return
	}
	cn.c.Close()
}

// Close closes idle connections.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cn := range c.idle {
		cn.c.Close()
	}
	c.idle = nil
}

// Do sends a command and returns its reply as string, int64, []any or error.
// A Redis error reply is returned as a Go error. Transport errors discard the
// connection.
func (c *Client) Do(ctx context.Context, args ...string) (any, error) {
	cn, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		cn.c.SetDeadline(dl)
	} else {
		cn.c.SetDeadline(time.Now().Add(c.timeout))
	}
	v, err := c.roundTrip(cn, args)
	var re redisError
	if err != nil && !errors.As(err, &re) {
		cn.c.Close() // desynchronised or broken: never reuse
		return nil, err
	}
	c.put(cn)
	return v, err
}

type redisError string

func (e redisError) Error() string { return "redis: " + string(e) }

func (c *Client) roundTrip(cn *conn, args []string) (any, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(cn.c, b.String()); err != nil {
		return nil, err
	}
	return readReply(cn.r, 0)
}

func readReply(r *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("redisc: reply nesting too deep")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, errors.New("redisc: short reply")
	}
	body := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return nil, redisError(body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, ErrNil
		}
		if n > 1<<20 {
			return nil, errors.New("redisc: bulk reply too large")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n > 1024 {
			return nil, errors.New("redisc: bad array reply")
		}
		if n < 0 {
			return nil, ErrNil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := readReply(r, depth+1)
			if err != nil && !errors.Is(err, ErrNil) {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("redisc: unknown reply type %q", line[0])
}
