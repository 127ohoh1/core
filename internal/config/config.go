// Package config loads typed, validated configuration from an optional JSON
// file with environment overrides (env wins). Validation failures are fatal at
// startup: there is no silent fallback to insecure behaviour.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that (un)marshals as a Go duration string.
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Environments.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
	EnvProduction  = "production"
)

// Load fills dst (a pointer to struct) from the JSON file at path (may be
// empty), then applies `env:"NAME"` overrides using the given prefix.
func Load(dst any, path, prefix string) error {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read config %s: %w", path, err)
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	return applyEnv(reflect.ValueOf(dst).Elem(), prefix, os.LookupEnv)
}

func applyEnv(v reflect.Value, prefix string, lookup func(string) (string, bool)) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Tag.Get("env")
		if name == "" {
			continue
		}
		raw, ok := lookup(prefix + name)
		if !ok {
			continue
		}
		f := v.Field(i)
		switch f.Interface().(type) {
		case string:
			f.SetString(raw)
		case bool:
			b, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("%s%s: %w", prefix, name, err)
			}
			f.SetBool(b)
		case int:
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%s%s: %w", prefix, name, err)
			}
			f.SetInt(int64(n))
		case int64:
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return fmt.Errorf("%s%s: %w", prefix, name, err)
			}
			f.SetInt(n)
		case Duration:
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("%s%s: %w", prefix, name, err)
			}
			f.SetInt(int64(d))
		default:
			return fmt.Errorf("%s%s: unsupported type %s", prefix, name, f.Type())
		}
	}
	return nil
}

// Problems accumulates validation errors so all are reported at once.
type Problems []string

func (p *Problems) Addf(format string, a ...any) { *p = append(*p, fmt.Sprintf(format, a...)) }

func (p Problems) Err() error {
	if len(p) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration: %s", strings.Join(p, "; "))
}
