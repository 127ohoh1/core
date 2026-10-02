package apperr

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassification(t *testing.T) {
	wrapped := fmt.Errorf("op: %w", ErrNotFound.Wrap(errors.New("sql: no rows")))
	if !errors.Is(wrapped, ErrNotFound) {
		t.Fatal("sentinel lost through wrapping")
	}
	if errors.Is(wrapped, ErrConflict) {
		t.Fatal("false match")
	}
	if As(errors.New("boom")).Code != "internal" {
		t.Fatal("unclassified must be internal")
	}
}

func TestWriteDoesNotLeakCause(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, ErrInternal.Wrap(errors.New("pq: password authentication failed")), "req_1")
	body := rec.Body.String()
	if strings.Contains(body, "pq:") || rec.Code != 500 {
		t.Fatalf("leak or wrong status: %d %s", rec.Code, body)
	}
	if !strings.Contains(body, `"request_id":"req_1"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bad envelope: %s", body)
	}
}
