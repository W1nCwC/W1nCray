package prismapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type seen struct {
	method, path, query, api, contentType, body string
}

func server(t *testing.T, status int, answer string, rec *seen) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if rec != nil {
			*rec = seen{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("X-Prism-Api"), r.Header.Get("Content-Type"), string(b)}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	c, err := New("tcp:" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEveryRequestCarriesTheApiVersionAndOnlyBodiesCarryAContentType(t *testing.T) {
	var rec seen
	c := server(t, 200, `{"api":1,"state":"idle","boot_id":"b"}`, &rec)

	st, err := c.Status(context.Background())

	if err != nil || st.BootID != "b" || st.State != "idle" {
		t.Fatalf("status = %+v err=%v", st, err)
	}
	if rec.api != "1" || rec.contentType != "" || rec.method != "GET" || rec.path != "/v1/status" {
		t.Fatalf("request = %+v", rec)
	}

	c = server(t, 200, `{"applied":"h","noop":false}`, &rec)
	if _, err := c.Apply(context.Background(), "h", json.RawMessage(`{"inbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	if rec.api != "1" || rec.contentType != "application/json" || rec.method != "PUT" {
		t.Fatalf("apply request = %+v", rec)
	}
	if !strings.Contains(rec.body, `"hash":"h"`) || !strings.Contains(rec.body, `"config":{"inbounds":[]}`) {
		t.Fatalf("apply body = %s", rec.body)
	}
}

func TestPathsAndBodiesAreEncodedForTheKernel(t *testing.T) {
	var rec seen
	c := server(t, 200, `{"applied":true}`, &rec)

	if _, err := c.SetUsers(context.Background(), "node7@machine 1/x", 5, nil); err != nil {
		t.Fatal(err)
	}
	if rec.path != "/v1/users/node7@machine%201%2Fx" {
		t.Fatalf("path = %q", rec.path)
	}
	if !strings.Contains(rec.body, `"users":[]`) || !strings.Contains(rec.body, `"seq":5`) {
		t.Fatalf("a nil user list must encode as []: %s", rec.body)
	}

	c = server(t, 200, `{}`, &rec)
	if err := c.SetDevices(context.Background(), "in", map[int]int{7: 2}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.body, `"alive":{"7":2}`) {
		t.Fatalf("device keys must be strings: %s", rec.body)
	}

	c = server(t, 200, `{"boot_id":"b","snapshot":3}`, &rec)
	if _, err := c.Stats(context.Background(), "a b&c"); err != nil {
		t.Fatal(err)
	}
	if rec.query != "tag=a+b%26c" {
		t.Fatalf("query = %q", rec.query)
	}
}

func TestErrorsKeepTheKernelsWordsAndMapToHelpers(t *testing.T) {
	c := server(t, 422, `{"error":"invalid","message":"missing certificate","kept":"h0"}`, nil)
	_, err := c.Apply(context.Background(), "h1", json.RawMessage(`{}`))
	var pe *Error
	if !errors.As(err, &pe) || !pe.IsInvalid() || pe.Kind != "invalid" || pe.Message != "missing certificate" || pe.Kept != "h0" {
		t.Fatalf("err = %#v", err)
	}
	if IsUnavailable(err) {
		t.Fatal("an answer is not 'unavailable'")
	}

	c = server(t, 404, `{"error":"not_found","message":"no such inbound"}`, nil)
	_, err = c.SetUsers(context.Background(), "x", 1, nil)
	if !errors.As(err, &pe) || !pe.IsNotFound() {
		t.Fatalf("err = %#v", err)
	}

	c = server(t, 409, `{"error":"stale"}`, nil)
	err = c.Commit(context.Background(), "x", 1, "b")
	if !errors.As(err, &pe) || !pe.IsStale() {
		t.Fatalf("err = %#v", err)
	}
}

func TestSuccessWithoutBodyAndABrokenBody(t *testing.T) {
	c := server(t, 200, ``, nil)
	if err := c.Check(context.Background(), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("an empty 2xx body: %v", err)
	}

	c = server(t, 200, `not json`, nil)
	_, err := c.Status(context.Background())
	var pe *Error
	if !errors.As(err, &pe) || pe.Kind != "bad_answer" {
		t.Fatalf("err = %#v", err)
	}
	if IsUnavailable(err) {
		t.Fatal("a kernel that answers garbage is reachable")
	}
}

func TestAnUnreachableKernelIsUnavailableAndBadAddressesAreRefused(t *testing.T) {
	c, err := New("tcp:127.0.0.1:1") // nothing listens there
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Status(context.Background())
	if err == nil || !IsUnavailable(err) {
		t.Fatalf("err = %v, want an 'unavailable' error", err)
	}
	if IsUnavailable(nil) {
		t.Fatal("nil is not unavailable")
	}

	for _, bad := range []string{"", "unix", "unix:", "ftp:host", "tcp"} {
		if _, err := New(bad); err == nil {
			t.Fatalf("New(%q) did not fail", bad)
		}
	}
}
