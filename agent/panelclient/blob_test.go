package panelclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientBlobGet covers the happy path: the body is returned with its ETag
// and the request carries the machine credentials and the sha256 in the path.
func TestClientBlobGet(t *testing.T) {
	body := []byte("route.json content")
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	var gotPath, gotMachine, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMachine, gotAuth = r.URL.Path, r.Header.Get("X-Machine-Id"), r.Header.Get("Authorization")
		w.Header().Set("ETag", `"`+sha+`"`)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	res, err := c.Blob(context.Background(), BlobRequest{SHA256: sha})
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if res.NotModified || string(res.Raw) != string(body) {
		t.Fatalf("res = %+v", res)
	}
	if res.ETag != `"`+sha+`"` {
		t.Errorf("etag = %q", res.ETag)
	}
	if gotPath != testPrefix+"file/"+sha {
		t.Errorf("path = %q, want %q", gotPath, testPrefix+"file/"+sha)
	}
	if gotMachine != "7" || gotAuth != "Bearer "+testToken {
		t.Errorf("credentials: machine=%q auth=%q", gotMachine, gotAuth)
	}
}

// TestClientBlobAnswers covers the answer shapes the applier relies on: 304,
// a non-2xx error, an oversized body, and an ETag that names other bytes.
func TestClientBlobAnswers(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	sha := hex.EncodeToString(sum[:])

	t.Run("304 is not modified", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-None-Match") == "" {
				t.Error("the If-None-Match header was not sent")
			}
			w.WriteHeader(http.StatusNotModified)
		}))
		defer srv.Close()
		res, err := newClient(t, srv).Blob(context.Background(), BlobRequest{SHA256: sha, ETag: `"` + sha + `"`})
		if err != nil {
			t.Fatalf("Blob: %v", err)
		}
		if !res.NotModified || len(res.Raw) != 0 {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("404 is an APIError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found","message":"no such blob"}`)
		}))
		defer srv.Close()
		_, err := newClient(t, srv).Blob(context.Background(), BlobRequest{SHA256: sha})
		var api *APIError
		if !errors.As(err, &api) || api.Status != http.StatusNotFound || api.Code != "not_found" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("oversized body is refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", MaxBlobBytes+1))
		}))
		defer srv.Close()
		_, err := newClient(t, srv).Blob(context.Background(), BlobRequest{SHA256: sha})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("mismatching ETag is refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"`+strings.Repeat("a", 64)+`"`)
			_, _ = w.Write([]byte("body"))
		}))
		defer srv.Close()
		_, err := newClient(t, srv).Blob(context.Background(), BlobRequest{SHA256: sha})
		if err == nil || !strings.Contains(err.Error(), "ETag") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a non-digest address never reaches the wire", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("a request was built for an invalid address")
		}))
		defer srv.Close()
		for _, bad := range []string{"", "abc", "../../etc/passwd", strings.ToUpper(sha), sha + "0"} {
			if _, err := newClient(t, srv).Blob(context.Background(), BlobRequest{SHA256: bad}); err == nil {
				t.Errorf("address %q was accepted", bad)
			}
		}
	})
}

// TestValidSHA256 pins the digest rule the blob path depends on.
func TestValidSHA256(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !ValidSHA256(good) {
		t.Errorf("ValidSHA256(%q) = false", good)
	}
	for _, bad := range []string{"", "0", strings.ToUpper(good), good[:63], good + "0", "g" + good[1:]} {
		if ValidSHA256(bad) {
			t.Errorf("ValidSHA256(%q) = true", bad)
		}
	}
}
