package noderelay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

const token = "machine-token"

// panelFake records the frames the relay sends and can answer them.
type panelFake struct {
	mu     sync.Mutex
	frames []wsproto.Envelope
	reqs   map[string]*wsproto.NodeReq
	body   map[string]*bytes.Buffer
	fail   error
	answer func(id string, req wsproto.NodeReq, body []byte)
}

func (p *panelFake) send(env wsproto.Envelope) error {
	p.mu.Lock()
	if p.fail != nil {
		p.mu.Unlock()
		return p.fail
	}
	p.frames = append(p.frames, env)
	var req wsproto.NodeReq
	if err := json.Unmarshal(env.D, &req); err != nil {
		p.mu.Unlock()
		return err
	}
	if p.reqs == nil {
		p.reqs, p.body = map[string]*wsproto.NodeReq{}, map[string]*bytes.Buffer{}
	}
	if p.reqs[env.ID] == nil {
		head := req
		p.reqs[env.ID] = &head
		p.body[env.ID] = &bytes.Buffer{}
	}
	b, _ := base64.StdEncoding.DecodeString(req.Body)
	p.body[env.ID].Write(b)
	head, body, answer := *p.reqs[env.ID], p.body[env.ID].Bytes(), p.answer
	p.mu.Unlock()
	if !req.More && answer != nil {
		go answer(env.ID, head, body)
	}
	return nil
}

func newRelay(t *testing.T, p *panelFake, enabled bool) *Relay {
	t.Helper()
	r := New(Options{MachineID: 7, Token: token, Timeout: 2 * time.Second})
	r.SetSend(p.send)
	if enabled {
		r.SetPanel(&wsproto.NodeRelayCtl{Enabled: true})
	}
	return r
}

func request(method, name string, body []byte) *http.Request {
	req := httptest.NewRequest(method, "http://w1ncray-relay"+pathPrefix+name+"?node_id=3", bytes.NewReader(body))
	req.Header.Set("X-Machine-Id", "7")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func serve(r *Relay, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAnswersComeBackAsTheHTTPResponse(t *testing.T) {
	p := &panelFake{}
	r := newRelay(t, p, true)
	p.answer = func(id string, req wsproto.NodeReq, body []byte) {
		if req.Method != "GET" || req.Name != "user" || req.NodeID != 3 || req.IfNoneMatch != `"old"` {
			t.Errorf("head = %+v", req)
		}
		big := strings.Repeat("x", 300_000)
		half := base64.StdEncoding.EncodeToString([]byte(big[:150_000]))
		rest := base64.StdEncoding.EncodeToString([]byte(big[150_000:]))
		r.OnResponse(id, wsproto.NodeRes{Status: 200, ETag: `"new"`, ContentType: "application/json", Body: half, More: true})
		r.OnResponse(id, wsproto.NodeRes{Status: 200, Body: rest})
	}
	req := request("GET", "user", nil)
	req.Header.Set("If-None-Match", `"old"`)

	rec := serve(r, req)

	if rec.Code != 200 || rec.Header().Get("ETag") != `"new"` || rec.Body.Len() != 300_000 {
		t.Fatalf("got %d etag=%q len=%d", rec.Code, rec.Header().Get("ETag"), rec.Body.Len())
	}
	if r.Waiting() != 0 {
		t.Fatalf("a call is still waiting")
	}
}

func TestALongBodyIsSplitOverFrames(t *testing.T) {
	p := &panelFake{}
	r := newRelay(t, p, true)
	body := bytes.Repeat([]byte("7"), wsproto.NodeRelayChunk*2+5)
	var got []byte
	p.answer = func(id string, _ wsproto.NodeReq, b []byte) {
		got = append([]byte(nil), b...)
		r.OnResponse(id, wsproto.NodeRes{Status: 200, Body: base64.StdEncoding.EncodeToString([]byte(`{"data":true}`))})
	}

	rec := serve(r, request("POST", "push", body))

	if rec.Code != 200 || !bytes.Equal(got, body) {
		t.Fatalf("code %d, body forwarded %d of %d bytes", rec.Code, len(got), len(body))
	}
	if len(p.frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(p.frames))
	}
	for i, f := range p.frames {
		var req wsproto.NodeReq
		_ = json.Unmarshal(f.D, &req)
		if (i == 0) != (req.Name == "push") || req.More != (i < 2) {
			t.Fatalf("frame %d = %+v", i, req)
		}
		if len(f.D) > wsproto.MaxFrame {
			t.Fatalf("frame %d is %d bytes", i, len(f.D))
		}
	}
}

func TestWhatIsNotForwardedIsRefusedAsUnavailable(t *testing.T) {
	cases := map[string]func(*panelFake) (*Relay, *http.Request){
		"panel did not offer": func(p *panelFake) (*Relay, *http.Request) {
			return newRelay(t, p, false), request("GET", "config", nil)
		},
		"session ended": func(p *panelFake) (*Relay, *http.Request) {
			r := newRelay(t, p, true)
			r.Disconnected()
			return r, request("GET", "config", nil)
		},
		"not a node endpoint": func(p *panelFake) (*Relay, *http.Request) {
			return newRelay(t, p, true), request("GET", "../nodes", nil)
		},
		"wrong token": func(p *panelFake) (*Relay, *http.Request) {
			req := request("GET", "config", nil)
			req.Header.Set("Authorization", "Bearer nope")
			return newRelay(t, p, true), req
		},
		"another machine": func(p *panelFake) (*Relay, *http.Request) {
			req := request("GET", "config", nil)
			req.Header.Set("X-Machine-Id", "8")
			return newRelay(t, p, true), req
		},
		"queue refused": func(p *panelFake) (*Relay, *http.Request) {
			p.fail = errors.New("offline")
			return newRelay(t, p, true), request("POST", "push", []byte(`{}`))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			p := &panelFake{}
			r, req := setup(p)
			rec := serve(r, req)
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(header) != unavailable {
				t.Fatalf("got %d %q", rec.Code, rec.Header().Get(header))
			}
			if r.Waiting() != 0 {
				t.Fatal("a refused request must not wait")
			}
		})
	}
}

func TestAForwardedRequestNeverFallsBack(t *testing.T) {
	p := &panelFake{}
	r := newRelay(t, p, true)
	p.answer = func(string, wsproto.NodeReq, []byte) { r.Disconnected() }

	rec := serve(r, request("POST", "push", []byte(`{"1":[1,2]}`)))
	if rec.Code != http.StatusBadGateway || rec.Header().Get(header) != "lost" {
		t.Fatalf("lost session: got %d %q", rec.Code, rec.Header().Get(header))
	}

	r.SetPanel(&wsproto.NodeRelayCtl{Enabled: true})
	r.opts.Timeout = 50 * time.Millisecond
	p.answer = nil
	rec = serve(r, request("POST", "push", []byte(`{"1":[1,2]}`)))
	if rec.Code != http.StatusGatewayTimeout || rec.Header().Get(header) != "timeout" {
		t.Fatalf("timeout: got %d %q", rec.Code, rec.Header().Get(header))
	}
	if r.Waiting() != 0 {
		t.Fatal("the timed out call must be forgotten")
	}
}
