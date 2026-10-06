// Package ws implements the agent side of the panel WebSocket channel
// (docs/WS-PROTOCOL.md, "wss://<panel>/w1ncray-ws").
//
// It is transport only: it dials, authenticates in request headers, keeps the
// connection alive, answers control frames, reconnects with backoff and hands
// every inbound frame to a Handler. It never decodes a desired state, never
// touches a kernel and never samples the machine; agentclient.go is the one
// place that joins the transport with the agent runtime.
//
// Safety properties:
//   - the machine token travels in the Authorization header only: it never
//     appears in the URL, in a log line, in an error string or in a close
//     reason (docs/WS-PROTOCOL.md section 1);
//   - one goroutine reads and one goroutine writes a connection (gorilla
//     forbids concurrent writers), so a slow panel can never interleave frames;
//   - the outbound queue belongs to a connection: nothing is buffered while
//     offline and nothing is resent after a reconnect (docs/WS-PROTOCOL.md
//     section 7 ruling 3).
package ws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// Encode marshals a payload into an Envelope. A nil payload yields an empty d
// so control frames stay byte-identical to the contract's "{}".
func Encode(t, id string, d any) (wsproto.Envelope, error) {
	env := wsproto.Envelope{T: t, ID: id}
	if d == nil {
		return env, nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return wsproto.Envelope{}, fmt.Errorf("ws: marshal %s payload: %w", t, err)
	}
	env.D = raw
	return env, nil
}

// Decode unmarshals env.D into out, strictly: a panel that invents fields is
// caught here instead of being half-applied. An empty d decodes to the zero
// value of out (the contract allows "{}" and, for ping/pong, no payload).
func Decode(env wsproto.Envelope, out any) error {
	raw := bytes.TrimSpace(env.D)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("ws: decode %s payload: %w", env.T, err)
	}
	return nil
}

// ErrorFrame builds the protocol's error answer for a frame we cannot handle
// (docs/WS-PROTOCOL.md section 2).
func ErrorFrame(id, code, message string) wsproto.Envelope {
	env, err := Encode(wsproto.TypeError, id, wsproto.ErrorBody{Code: code, Message: message})
	if err != nil {
		// ErrorBody is a plain struct of two strings: marshalling cannot fail.
		return wsproto.Envelope{T: wsproto.TypeError, ID: id}
	}
	return env
}

// marshalEnvelope renders a frame for the wire. It is the only place that
// turns an Envelope into bytes, so the writer and Send cannot disagree about
// the encoding. The contract's 256 KiB limit applies to what we send as well:
// a larger frame is refused here instead of being pushed to a peer that would
// close the connection over it.
func marshalEnvelope(env wsproto.Envelope) ([]byte, error) {
	if env.T == "" {
		return nil, errors.New("ws: frame has no type")
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("ws: marshal %s envelope: %w", env.T, err)
	}
	if len(raw) > wsproto.MaxFrame {
		return nil, fmt.Errorf("%w: %s frame is %d bytes", ErrFrameTooLarge, env.T, len(raw))
	}
	return raw, nil
}

// strictUnmarshal decodes a frame envelope, rejecting unknown top-level fields:
// the envelope has exactly t/id/d, and a frame that carries more is not the
// contract's frame.
func strictUnmarshal(raw []byte, env *wsproto.Envelope) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(env)
}

// Interval clamping. The panel negotiates the cadence in hello.ok; the bounds
// live in wsproto (data) and are enforced here so a buggy or hostile panel
// cannot make the agent spin or stop reporting. A zero/negative value means
// "not configured" and falls back to the contract default.
const (
	DefaultTelemetryIntervalS  = 5
	DefaultComponentsIntervalS = 15
)

// clampTelemetryIntervalS bounds hello.ok.intervals.telemetry_s.
func clampTelemetryIntervalS(v int) int {
	if v <= 0 {
		return DefaultTelemetryIntervalS
	}
	if v < wsproto.MinTelemetryIntervalS {
		return wsproto.MinTelemetryIntervalS
	}
	if v > wsproto.MaxTelemetryIntervalS {
		return wsproto.MaxTelemetryIntervalS
	}
	return v
}

// clampComponentsIntervalS bounds hello.ok.intervals.components_s.
func clampComponentsIntervalS(v int) int {
	if v <= 0 {
		return DefaultComponentsIntervalS
	}
	if v < wsproto.MinComponentsIntervalS {
		return wsproto.MinComponentsIntervalS
	}
	if v > wsproto.MaxComponentsIntervalS {
		return wsproto.MaxComponentsIntervalS
	}
	return v
}

// clampIntervals applies both bounds at once; it is the only conversion the
// Agent performs on the negotiated intervals.
func clampIntervals(in wsproto.Intervals) wsproto.Intervals {
	return wsproto.Intervals{
		TelemetryS:  clampTelemetryIntervalS(in.TelemetryS),
		ComponentsS: clampComponentsIntervalS(in.ComponentsS),
	}
}
