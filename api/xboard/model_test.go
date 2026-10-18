package xboard

import (
	"encoding/json"
	"testing"
)

func TestBoolDecode(t *testing.T) {
	cases := map[string]bool{
		`true`:    true,
		`false`:   false,
		`1`:       true,
		`0`:       false,
		`"1"`:     true,
		`"0"`:     false,
		`"true"`:  true,
		`"false"`: false,
		`null`:    false,
		`"yes"`:   false,
		`2.0`:     true,
		`""`:      false,
	}
	for in, want := range cases {
		var b Bool
		if err := json.Unmarshal([]byte(in), &b); err != nil {
			t.Fatalf("%s: unexpected error %v", in, err)
		}
		if bool(b) != want {
			t.Fatalf("%s: got %v, want %v", in, bool(b), want)
		}
	}
}

func TestNodeConfigAcceptProxyProtocol(t *testing.T) {
	on := []byte(`{"protocol":"vless","server_port":10001,"accept_proxy_protocol":true}`)
	off := []byte(`{"protocol":"vless","server_port":10001}`)
	var nc NodeConfig
	if err := json.Unmarshal(on, &nc); err != nil {
		t.Fatal(err)
	}
	if !bool(nc.AcceptProxyProtocol) {
		t.Fatal("present true: want AcceptProxyProtocol")
	}
	nc = NodeConfig{}
	if err := json.Unmarshal(off, &nc); err != nil {
		t.Fatal(err)
	}
	if bool(nc.AcceptProxyProtocol) {
		t.Fatal("absent: want AcceptProxyProtocol false")
	}
}
