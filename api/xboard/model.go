package xboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Int decodes a JSON number, a numeric string, a bool or null. PHP/Laravel may
// emit integers as strings depending on the PDO driver settings.
type Int int64

// UnmarshalJSON implements json.Unmarshaler.
func (i *Int) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch s {
	case "null", `""`, "false":
		*i = 0
		return nil
	case "true":
		*i = 1
		return nil
	}
	s = strings.Trim(s, `"`)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*i = Int(v)
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid integer %s", b)
	}
	*i = Int(f)
	return nil
}

// String decodes a JSON string, number, bool or null into a string.
type String string

// UnmarshalJSON implements json.Unmarshaler.
func (s *String) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = String(v)
		return nil
	}
	if string(b) == "null" {
		*s = ""
		return nil
	}
	*s = String(b)
	return nil
}

// Object holds a JSON object. PHP encodes empty associative arrays as [],
// which Object normalizes to an empty value.
type Object json.RawMessage

// UnmarshalJSON implements json.Unmarshaler.
func (o *Object) UnmarshalJSON(b []byte) error {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || string(t) == "null" || string(t) == "[]" || t[0] != '{' {
		*o = nil
		return nil
	}
	*o = append((*o)[:0], t...)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (o Object) MarshalJSON() ([]byte, error) {
	if len(o) == 0 {
		return []byte("null"), nil
	}
	return o, nil
}

// Empty reports whether the object is absent.
func (o Object) Empty() bool { return len(o) == 0 }

// Map decodes the object into a generic map (nil when empty).
func (o Object) Map() map[string]any {
	if o.Empty() {
		return nil
	}
	m := make(map[string]any)
	if err := json.Unmarshal(o, &m); err != nil {
		return nil
	}
	return m
}

// Strings decodes a JSON string array; a single string becomes one element.
type Strings []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *Strings) UnmarshalJSON(b []byte) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		var one String
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		if one != "" {
			*s = Strings{string(one)}
		} else {
			*s = nil
		}
		return nil
	}
	out := make(Strings, 0, len(arr))
	for _, raw := range arr {
		var v String
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		out = append(out, string(v))
	}
	*s = out
	return nil
}

// BaseConfig carries panel intervals (seconds).
type BaseConfig struct {
	PushInterval Int `json:"push_interval"`
	PullInterval Int `json:"pull_interval"`
}

// Route is a panel routing rule (v2_server_route).
type Route struct {
	ID          Int     `json:"id"`
	Match       Strings `json:"match"`
	Action      String  `json:"action"`
	ActionValue String  `json:"action_value"`
}

// CertConfig is the panel certificate automation config (field names taken
// from the Xboard admin UI schema).
type CertConfig struct {
	CertMode    String            `json:"cert_mode"`
	Mode        String            `json:"mode"`
	Domain      String            `json:"domain"`
	Email       String            `json:"email"`
	DNSProvider String            `json:"dns_provider"`
	DNSEnv      map[string]String `json:"dns_env"`
	HTTPPort    Int               `json:"http_port"`
	CertFile    String            `json:"cert_file"`
	KeyFile     String            `json:"key_file"`
	CertContent String            `json:"cert_content"`
	KeyContent  String            `json:"key_content"`
}

// UnmarshalJSON accepts dns_env as either an object or [] (PHP empty array).
func (c *CertConfig) UnmarshalJSON(b []byte) error {
	type plain CertConfig
	var raw struct {
		plain
		DNSEnv json.RawMessage `json:"dns_env"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*c = CertConfig(raw.plain)
	c.DNSEnv = nil
	if t := bytes.TrimSpace(raw.DNSEnv); len(t) > 0 && t[0] == '{' {
		if err := json.Unmarshal(t, &c.DNSEnv); err != nil {
			return err
		}
	}
	if c.CertMode == "" {
		c.CertMode = c.Mode
	}
	return nil
}

// ECH is the server side ECH configuration inside tls_settings.
type ECH struct {
	Enabled bool   `json:"enabled"`
	Key     String `json:"key"`
	KeyPath String `json:"key_path"`
}

// TLSSettings covers both Xboard tls_settings and reality_settings (for
// tls=2 the panel sends reality_settings under the tls_settings key).
type TLSSettings struct {
	ServerName    String `json:"server_name"`
	AllowInsecure bool   `json:"allow_insecure"`
	ECH           *ECH   `json:"ech"`

	// REALITY
	ServerPort String  `json:"server_port"`
	PrivateKey String  `json:"private_key"`
	PublicKey  String  `json:"public_key"`
	ShortID    String  `json:"short_id"`
	ShortIDs   Strings `json:"short_ids"`
	Dest       String  `json:"dest"`
	Xver       Int     `json:"xver"`
}

// NodeConfig is the response of GET /api/v1/server/UniProxy/config.
type NodeConfig struct {
	Protocol   String `json:"protocol"`
	ListenIP   String `json:"listen_ip"`
	ServerPort Int    `json:"server_port"`
	Network    String `json:"network"`
	// Xboard sends "networkSettings"; "network_settings" is accepted for
	// forks of the panel.
	NetworkSettings    Object `json:"networkSettings"`
	NetworkSettingsAlt Object `json:"network_settings"`

	BaseConfig      *BaseConfig       `json:"base_config"`
	Routes          []Route           `json:"routes"`
	CustomOutbounds []json.RawMessage `json:"custom_outbounds"`
	CustomRoutes    []json.RawMessage `json:"custom_routes"`
	CertConfig      *CertConfig       `json:"cert_config"`

	// shadowsocks
	Cipher     String `json:"cipher"`
	Plugin     String `json:"plugin"`
	PluginOpts String `json:"plugin_opts"`
	ServerKey  String `json:"server_key"`

	// vmess / vless / trojan / socks / http
	TLS         Int    `json:"tls"`
	TLSSettings Object `json:"tls_settings"`
	Flow        String `json:"flow"`
	Decryption  String `json:"decryption"`
	Host        String `json:"host"`
	ServerName  String `json:"server_name"`

	// hysteria
	Version      Int    `json:"version"`
	UpMbps       Int    `json:"up_mbps"`
	DownMbps     Int    `json:"down_mbps"`
	Obfs         String `json:"obfs"`
	ObfsPassword String `json:"obfs-password"`

	// Raw is the original response body, used for change detection.
	Raw []byte `json:"-"`
}

// NetworkSettingsObject returns the transport settings object.
func (n *NodeConfig) NetworkSettingsObject() Object {
	if !n.NetworkSettings.Empty() {
		return n.NetworkSettings
	}
	return n.NetworkSettingsAlt
}

// TLSConfig returns the decoded tls_settings (never nil).
func (n *NodeConfig) TLSConfig() *TLSSettings {
	t := new(TLSSettings)
	if !n.TLSSettings.Empty() {
		_ = json.Unmarshal(n.TLSSettings, t)
	}
	return t
}

// User is an entry of GET /api/v1/server/UniProxy/user.
type User struct {
	ID          Int    `json:"id"`
	UUID        String `json:"uuid"`
	SpeedLimit  Int    `json:"speed_limit"`  // Mbps, 0/null = unlimited
	DeviceLimit Int    `json:"device_limit"` // 0/null = unlimited
}

// Status is the payload of POST /api/v1/server/UniProxy/status.
type Status struct {
	CPU  float64  `json:"cpu"`
	Mem  Resource `json:"mem"`
	Swap Resource `json:"swap"`
	Disk Resource `json:"disk"`
}

// Resource is a total/used pair in bytes.
type Resource struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}
