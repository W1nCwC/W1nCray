// Package wsproto holds the wire types of the agent <-> panel WebSocket
// (docs/WS-PROTOCOL.md). It has no behaviour: the transport (agent/ws) and the
// collectors (agent/telemetry) both depend on it so they cannot drift apart.
package wsproto

import "encoding/json"

// Message types.
const (
	TypeHello      = "hello"
	TypeHelloOK    = "hello.ok"
	TypeTelemetry  = "telemetry"
	TypeComponents = "components"
	TypeCmd        = "cmd"
	TypeCmdResult  = "cmd.result"
	TypeHint       = "hint"
	TypeEvent      = "event"
	TypePing       = "ping"
	TypePong       = "pong"
	TypeError      = "error"

	TypeTermOpen   = "term.open"
	TypeTermOpened = "term.opened"
	TypeTermInput  = "term.input"
	TypeTermResize = "term.resize"
	TypeTermClose  = "term.close"
	TypeTermData   = "term.data"
	TypeTermExit   = "term.exit"
	TypeTermError  = "term.error"
)

// Capabilities an agent may declare in hello.
const (
	CapTelemetry = "telemetry"
	CapKernel    = "kernel"
	CapFiles     = "files"
	CapUpgrade   = "upgrade"
	CapTerminal  = "terminal"
	CapXrayNodes = "xray_nodes"
)

// CapabilitiesAll is the closed set a hello.capabilities may contain. The
// panel must not gate a feature on anything outside this list.
var CapabilitiesAll = []string{CapTerminal, CapFiles, CapKernel, CapUpgrade, CapXrayNodes, CapTelemetry}

// Error codes used in an "error" frame's d.code.
const (
	ErrCodeUnknownType  = "unknown_type"
	ErrCodeUnknownHint  = "unknown_hint"
	ErrCodeNotSupported = "not_supported"
	ErrCodeBadPayload   = "bad_payload"
)

// Interval bounds the agent enforces, so the panel cannot make it spin (a zero
// interval) or stop reporting (an absurd one).
const (
	MinTelemetryIntervalS  = 1
	MaxTelemetryIntervalS  = 300
	MinComponentsIntervalS = 1
	MaxComponentsIntervalS = 3600
)

// MaxFrame is the largest accepted frame (bytes).
const MaxFrame = 256 << 10

// Envelope is every frame: {"t":..., "id":..., "d":...}.
type Envelope struct {
	T  string          `json:"t"`
	ID string          `json:"id,omitempty"`
	D  json.RawMessage `json:"d,omitempty"`
}

// Hello is the first message the agent sends after the upgrade.
type Hello struct {
	AgentVersion string        `json:"agent_version"`
	InstanceID   string        `json:"instance_id"`
	Seq          int64         `json:"seq"`
	Platform     Platform      `json:"platform"`
	HostInfo     HostInfo      `json:"host_info"`
	Capabilities []string      `json:"capabilities"`
	Policy       Policy        `json:"policy"`
	Kernels      []KernelEntry `json:"kernels"`
}

// HelloOK is the panel's answer.
type HelloOK struct {
	ServerTime int64     `json:"server_time"`
	Intervals  Intervals `json:"intervals"`
	Session    string    `json:"session"`
}

// Intervals tells the agent how often to send telemetry and components.
type Intervals struct {
	TelemetryS  int `json:"telemetry_s"`
	ComponentsS int `json:"components_s"`
}

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Libc string `json:"libc,omitempty"`
}

// Policy is the part of the agent's LOCAL policy the panel may display.
type Policy struct {
	Terminal bool         `json:"terminal"`
	Files    FilesPolicy  `json:"files"`
	Modules  ModulePolicy `json:"modules"`
}

type FilesPolicy struct {
	Roots        []string `json:"roots"`
	Unrestricted bool     `json:"unrestricted"`
}

type ModulePolicy struct {
	XrayNodes bool `json:"xray_nodes"`
}

// HostInfo is the static-ish device description. Every field is optional:
// leave it zero when it cannot be determined, never invent a value.
type HostInfo struct {
	Hostname       string     `json:"hostname,omitempty"`
	OS             string     `json:"os,omitempty"`
	OSVersion      string     `json:"os_version,omitempty"`
	KernelVersion  string     `json:"kernel_version,omitempty"`
	Arch           string     `json:"arch,omitempty"`
	CPUModel       string     `json:"cpu_model,omitempty"`
	CPUCores       int        `json:"cpu_cores,omitempty"`
	CPUThreads     int        `json:"cpu_threads,omitempty"`
	MemTotal       uint64     `json:"mem_total,omitempty"`
	SwapTotal      uint64     `json:"swap_total,omitempty"`
	Disks          []DiskInfo `json:"disks,omitempty"`
	Virtualization string     `json:"virtualization,omitempty"`
	BootTime       int64      `json:"boot_time,omitempty"`
	IPs            IPs        `json:"ips"`
	Timezone       string     `json:"timezone,omitempty"`
}

type DiskInfo struct {
	Mount  string `json:"mount"`
	FSType string `json:"fstype,omitempty"`
	Total  uint64 `json:"total"`
}

type IPs struct {
	Private []string `json:"private,omitempty"`
	Public  []string `json:"public,omitempty"`
}

// Telemetry is one dynamic sample.
type Telemetry struct {
	TS      int64     `json:"ts"`
	CPUPct  float64   `json:"cpu_pct"`
	Load    Load      `json:"load"`
	Mem     Usage     `json:"mem"`
	Swap    Usage     `json:"swap"`
	Disks   []DiskUse `json:"disks"`
	Net     Net       `json:"net"`
	Conns   *Conns    `json:"conns"` // null when unreadable on this platform
	Procs   int       `json:"procs"`
	UptimeS int64     `json:"uptime_s"`
}

type Load struct {
	L1  float64 `json:"l1"`
	L5  float64 `json:"l5"`
	L15 float64 `json:"l15"`
}

type Usage struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type DiskUse struct {
	Mount string `json:"mount"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// Net is bandwidth in bytes/second (summed over non-loopback interfaces) and
// cumulative byte counters.
type Net struct {
	InBps    uint64 `json:"in_bps"`
	OutBps   uint64 `json:"out_bps"`
	InTotal  uint64 `json:"in_total"`
	OutTotal uint64 `json:"out_total"`
}

type Conns struct {
	TCP int `json:"tcp"`
	UDP int `json:"udp"`
}

// Components is the payload of the "components" message.
type Components struct {
	TS    int64       `json:"ts"`
	Items []Component `json:"items"`
}

// Component states.
const (
	StateRunning      = "running"
	StateStopped      = "stopped"
	StateFailed       = "failed"
	StateStarting     = "starting"
	StateNotInstalled = "not_installed"
)

type Component struct {
	Name      string              `json:"name"` // agent | xray | gost | realm | frp
	Kind      string              `json:"kind"` // agent | kernel
	Version   string              `json:"version,omitempty"`
	State     string              `json:"state"`
	PID       int                 `json:"pid,omitempty"`
	UptimeS   int64               `json:"uptime_s,omitempty"`
	Restarts  int                 `json:"restarts,omitempty"`
	CPUPct    float64             `json:"cpu_pct,omitempty"`
	RSS       uint64              `json:"rss,omitempty"`
	Instances []ComponentInstance `json:"instances"`
}

type ComponentInstance struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Conns     int    `json:"conns,omitempty"`
	UpBytes   uint64 `json:"up_bytes,omitempty"`
	DownBytes uint64 `json:"down_bytes,omitempty"`
}

// KernelEntry is one installed kernel version.
type KernelEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Current     bool   `json:"current"`
	Previous    bool   `json:"previous"`
	Path        string `json:"path,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	InstalledAt int64  `json:"installed_at,omitempty"`
	InUse       bool   `json:"in_use"`
}

// Cmd is the payload of a panel -> agent command.
type Cmd struct {
	Type string          `json:"type"`
	Args json.RawMessage `json:"args,omitempty"`
	TTLS int             `json:"ttl_s,omitempty"`
}

// CmdResult answers a Cmd (same envelope id).
type CmdResult struct {
	Status string `json:"status"` // accepted | done | failed
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Hint tells the agent to pull a resource over HTTP now.
type Hint struct {
	What string `json:"what"` // desired | files | nodes | manifest
}

// ErrorBody is the payload of an "error" message.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
