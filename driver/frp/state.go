package frp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

const stateVersion = 1

// proxyMeta describes one frpc proxy of a bridge unit.
type proxyMeta struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Remote int    `json:"remote"`
	Local  string `json:"local"`
	Hash   string `json:"hash"`
}

// unit is one applied instance: everything the driver needs to start, reload,
// probe or restore it without the original spec.Instance.
type unit struct {
	ID          string             `json:"id"`
	Role        string             `json:"role"`
	Hash        string             `json:"hash"`
	CommonHash  string             `json:"common_hash"`
	Files       map[string][]byte  `json:"files"` // holds the token: state files are 0600
	Networks    []string           `json:"networks"`
	Claims      []driver.PortClaim `json:"claims,omitempty"`
	Proxies     []proxyMeta        `json:"proxies,omitempty"`
	Transport   string             `json:"transport"`
	ControlAddr string             `json:"control_addr,omitempty"`
	ControlPort int                `json:"control_port,omitempty"`
}

func (u *unit) mainFile() string {
	if u.Role == rolePortal {
		return fileFrps
	}
	return fileFrpc
}

type stateFile struct {
	Version int              `json:"version"`
	Units   map[string]*unit `json:"units"`
}

// adminInfo is the loopback admin endpoint of a running frps/frpc.
type adminInfo struct {
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
	// Cfg is the config file the running process was started with.
	Cfg string `json:"cfg"`
}

const (
	currentFile  = "current.json"
	lastGoodFile = "lastgood.json"
)

func dirRun(rt driver.Runtime) string   { return filepath.Join(rt.StateDir, "run") }
func dirLogs(rt driver.Runtime) string  { return filepath.Join(rt.StateDir, "logs") }
func dirAdmin(rt driver.Runtime) string { return filepath.Join(rt.StateDir, "admin") }

func ensureDirs(rt driver.Runtime) error {
	if rt.StateDir == "" {
		return errors.New("frp: StateDir is empty")
	}
	for _, d := range []string{rt.StateDir, dirRun(rt), dirLogs(rt), dirAdmin(rt)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory and renames it over path. The file is 0600.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func loadState(rt driver.Runtime, name string) (map[string]*unit, error) {
	b, err := os.ReadFile(filepath.Join(rt.StateDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*unit{}, nil
	}
	if err != nil {
		return nil, err
	}
	var sf stateFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("frp: corrupt %s: %w", name, err)
	}
	if sf.Version != stateVersion {
		return nil, fmt.Errorf("frp: %s has unsupported version %d", name, sf.Version)
	}
	if sf.Units == nil {
		sf.Units = map[string]*unit{}
	}
	return sf.Units, nil
}

func saveState(rt driver.Runtime, name string, units map[string]*unit) error {
	b, err := json.Marshal(stateFile{Version: stateVersion, Units: units})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(rt.StateDir, name), b)
}

func saveAdmin(rt driver.Runtime, id string, a adminInfo) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dirAdmin(rt), id+".json"), b)
}

func loadAdmin(rt driver.Runtime, id string) (adminInfo, bool) {
	b, err := os.ReadFile(filepath.Join(dirAdmin(rt), id+".json"))
	if err != nil {
		return adminInfo{}, false
	}
	var a adminInfo
	if json.Unmarshal(b, &a) != nil || a.Port == 0 {
		return adminInfo{}, false
	}
	return a, true
}

func removeAdmin(rt driver.Runtime, id string) {
	_ = os.Remove(filepath.Join(dirAdmin(rt), id+".json"))
}
