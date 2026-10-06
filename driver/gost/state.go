package gost

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Files inside driver.Runtime.StateDir. Every one of them can contain secrets
// and is written with mode 0600 through a temp file and rename.
const (
	baseFile     = "base.json"     // static gost config: api, metrics, log
	currentFile  = "current.json"  // services of the applied instances (second -C)
	appliedFile  = "applied.json"  // what Apply last committed (hash+fragment per instance)
	previousFile = "previous.json" // the state before the last commit, for Rollback
	endpointFile = "endpoint.json" // API address and credentials of the running process
	logFile      = "gost.log"
	procID       = "gost/main"
)

// runtimeState is the in-memory part of the driver. Everything durable lives
// in files so a restarted agent can reconcile.
type runtimeState struct {
	mu sync.Mutex // serialises Apply/Rollback/Stop/Stats/Health

	// Stats accumulators, per gost service name. gost's counters start from
	// zero whenever a service is (re)created; the accumulator keeps the
	// reported value monotonic.
	acc map[string]*svcAcc
	// retired holds, per instance, what services that were removed from it
	// (a port dropped from a range) had transferred.
	retired map[string]rawStats
}

func newRuntimeState() *runtimeState {
	return &runtimeState{acc: map[string]*svcAcc{}, retired: map[string]rawStats{}}
}

// appliedState is the committed state: for each instance the artifact hash
// and the fragment that was given to gost.
type appliedState struct {
	Instances map[string]appliedInstance `json:"instances"`
}

type appliedInstance struct {
	Hash     string   `json:"hash"`
	Fragment fragment `json:"fragment"`
}

func (a *appliedState) ids() []string {
	ids := make([]string, 0, len(a.Instances))
	for id := range a.Instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (a *appliedState) clone() *appliedState {
	c := &appliedState{Instances: make(map[string]appliedInstance, len(a.Instances))}
	for k, v := range a.Instances {
		c.Instances[k] = v
	}
	return c
}

// endpoint is how the driver talks to the running gost process.
type endpoint struct {
	Addr        string `json:"addr"` // API, 127.0.0.1:port
	User        string `json:"user"`
	Pass        string `json:"pass"`
	MetricsAddr string `json:"metrics_addr,omitempty"`
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("gost: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// freeLoopbackAddr asks the kernel for a free port on 127.0.0.1. The port is
// released again before gost binds it; the window is tiny and a collision
// only fails the start, which the caller retries.
func freeLoopbackAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func newEndpoint(withMetrics bool) (endpoint, error) {
	a, err := freeLoopbackAddr()
	if err != nil {
		return endpoint{}, err
	}
	ep := endpoint{Addr: a, User: "w1nc-" + randHex(4), Pass: randHex(24)}
	if withMetrics {
		m, err := freeLoopbackAddr()
		if err != nil {
			return endpoint{}, err
		}
		ep.MetricsAddr = m
	}
	return ep, nil
}

// writeFileAtomic writes data to path with the given permissions through a
// temporary file in the same directory, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	// CreateTemp already uses 0600 on POSIX; Chmod is best effort (it is a
	// no-op for most bits on Windows).
	_ = tmp.Chmod(perm)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func loadApplied(dir, name string) (*appliedState, error) {
	st := &appliedState{Instances: map[string]appliedInstance{}}
	err := readJSON(filepath.Join(dir, name), st)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &appliedState{Instances: map[string]appliedInstance{}}, nil
		}
		return nil, fmt.Errorf("gost: read %s: %w", name, err)
	}
	if st.Instances == nil {
		st.Instances = map[string]appliedInstance{}
	}
	return st, nil
}

func loadEndpoint(dir string) (endpoint, error) {
	var ep endpoint
	if err := readJSON(filepath.Join(dir, endpointFile), &ep); err != nil {
		return endpoint{}, err
	}
	if ep.Addr == "" {
		return endpoint{}, errors.New("empty endpoint")
	}
	return ep, nil
}

// currentFromApplied builds the second -C file from the applied instances.
// Objects are ordered by instance id so the file is deterministic.
func currentFromApplied(a *appliedState) currentConfig {
	cc := currentConfig{Services: []service{}}
	for _, id := range a.ids() {
		f := a.Instances[id].Fragment
		cc.Services = append(cc.Services, f.Services...)
		cc.Chains = append(cc.Chains, f.Chains...)
		cc.Admissions = append(cc.Admissions, f.Admissions...)
		cc.Limiters = append(cc.Limiters, f.Limiters...)
		cc.CLimiters = append(cc.CLimiters, f.CLimiters...)
	}
	return cc
}

func tailFile(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	b := make([]byte, st.Size()-off)
	n2, _ := f.ReadAt(b, off) // a short read is fine, keep what we got
	return strings.TrimSpace(string(b[:n2]))
}
