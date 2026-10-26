package porthop

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ConflictChecker decides whether a hop range collides with something already
// using ports on this machine. Check returns nil when the range is free. to is
// the redirect target and is always excluded from the check.
type ConflictChecker interface {
	Check(proto string, lo, hi, to int) error
}

// ledgerChecker rejects ranges that contain a port claimed by a local forward.
type ledgerChecker struct {
	ports   func() map[int]bool
	byProto func(proto string) map[int]bool // takes precedence when set
}

// NewLedgerChecker wraps a function returning the ports local forwards occupy
// (for example the reconcile ledger's ports).
func NewLedgerChecker(ports func() map[int]bool) ConflictChecker {
	return ledgerChecker{ports: ports}
}

func (l ledgerChecker) Check(proto string, lo, hi, to int) error {
	var set map[int]bool
	switch {
	case l.byProto != nil:
		set = l.byProto(proto)
	case l.ports != nil:
		set = l.ports()
	default:
		return nil
	}
	for p := lo; p <= hi; p++ {
		if p != to && set[p] {
			return fmt.Errorf("port %d is used by a local forward", p)
		}
	}
	return nil
}

// ProcChecker rejects ranges that contain a port bound by a local socket,
// read from <Root>/net/{udp,udp6,tcp,tcp6}. Sockets without an owner inode
// (inode 0, kernel sockets such as WireGuard) count as conflicts. Sockets that
// belong to the agent's own process are ignored (best effort: the inode ->
// process mapping reads <Root>/<pid>/fd; if that fails only the target port is
// excluded).
type ProcChecker struct {
	Root string
	PID  int
	// ownInodes overrides the /proc/<pid>/fd scan (tests).
	ownInodes func() map[uint64]bool
}

// NewProcChecker builds a ProcChecker; root defaults to /proc.
func NewProcChecker(root string, pid int) *ProcChecker {
	if root == "" {
		root = "/proc"
	}
	return &ProcChecker{Root: root, PID: pid}
}

func (p *ProcChecker) own() map[uint64]bool {
	if p.ownInodes != nil {
		return p.ownInodes()
	}
	out := map[uint64]bool{}
	dir := filepath.Join(p.Root, strconv.Itoa(p.PID), "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil || !strings.HasPrefix(l, "socket:[") || !strings.HasSuffix(l, "]") {
			continue
		}
		if n, err := strconv.ParseUint(l[len("socket:["):len(l)-1], 10, 64); err == nil {
			out[n] = true
		}
	}
	return out
}

// Check implements ConflictChecker.
func (p *ProcChecker) Check(proto string, lo, hi, to int) error {
	files := []string{"udp", "udp6"}
	if proto == ProtoTCP {
		files = []string{"tcp", "tcp6"}
	}
	own := p.own()
	for _, f := range files {
		port, err := p.scan(filepath.Join(p.Root, "net", f), proto == ProtoTCP, lo, hi, to, own)
		if err != nil {
			return err
		}
		if port != 0 {
			return fmt.Errorf("port %d is bound by a local %s socket", port, proto)
		}
	}
	return nil
}

// scan returns the lowest conflicting port in the file (0 when none).
func (p *ProcChecker) scan(path string, tcp bool, lo, hi, to int, own map[uint64]bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // e.g. IPv6 disabled
		}
		return 0, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer f.Close()
	first := 0
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		if tcp && fs[3] != "0A" { // only LISTEN
			continue
		}
		i := strings.LastIndexByte(fs[1], ':')
		if i < 0 {
			continue
		}
		port64, err := strconv.ParseUint(fs[1][i+1:], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		if port < lo || port > hi || port == to {
			continue
		}
		inode, err := strconv.ParseUint(fs[9], 10, 64)
		if err != nil {
			continue
		}
		if inode != 0 && own[inode] {
			continue
		}
		if first == 0 || port < first {
			first = port
		}
	}
	return first, sc.Err()
}

type chain []ConflictChecker

func (c chain) Check(proto string, lo, hi, to int) error {
	for _, x := range c {
		if err := x.Check(proto, lo, hi, to); err != nil {
			return err
		}
	}
	return nil
}
