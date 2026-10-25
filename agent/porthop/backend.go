package porthop

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	// NftTable is the nftables table (per family) the agent owns.
	NftTable = "w1ncray_porthop"
	// IptChain is the iptables nat chain the agent owns.
	IptChain = "W1NCRAY-PORTHOP"

	backendNft      = "nft"
	backendIptables = "iptables"
)

// accepted is a rule that passed every gate, with its parsed range.
type accepted struct {
	Rule
	Lo, Hi int
}

// marker is the comment text of a rule. It contains the integer node id only.
func marker(nodeID int) string { return fmt.Sprintf("w1ncray node %d", nodeID) }

// env is what a backend needs from the Manager.
type env struct {
	run      func(ctx context.Context, name string, args ...string) (string, error)
	runFile  func(ctx context.Context, stdinFile, name string, args ...string) (string, error)
	writeTmp func(name, content string) (string, error)
}

type backend interface {
	name() string
	// probe checks that the backend can be used, without changing the system.
	probe(ctx context.Context) error
	// install makes exactly rules (non-empty) active.
	install(ctx context.Context, rules []accepted) error
	// remove deletes everything the backend installed. It is idempotent.
	remove(ctx context.Context) error
	// verify reports an error when a rule's marker is missing.
	verify(ctx context.Context, rules []accepted) error
	// note describes degraded modes (for example "ipv6 unavailable").
	note() string
}

// ---- nftables -------------------------------------------------------------

func nftFamilies(v6 bool) []string {
	if v6 {
		return []string{"ip", "ip6"}
	}
	return []string{"ip"}
}

// renderNft renders the atomic ruleset file. Each family is declared, deleted
// and rebuilt, so the commit replaces the previous state in one transaction
// and works whether or not the table already exists.
func renderNft(rules []accepted, v6 bool) string {
	var b strings.Builder
	for _, fam := range nftFamilies(v6) {
		fmt.Fprintf(&b, "table %s %s\n", fam, NftTable)
		fmt.Fprintf(&b, "delete table %s %s\n", fam, NftTable)
		if len(rules) == 0 {
			continue
		}
		fmt.Fprintf(&b, "table %s %s {\n", fam, NftTable)
		b.WriteString("\tchain prerouting {\n")
		b.WriteString("\t\ttype nat hook prerouting priority -100; policy accept;\n")
		for _, r := range rules {
			fmt.Fprintf(&b, "\t\tfib daddr type local %s dport %d-%d counter redirect to :%d comment \"%s\"\n",
				r.Proto, r.Lo, r.Hi, r.To, marker(r.NodeID))
		}
		b.WriteString("\t}\n}\n")
	}
	return b.String()
}

type nftBackend struct {
	e  env
	v6 bool // ip6 table in use (cleared when the kernel rejects it)
	n  string
}

func newNft(e env) *nftBackend { return &nftBackend{e: e, v6: true} }

func (b *nftBackend) name() string { return backendNft }
func (b *nftBackend) note() string { return b.n }

// commit validates and commits the file produced by render, dropping ip6 when
// the kernel does not accept it.
func (b *nftBackend) commit(ctx context.Context, render func(v6 bool) string, dry bool) error {
	tries := []bool{b.v6}
	if b.v6 {
		tries = append(tries, false)
	}
	var last error
	for _, v6 := range tries {
		file := "rules.nft"
		if dry {
			file = "probe.nft"
		}
		path, err := b.e.writeTmp(file, render(v6))
		if err != nil {
			return err
		}
		if _, err := b.e.run(ctx, "nft", "-c", "-f", path); err != nil {
			last = err
			continue
		}
		if !dry {
			if _, err := b.e.run(ctx, "nft", "-f", path); err != nil {
				return err
			}
		}
		if b.v6 && !v6 {
			b.v6 = false
			b.n = "ipv6 nat unavailable, only IPv4 is redirected"
		}
		return nil
	}
	return last
}

func (b *nftBackend) probe(ctx context.Context) error {
	return b.commit(ctx, func(v6 bool) string { return renderNft(nil, v6) }, true)
}

func (b *nftBackend) install(ctx context.Context, rules []accepted) error {
	return b.commit(ctx, func(v6 bool) string { return renderNft(rules, v6) }, false)
}

func (b *nftBackend) remove(ctx context.Context) error {
	return b.commit(ctx, func(v6 bool) string { return renderNft(nil, v6) }, false)
}

func (b *nftBackend) verify(ctx context.Context, rules []accepted) error {
	for _, fam := range nftFamilies(b.v6) {
		out, err := b.e.run(ctx, "nft", "list", "table", fam, NftTable)
		if err != nil {
			return fmt.Errorf("nft table %s %s missing: %w", fam, NftTable, err)
		}
		for _, r := range rules {
			if !strings.Contains(out, `"`+marker(r.NodeID)+`"`) {
				return fmt.Errorf("nft %s: rule for node %d missing", fam, r.NodeID)
			}
		}
	}
	return nil
}

// ---- iptables -------------------------------------------------------------

// renderIptables renders the iptables-restore input for the nat table.
func renderIptables(rules []accepted) string {
	var b strings.Builder
	b.WriteString("*nat\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", IptChain)
	fmt.Fprintf(&b, "-F %s\n", IptChain)
	for _, r := range rules {
		fmt.Fprintf(&b, "-A %s -p %s -m addrtype --dst-type LOCAL --dport %d:%d -m comment --comment \"%s\" -j REDIRECT --to-ports %d\n",
			IptChain, r.Proto, r.Lo, r.Hi, marker(r.NodeID), r.To)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

type iptFamily struct {
	tool, restore string
}

type iptBackend struct {
	e  env
	v6 bool
	n  string
}

func newIpt(e env) *iptBackend { return &iptBackend{e: e} }

var (
	ipt4 = iptFamily{"iptables", "iptables-restore"}
	ipt6 = iptFamily{"ip6tables", "ip6tables-restore"}
)

func (b *iptBackend) name() string { return backendIptables }
func (b *iptBackend) note() string { return b.n }

func (b *iptBackend) families() []iptFamily {
	if b.v6 {
		return []iptFamily{ipt4, ipt6}
	}
	return []iptFamily{ipt4}
}

func (b *iptBackend) probe(ctx context.Context) error {
	if _, err := b.e.run(ctx, ipt4.tool, "-t", "nat", "-S", "PREROUTING"); err != nil {
		return err
	}
	if _, err := b.e.run(ctx, ipt6.tool, "-t", "nat", "-S", "PREROUTING"); err == nil {
		b.v6 = true
		b.n = ""
	} else {
		b.v6 = false
		b.n = "ip6tables nat unavailable, only IPv4 is redirected"
	}
	return nil
}

func (b *iptBackend) installFamily(ctx context.Context, f iptFamily, rules []accepted) error {
	path, err := b.e.writeTmp("rules."+f.tool, renderIptables(rules))
	if err != nil {
		return err
	}
	if _, err := b.e.runFile(ctx, path, f.restore, "--noflush"); err != nil {
		return err
	}
	if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-C", "PREROUTING", "-j", IptChain); err != nil {
		if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-I", "PREROUTING", "1", "-j", IptChain); err != nil {
			return err
		}
	}
	return nil
}

func (b *iptBackend) install(ctx context.Context, rules []accepted) error {
	if err := b.installFamily(ctx, ipt4, rules); err != nil {
		return err
	}
	if b.v6 {
		if err := b.installFamily(ctx, ipt6, rules); err != nil {
			b.v6 = false
			b.n = "ip6tables nat failed, only IPv4 is redirected"
		}
	}
	return nil
}

func (b *iptBackend) removeFamily(ctx context.Context, f iptFamily) error {
	if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-S", IptChain); err != nil {
		return nil // chain absent: nothing to remove
	}
	for i := 0; i < 16; i++ {
		if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-D", "PREROUTING", "-j", IptChain); err != nil {
			break
		}
	}
	var errs []error
	if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-F", IptChain); err != nil {
		errs = append(errs, err)
	}
	if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-X", IptChain); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (b *iptBackend) remove(ctx context.Context) error {
	err := b.removeFamily(ctx, ipt4)
	if b.v6 {
		err = errors.Join(err, b.removeFamily(ctx, ipt6))
	}
	return err
}

func (b *iptBackend) verify(ctx context.Context, rules []accepted) error {
	for _, f := range b.families() {
		if _, err := b.e.run(ctx, f.tool, "-t", "nat", "-C", "PREROUTING", "-j", IptChain); err != nil {
			return fmt.Errorf("%s: jump to %s missing: %w", f.tool, IptChain, err)
		}
		out, err := b.e.run(ctx, f.tool, "-t", "nat", "-S", IptChain)
		if err != nil {
			return fmt.Errorf("%s: chain %s missing: %w", f.tool, IptChain, err)
		}
		for _, r := range rules {
			if !strings.Contains(out, `"`+marker(r.NodeID)+`"`) {
				return fmt.Errorf("%s: rule for node %d missing", f.tool, r.NodeID)
			}
		}
	}
	return nil
}
