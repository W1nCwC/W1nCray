// Command manifestgen builds, signs and verifies the W1nCray kernel manifest.
// It runs in the release CI and on the release owner's machine; the agent
// never executes it.
//
//	manifestgen keygen -out keys/manifest-1.key
//	manifestgen build  -config kernels.yaml -out unsigned.json [-cache dir] [-sequence N]
//	manifestgen sign   -key keys/manifest-1.key -in unsigned.json -out manifest.json
//	manifestgen verify -in manifest.json -pub <hex|file> [-pub ...] [-min-sequence N] [-agent X.Y.Z]
//
// "build" reads the GitHub release API (proxy variables incl. ALL_PROXY
// socks5h:// are honoured; GITHUB_TOKEN is used for the API only), downloads
// every asset, cross-checks GitHub's asset digest and the upstream checksum
// file against the downloaded bytes, hashes the files inside each archive and
// writes the UNSIGNED manifest. The private key is only touched by "sign".
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/netutil"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "manifestgen:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: manifestgen <command> [flags]
  keygen  -out FILE                 generate an ed25519 key pair (FILE 0600, FILE.pub)
  build   -config FILE -out FILE    resolve upstream releases into an unsigned manifest
  sign    -key FILE -in FILE -out FILE
  verify  -in FILE -pub HEX|FILE [-pub ...]
`)
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], stdout)
	case "build":
		return cmdBuild(args[1:], stdout, stderr)
	case "sign":
		return cmdSign(args[1:], stdout)
	case "verify":
		return cmdVerify(args[1:], stdout)
	case "-h", "--help", "help":
		usage(stdout)
		return nil
	}
	usage(stderr)
	return fmt.Errorf("unknown command %q", args[0])
}

// ---- keygen -----------------------------------------------------------------

func cmdKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "private key file to create (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// The private key file holds the hex seed only; O_EXCL refuses to
	// overwrite an existing key.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "public key: %s\nkey id:     %s\nprivate key written to %s (mode 0600); keep it offline\n",
		hex.EncodeToString(pub), manifest.KeyID(pub), *out)
	return nil
}

func loadPrivate(path string) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is accessible by group/others (mode %v); chmod 600", path, fi.Mode().Perm())
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: not hex", path)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("%s: want a %d-byte seed in hex", path, ed25519.SeedSize)
}

// ---- build ------------------------------------------------------------------

func cmdBuild(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "build description (YAML/JSON)")
	out := fs.String("out", "", "unsigned manifest to write")
	cache := fs.String("cache", "", "download cache directory (default: ./.manifestgen-cache)")
	seq := fs.Int64("sequence", 0, "override the config's sequence")
	api := fs.String("api-base", "https://api.github.com", "GitHub API base URL (tests)")
	nowFlag := fs.String("now", "", "issue time, RFC 3339 (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *out == "" {
		return errors.New("-config and -out are required")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *seq != 0 {
		cfg.Sequence = *seq
	}
	if *cache == "" {
		*cache = ".manifestgen-cache"
	}
	now := time.Now()
	if *nowFlag != "" {
		if now, err = time.Parse(time.RFC3339, *nowFlag); err != nil {
			return err
		}
	}
	gh := &github{api: *api, token: os.Getenv("GITHUB_TOKEN"), client: netutil.NewClient()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	m, err := Build(ctx, buildOptions{
		Cfg: cfg, GH: gh, Cache: *cache, Now: now,
		Log: func(f string, a ...any) { fmt.Fprintf(stderr, f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote unsigned manifest %s (sequence %d, %d kernels)\n", *out, m.Sequence, len(m.Kernels))
	return nil
}

// ---- sign -------------------------------------------------------------------

func cmdSign(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "private key file")
	in := fs.String("in", "", "unsigned manifest")
	out := fs.String("out", "", "signed manifest to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" || *out == "" {
		return errors.New("-key, -in and -out are required")
	}
	priv, err := loadPrivate(*keyPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var m manifest.Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	signed, err := manifest.Sign(&m, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s with key %s (sequence %d)\n", *out, manifest.KeyID(priv.Public().(ed25519.PublicKey)), m.Sequence)
	return nil
}

// ---- verify -----------------------------------------------------------------

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	in := fs.String("in", "", "signed manifest")
	var pubs multiFlag
	fs.Var(&pubs, "pub", "trusted public key: hex, or a file with one hex key per line (repeatable)")
	defaults := fs.Bool("default-keys", false, "also trust the keys compiled into this build")
	minSeq := fs.Int64("min-sequence", 0, "reject sequences below this")
	agent := fs.String("agent", "", "agent version to evaluate min_agent against")
	allowExpired := fs.Bool("allow-expired", false, "do not fail on expiry")
	nowFlag := fs.String("now", "", "evaluate at this time, RFC 3339 (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	var keys []manifest.Key
	for _, p := range pubs {
		text := p
		if b, err := os.ReadFile(p); err == nil {
			text = string(b)
		}
		ks, err := manifest.ParseKeys(text)
		if err != nil {
			return fmt.Errorf("-pub %q: %w", p, err)
		}
		keys = append(keys, ks...)
	}
	if *defaults {
		ks, err := manifest.DefaultKeys()
		if err != nil {
			return err
		}
		keys = append(keys, ks...)
	}
	now := time.Now()
	if *nowFlag != "" {
		var err error
		if now, err = time.Parse(time.RFC3339, *nowFlag); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	m, err := manifest.Verify(raw, manifest.VerifyOptions{Keys: keys, Now: now, MinSequence: *minSeq, AllowExpired: *allowExpired})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OK  signature valid (key %s), sequence %d, issued %s, expires %s\n",
		m.Signature.KeyID, m.Sequence, m.IssuedAt.UTC().Format(time.RFC3339), m.ExpiresAt.UTC().Format(time.RFC3339))
	for i := range m.Kernels {
		k := &m.Kernels[i]
		var have, none []string
		for key, t := range k.Targets {
			if t == nil {
				none = append(none, key)
			} else {
				have = append(have, key)
			}
		}
		sort.Strings(have)
		sort.Strings(none)
		note := ""
		if err := k.CheckAgent(*agent); err != nil {
			note = "  [" + err.Error() + "]"
		}
		fmt.Fprintf(stdout, "    %-6s %-10s %d builds, %d unavailable (%s)%s\n", k.Name, k.Version, len(have), len(none), strings.Join(none, " "), note)
	}
	return nil
}
