//go:build unix

package fileops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteModePolicy covers acceptance 8's mode rows on the platform where
// permission bits exist: setuid/setgid/sticky are refused, an executable bit
// needs Files.AllowExec, and only 0600/0644/0755 are accepted.
func TestWriteModePolicy(t *testing.T) {
	_, ops := testRoots(t)
	ctx := context.Background()
	cases := []struct {
		name string
		mode os.FileMode
		want error
	}{
		{"setuid", 0o4755, ErrSpecialMode},
		{"setgid", 0o2755, ErrSpecialMode},
		{"sticky", 0o1777, ErrSpecialMode},
		{"exec-bit", 0o755, ErrExecBit},
		{"odd-mode", 0o640, ErrBadPath},
		{"world-writable", 0o666, ErrBadPath},
		{"default-ok", 0o644, nil},
		{"private-ok", 0o600, nil},
		{"zero-is-default", 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ops.Write(ctx, "xray", "mode-"+tc.name+".txt", []byte("x"), tc.mode, "")
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Write(mode %04o) = %v", tc.mode, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Write(mode %04o) = %v, want %v", tc.mode, err, tc.want)
			}
		})
	}
}

// TestWriteAllowsExecWithLocalPolicy covers the local Files.AllowExec switch:
// it is the only way an executable bit can be written.
func TestWriteAllowsExecWithLocalPolicy(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ops, err := New(Options{
		Roots:               []Root{{Name: "xray", Path: root}},
		AllowExec:           true,
		testAllowSystemRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ops.Write(context.Background(), "xray", "hook.sh", []byte("#!/bin/sh\n"), 0o755, "")
	if err != nil {
		t.Fatalf("Write with AllowExec: %v", err)
	}
	fi, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %04o, want 0755", fi.Mode().Perm())
	}
	// setuid is still refused with AllowExec on.
	if _, err := ops.Write(context.Background(), "xray", "s.sh", []byte("x"), 0o4755, ""); !errors.Is(err, ErrSpecialMode) {
		t.Errorf("setuid with AllowExec = %v, want ErrSpecialMode", err)
	}
}

// TestWriteRefusesModeOutsideTheAllowlist keeps the AllowExec switch from
// widening the mode list.
func TestWriteRefusesModeOutsideTheAllowlist(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ops, err := New(Options{
		Roots:               []Root{{Name: "xray", Path: root}},
		AllowExec:           true,
		testAllowSystemRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Write(context.Background(), "xray", "x.txt", []byte("x"), 0o777, ""); !errors.Is(err, ErrBadPath) {
		t.Errorf("Write with mode 0777 and AllowExec = %v, want ErrBadPath", err)
	}
}
