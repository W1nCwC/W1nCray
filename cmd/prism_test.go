package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

type fakePrismLocal struct {
	got install.LocalInstall
	err error
}

func (f *fakePrismLocal) InstallLocal(_ context.Context, li install.LocalInstall) (driver.Installed, error) {
	f.got = li
	return driver.Installed{Path: "/k/prism/0.1.0/W1nCray-prism", Version: "0.1.0"}, f.err
}

func TestPrismInstallLocalPinsTheBytesAndNamesTheBinary(t *testing.T) {
	f := &fakePrismLocal{}

	if err := prismInstallLocal(context.Background(), f, "/tmp/W1nCray-prism-linux-amd64.gz", "abc"); err != nil {
		t.Fatal(err)
	}

	if f.got.Name != "prism" || f.got.Archive != "/tmp/W1nCray-prism-linux-amd64.gz" || f.got.ArchiveSHA256 != "abc" {
		t.Fatalf("install = %+v", f.got)
	}
	if f.got.To != "W1nCray-prism" || f.got.Run.Binary != "W1nCray-prism" || f.got.Run.VersionRegex == "" || f.got.Run.VersionCmd[0] != "version" {
		t.Fatalf("run block = %+v to=%q", f.got.Run, f.got.To)
	}
}

func TestPrismInstallLocalReportsTheInstallerError(t *testing.T) {
	f := &fakePrismLocal{err: errors.New("sha256 mismatch")}

	if err := prismInstallLocal(context.Background(), f, "x", "y"); err == nil || err.Error() != "sha256 mismatch" {
		t.Fatalf("err = %v", err)
	}
}

func TestPrismInstallNeedsBothFlags(t *testing.T) {
	c := prismInstallCmd()
	c.SetArgs([]string{"--file", "x"})
	c.SilenceUsage, c.SilenceErrors = true, true

	if err := c.Execute(); err == nil {
		t.Fatal("--file without --sha256 must fail before touching any configuration")
	}
}

type fakePrismRemover struct {
	backend string
	removed int
	err     error
}

func (f *fakePrismRemover) Backend() string              { return f.backend }
func (f *fakePrismRemover) Remove(context.Context) error { f.removed++; return f.err }

func TestPrismRemoveCallsTheManagerOnASupportedMachine(t *testing.T) {
	f := &fakePrismRemover{backend: "openrc"}
	if err := prismRemove(context.Background(), f); err != nil || f.removed != 1 {
		t.Fatalf("err = %v removed = %d", err, f.removed)
	}
}

func TestPrismRemoveDoesNothingWithoutABackendAndReportsFailures(t *testing.T) {
	f := &fakePrismRemover{}
	if err := prismRemove(context.Background(), f); err != nil || f.removed != 0 {
		t.Fatalf("err = %v removed = %d", err, f.removed)
	}
	f = &fakePrismRemover{backend: "systemd", err: errors.New("boom")}
	if err := prismRemove(context.Background(), f); err == nil {
		t.Fatal("a failed removal must be an error")
	}
}
