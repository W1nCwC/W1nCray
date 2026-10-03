// Command protogen regenerates app/dispatcher/config.pb.go without needing the
// protoc binary: it builds the CodeGeneratorRequest in Go and pipes it through
// protoc-gen-go (same version as the protobuf runtime used by xray-core).
//
//	go run ./tools/protogen
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

const protocGenGo = "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "protogen:", err)
		os.Exit(1)
	}
}

func run() error {
	// Must stay in sync with app/dispatcher/config.proto. The registered
	// file name carries the module prefix: protobuf rejects a second
	// "app/dispatcher/config.proto", which xray-core already registers.
	name := "github.com/W1nCwC/W1nCray/app/dispatcher/config.proto"
	fd := &descriptorpb.FileDescriptorProto{
		Name:    proto.String(name),
		Package: proto.String("w1ncray.app.dispatcher"),
		Syntax:  proto.String("proto3"),
		Options: &descriptorpb.FileOptions{
			GoPackage: proto.String("github.com/W1nCwC/W1nCray/app/dispatcher"),
		},
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Config")}},
	}
	req := &pluginpb.CodeGeneratorRequest{
		FileToGenerate:  []string{name},
		Parameter:       proto.String("paths=source_relative"),
		ProtoFile:       []*descriptorpb.FileDescriptorProto{fd},
		CompilerVersion: &pluginpb.Version{Major: proto.Int32(0), Minor: proto.Int32(0), Patch: proto.Int32(0)},
	}
	in, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "run", protocGenGo)
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("protoc-gen-go: %w", err)
	}

	resp := new(pluginpb.CodeGeneratorResponse)
	if err := proto.Unmarshal(out, resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("protoc-gen-go: %s", resp.GetError())
	}
	for _, f := range resp.File {
		out := strings.TrimPrefix(f.GetName(), "github.com/W1nCwC/W1nCray/")
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, []byte(f.GetContent()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", out)
	}
	return nil
}
