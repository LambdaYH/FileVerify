package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIWorkflowAndExitCodes(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "FolderVerify")
	file := filepath.Join(root, "中文.txt")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args []string, input string) (int, string) {
		t.Helper()
		var out, errs bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(input), &out, &errs, exe)
		return code, out.String() + errs.String()
	}
	code, out := run([]string{"--quiet"}, "")
	if code != 0 || !strings.Contains(out, "清单生成成功") {
		t.Fatal(code, out)
	}
	manifest := filepath.Join(root, "sha512-manifest.json")
	before, _ := os.ReadFile(manifest)
	code, out = run([]string{"--quiet", "--details", "--report"}, "")
	if code != 0 || !strings.Contains(out, "[PASS]") {
		t.Fatal(code, out)
	}
	if _, err := os.Stat(filepath.Join(root, "verify-report.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out = run([]string{"--quiet"}, "")
	if code != 1 || !strings.Contains(out, "[MODIFIED]") {
		t.Fatal(code, out)
	}
	after, _ := os.ReadFile(manifest)
	if !bytes.Equal(before, after) {
		t.Fatal("CLI verification changed manifest")
	}
	code, _ = run([]string{"--regenerate", "--quiet"}, "YES\nNO\n")
	if code != 130 {
		t.Fatal(code)
	}
	after, _ = os.ReadFile(manifest)
	if !bytes.Equal(before, after) {
		t.Fatal("unconfirmed regeneration changed manifest")
	}
	code, out = run([]string{"--regenerate", "--quiet"}, "YES\nYES\n")
	if code != 0 || !strings.Contains(out, "清单生成成功") {
		t.Fatal(code, out)
	}
	if err := os.WriteFile(manifest, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out = run([]string{"--quiet"}, "")
	if code != 2 || !strings.Contains(out, "禁止自动生成") {
		t.Fatal(code, out)
	}
	after, _ = os.ReadFile(manifest)
	if string(after) != "{broken" {
		t.Fatal("corrupt manifest overwritten")
	}
	code, _ = run([]string{"--unknown"}, "")
	if code != 2 {
		t.Fatal(code)
	}
	code, _ = run([]string{"--help"}, "")
	if code != 0 {
		t.Fatal(code)
	}
}
func TestCLICanceledConfirmation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	code := Run(ctx, []string{"--regenerate"}, reader, &out, &out, filepath.Join(t.TempDir(), "FolderVerify"))
	if code != 130 {
		t.Fatal(code)
	}
}
