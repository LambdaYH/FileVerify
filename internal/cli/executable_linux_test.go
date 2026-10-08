package cli

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func linuxExecutable(t *testing.T) (string, string) {
	t.Helper()
	source := os.Getenv("FOLDERVERIFY_TEST_EXE")
	if source == "" {
		t.Skip("set FOLDERVERIFY_TEST_EXE to test the actual Linux executable")
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	exe := filepath.Join(root, "FolderVerify")
	if err = os.WriteFile(exe, b, 0700); err != nil {
		t.Fatal(err)
	}
	return root, exe
}
func TestLinuxExecutableWorkflow(t *testing.T) {
	root, exe := linuxExecutable(t)
	file := filepath.Join(root, "中文.txt")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(want int, args ...string) string {
		t.Helper()
		cmd := exec.Command(exe, args...)
		cmd.Dir = os.TempDir()
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatalf("exit %d expected %d: %s", code, want, output)
		}
		return string(output)
	}
	if output := run(0, "--quiet"); !strings.Contains(output, "清单生成成功") {
		t.Fatal(output)
	}
	manifest := filepath.Join(root, "sha512-manifest.json")
	before, _ := os.ReadFile(manifest)
	if output := run(0, "--quiet", "--report", "--details"); !strings.Contains(output, "[PASS]") {
		t.Fatal(output)
	}
	if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if output := run(1, "--quiet"); !strings.Contains(output, "[MODIFIED]") {
		t.Fatal(output)
	}
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if output := run(1, "--quiet"); !strings.Contains(output, "[ADDED]") {
		t.Fatal(output)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if output := run(1, "--quiet"); !strings.Contains(output, "[MISSING]") {
		t.Fatal(output)
	}
	after, _ := os.ReadFile(manifest)
	if string(before) != string(after) {
		t.Fatal("verification changed manifest")
	}
	if err := os.WriteFile(manifest, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	run(2, "--quiet")
	after, _ = os.ReadFile(manifest)
	if string(after) != "{broken" {
		t.Fatal("corrupt manifest overwritten")
	}
}
func TestLinuxExecutableSIGINTCancelsWithoutManifest(t *testing.T) {
	root, exe := linuxExecutable(t)
	large, err := os.Create(filepath.Join(root, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err = large.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	large.Close()
	cmd := exec.Command(exe)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	started := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		sent := false
		for scanner.Scan() {
			if !sent && strings.Contains(scanner.Text(), "生成清单") {
				started <- true
				sent = true
			}
		}
		if !sent {
			started <- false
		}
	}()
	select {
	case ready := <-started:
		if !ready {
			t.Fatal("hashing progress was not emitted")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("hashing did not start")
	}
	if err = cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case err = <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("SIGINT did not cancel hashing")
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 130 {
		t.Fatalf("expected cancellation code 130, got %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, "sha512-manifest.json")); !os.IsNotExist(err) {
		t.Fatal("canceled task created manifest", err)
	}
	files, _ := filepath.Glob(filepath.Join(root, ".folderverify-*"))
	if len(files) > 0 {
		t.Fatal("temporary file not cleaned", files)
	}
}
