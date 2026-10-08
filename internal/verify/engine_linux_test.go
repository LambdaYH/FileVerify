package verify

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxSymlinksAndFIFO(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"file-link": filepath.Join(outside, "secret"), "dir-link": outside} {
		if err := os.Symlink(target, filepath.Join(e.Root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(e.Root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	r := e.Verify(context.Background(), m)
	status(t, r, "ERROR", 3)
	if r.Complete {
		t.Fatal(r)
	}
	if f, cleanup, err := e.safeOpen("dir-link/secret"); err == nil {
		f.Close()
		cleanup()
		t.Fatal("directory symlink followed")
	}
	if f, cleanup, err := e.safeOpen("pipe"); err == nil {
		f.Close()
		cleanup()
		t.Fatal("FIFO read as ordinary file")
	}
	if f, cleanup, err := e.safeOpen("../secret"); err == nil {
		f.Close()
		cleanup()
		t.Fatal("path traversal accepted")
	}
}
func TestLinuxUnreadableFilesAndScanFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission test must run as a non-root user")
	}
	e := fixture(t)
	m := generate(t, e)
	p := filepath.Join(e.Root, "empty.bin")
	if err := os.Chmod(p, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0600)
	r := e.Verify(context.Background(), m)
	status(t, r, "ERROR", 1)
	if r.Conclusion() == "通过" {
		t.Fatal(r)
	}
	dir := filepath.Join(e.Root, "中文 目录")
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	r = e.Verify(context.Background(), m)
	if r.Complete || r.Counts()["MISSING"] != 0 {
		t.Fatal("scan failure must not be reported as missing", r)
	}
}
func TestLinuxCaseSensitiveFilesAndToolExclusions(t *testing.T) {
	e := fixture(t)
	put(t, e, "A.txt", "upper")
	put(t, e, "a.txt", "lower")
	put(t, e, "FolderVerify-linux-amd64", "linux tool")
	put(t, e, "FolderVerify-linux-arm64", "linux tool")
	m := generate(t, e)
	if len(m.Files) != 4 {
		t.Fatal(m)
	}
	if r := e.Verify(context.Background(), m); r.Conclusion() != "通过" {
		t.Fatal(r)
	}
}
func TestLinuxSwappedDirectoryIsNotFollowed(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	outside := t.TempDir()
	put(t, New(outside, ""), "config & file.txt", "outside secret")
	e.BeforeRead = func(p string) {
		if p == "中文 目录/config & file.txt" {
			old := filepath.Join(e.Root, "中文 目录")
			if err := os.Rename(old, old+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	r := e.Verify(context.Background(), m)
	if r.Conclusion() == "通过" {
		t.Fatal(r)
	}
	for _, v := range r.Items {
		if v.Path == "中文 目录/config & file.txt" && (v.Status != "ERROR" || v.Actual != "") {
			t.Fatal("directory swap read outside root", v)
		}
	}
}
func TestLinuxChangesCannotBeHiddenByRestoringMTime(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	p := filepath.Join(e.Root, "empty.bin")
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	once := false
	e.Progress = func(progress Progress) {
		if !once && progress.Phase == "校验 SHA-512" && progress.Done == 2 {
			once = true
			// Linux may reuse a timestamp within one clock tick. Ensure the
			// fixture has an observable ctime change before asserting detection.
			deadline := time.Now().Add(3 * time.Second)
			for {
				put(t, e, "empty.bin", "")
				if err := os.Chtimes(p, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
				after, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if after.Sys().(*syscall.Stat_t).Ctim != info.Sys().(*syscall.Stat_t).Ctim {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("fixture ctime did not advance")
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	r := e.Verify(context.Background(), m)
	if r.Complete {
		t.Fatal("ctime mutation was missed", r)
	}
}
