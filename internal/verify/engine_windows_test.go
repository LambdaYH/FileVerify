package verify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadFailureNeverPasses(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	p, _ := syscall.UTF16PtrFromString(filepath.Join(e.Root, "empty.bin"))
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	r := e.Verify(context.Background(), m)
	status(t, r, "ERROR", 1)
	if r.Conclusion() == "通过" {
		t.Fatal(r)
	}
}
func TestUnreadableManifestStopsStartup(t *testing.T) {
	e := fixture(t)
	generate(t, e)
	p, _ := syscall.UTF16PtrFromString(filepath.Join(e.Root, ManifestName))
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	mode, _, err := e.Detect()
	if mode != "校验" || err == nil {
		t.Fatal(mode, err)
	}
}
func TestJunctionAndSymlinkAreNotFollowed(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(e.Root, "junction")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Fatalf("junction fixture failed: %v %s", err, out)
	}
	defer os.Remove(junction)
	r := e.Verify(context.Background(), m)
	status(t, r, "ERROR", 1)
	if r.Complete || r.Conclusion() == "通过" {
		t.Fatal(r)
	}
	for _, v := range r.Items {
		if strings.Contains(v.Path, "secret") {
			t.Fatal("junction followed", v)
		}
	}
	if _, cleanup, err := e.safeOpen("junction/secret.txt"); err == nil {
		cleanup()
		t.Fatal("unsafe open followed junction")
	}
	if err := os.Remove(junction); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.Root, "symlink.txt")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), link); err != nil {
		t.Log("symlink creation requires developer mode; Junction coverage completed:", err)
		return
	}
	r = e.Verify(context.Background(), m)
	status(t, r, "ERROR", 1)
}
