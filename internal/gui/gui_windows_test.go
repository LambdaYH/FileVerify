package gui

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Run against the actual GUI-subsystem EXE, from an unrelated working directory.
// The temporary executable is named differently to exercise self-exclusion.
func TestNativeMemoryAPI(t *testing.T) {
	if err := kernel.NewProc("RtlMoveMemory").Find(); err != nil {
		t.Fatal(err)
	}
}
func TestNativeEXEWorkflow(t *testing.T) {
	source := os.Getenv("FOLDERVERIFY_TEST_EXE")
	if source == "" {
		t.Skip("set FOLDERVERIFY_TEST_EXE to the compiled EXE for native integration testing")
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	image, err := pe.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if image.OptionalHeader.(*pe.OptionalHeader64).Subsystem != 2 {
		t.Fatal("EXE must use Windows GUI subsystem")
	}
	image.Close()
	root := t.TempDir()
	exe := filepath.Join(root, "Renamed.exe")
	if err = os.WriteFile(exe, b, 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "中文 测试.txt")
	if err = os.WriteFile(data, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(want string) {
		t.Helper()
		cmd := exec.Command(exe)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		cmd.Dir = os.TempDir()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer cmd.Process.Kill()
		var window uintptr
		deadline := time.Now().Add(20 * time.Second)
		found := false
		var observed string
		var windows string
		for time.Now().Before(deadline) {
			windows = ""
			ret(user.NewProc("EnumWindows").Call(syscall.NewCallback(func(h, l uintptr) uintptr {
				var pid uint32
				ret(user.NewProc("GetWindowThreadProcessId").Call(h, uintptr(unsafe.Pointer(&pid))))
				var caption [200]uint16
				ret(user.NewProc("GetWindowTextW").Call(h, uintptr(unsafe.Pointer(&caption[0])), 200))
				if strings.Contains(syscall.UTF16ToString(caption[:]), "FolderVerify") {
					windows += fmt.Sprintf("pid=%d caption=%s; ", pid, syscall.UTF16ToString(caption[:]))
				}
				var class [100]uint16
				ret(user.NewProc("GetClassNameW").Call(h, uintptr(unsafe.Pointer(&class[0])), 100))
				if int(pid) == cmd.Process.Pid && syscall.UTF16ToString(class[:]) == "FolderVerifyNativeWindow" {
					window = h
					return 0
				}
				return 1
			}), 0))
			if window != 0 {
				observed = ""
				ret(user.NewProc("EnumChildWindows").Call(window, syscall.NewCallback(func(h, l uintptr) uintptr {
					var text [2048]uint16
					ret(user.NewProc("SendMessageW").Call(h, 0xd, uintptr(len(text)), uintptr(unsafe.Pointer(&text[0]))))
					observed += syscall.UTF16ToString(text[:]) + " | "
					if strings.HasPrefix(syscall.UTF16ToString(text[:]), want+"\r\n") {
						found = true
					}
					return 1
				}), 0))
			}
			if found {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !found {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("native GUI did not show %q within timeout: %s; observed: %s; target=%d; windows=%s", want, output.String(), observed, cmd.Process.Pid, windows)
		}
		var list uintptr
		ret(user.NewProc("EnumChildWindows").Call(window, syscall.NewCallback(func(h, l uintptr) uintptr {
			var name [100]uint16
			ret(user.NewProc("GetClassNameW").Call(h, uintptr(unsafe.Pointer(&name[0])), 100))
			if syscall.UTF16ToString(name[:]) == "SysListView32" {
				list = h
			}
			return 1
		}), 0))
		if list == 0 {
			t.Fatal("native result list missing")
		}
		if want == "清单生成成功" {
			assertAdaptiveWindow(t, window, list)
		}
		send(list, 0x100, 0x24, 0)
		fullHash := false
		ret(user.NewProc("EnumChildWindows").Call(window, syscall.NewCallback(func(h, l uintptr) uintptr {
			var text [2048]uint16
			ret(user.NewProc("SendMessageW").Call(h, 0xd, 2048, uintptr(unsafe.Pointer(&text[0]))))
			if regexp.MustCompile(`[0-9a-f]{128}`).MatchString(syscall.UTF16ToString(text[:])) {
				fullHash = true
			}
			return 1
		}), 0))
		if !fullHash {
			t.Fatal("selected result does not show a full SHA-512")
		}
		send(window, 0x10, 0, 0)
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	run("清单生成成功")
	manifest := filepath.Join(root, "sha512-manifest.json")
	before, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "Renamed.exe") {
		t.Fatal("self executable included")
	}
	run("通过")
	if err = os.WriteFile(data, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	run("不通过")
	after, _ := os.ReadFile(manifest)
	if string(before) != string(after) {
		t.Fatal("GUI verification changed manifest")
	}
}

func assertAdaptiveWindow(t *testing.T, window, list uintptr) {
	t.Helper()
	var smallFont uintptr
	for index, size := range []point{{640, 480}, {500, 420}, {1200, 900}} {
		if ret(user.NewProc("SetWindowPos").Call(window, 0, 0, 0, uintptr(size.x), uintptr(size.y), 0x16)) == 0 {
			t.Fatal("cannot resize native window")
		}
		var outer, client rect
		ret(user.NewProc("GetWindowRect").Call(window, uintptr(unsafe.Pointer(&outer))))
		ret(user.NewProc("GetClientRect").Call(window, uintptr(unsafe.Pointer(&client))))
		if index == 0 && (outer.right-outer.left > 640 || outer.bottom-outer.top > 480) {
			t.Fatal("window still has a large minimum size", outer)
		}
		var controls []rect
		ret(user.NewProc("EnumChildWindows").Call(window, syscall.NewCallback(func(child, l uintptr) uintptr {
			if ret(user.NewProc("GetParent").Call(child)) != window {
				return 1
			}
			var bounds rect
			ret(user.NewProc("GetWindowRect").Call(child, uintptr(unsafe.Pointer(&bounds))))
			ret(user.NewProc("MapWindowPoints").Call(0, window, uintptr(unsafe.Pointer(&bounds)), 2))
			controls = append(controls, bounds)
			return 1
		}), 0))
		for i, bounds := range controls {
			if bounds.left < 0 || bounds.top < 0 || bounds.right > client.right || bounds.bottom > client.bottom || bounds.right <= bounds.left || bounds.bottom <= bounds.top {
				t.Fatalf("control outside client area at %dx%d: %+v (client %+v)", size.x, size.y, bounds, client)
			}
			for _, previous := range controls[:i] {
				if bounds.left < previous.right && bounds.right > previous.left && bounds.top < previous.bottom && bounds.bottom > previous.top {
					t.Fatalf("controls overlap at %dx%d: %+v %+v", size.x, size.y, bounds, previous)
				}
			}
		}
		currentFont := send(list, 0x31, 0, 0)
		if currentFont == 0 {
			t.Fatal("result list has no font")
		}
		if index == 1 {
			smallFont = currentFont
		}
		if index == 2 && currentFont == smallFont {
			t.Fatal("font did not adapt when window expanded")
		}
		if header := send(list, 0x101f, 0, 0); send(header, 0x31, 0, 0) != currentFont {
			t.Fatal("result header font did not scale with rows")
		}
	}
}
