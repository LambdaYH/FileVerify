package verify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var moveFileEx = kernel.NewProc("MoveFileExW")

func longPath(p string) string {
	p, _ = filepath.Abs(p)
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	return `\\?\` + p
}
func isSpecial(info os.FileInfo) bool {
	a, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return info.Mode()&os.ModeSymlink != 0 || (ok && a.FileAttributes&0x400 != 0)
}

// Hold every parent without FILE_SHARE_WRITE / FILE_SHARE_DELETE. This prevents
// a directory being replaced by a junction between validation and file opening.
func (e *Engine) safeOpen(rel string) (*os.File, func(), error) {
	parts := strings.Split(filepath.FromSlash(rel), string(filepath.Separator))
	paths := []string{e.Root}
	p := e.Root
	for _, part := range parts {
		if part == "" {
			continue
		}
		p = filepath.Join(p, part)
		paths = append(paths, p)
	}
	var held []syscall.Handle
	cleanup := func() {
		for i := len(held) - 1; i >= 0; i-- {
			syscall.CloseHandle(held[i])
		}
	}
	for i, p := range paths {
		ptr, err := syscall.UTF16PtrFromString(longPath(p))
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		access := uint32(0)
		if i == len(paths)-1 {
			access = syscall.GENERIC_READ
		}
		h, err := syscall.CreateFile(ptr, access, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000|0x02000000, 0)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		var info syscall.ByHandleFileInformation
		err = syscall.GetFileInformationByHandle(h, &info)
		if err != nil || info.FileAttributes&0x400 != 0 {
			syscall.CloseHandle(h)
			cleanup()
			if err == nil {
				err = errors.New("拒绝符号链接 / Junction / 重解析点")
			}
			return nil, func() {}, err
		}
		if i < len(paths)-1 {
			if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
				syscall.CloseHandle(h)
				cleanup()
				return nil, func() {}, errors.New("父路径不是目录")
			}
			held = append(held, h)
		} else {
			if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
				syscall.CloseHandle(h)
				cleanup()
				return nil, func() {}, errors.New("不是普通文件")
			}
			return os.NewFile(uintptr(h), p), cleanup, nil
		}
	}
	cleanup()
	return nil, func() {}, errors.New("文件路径为空")
}
func lockDirectory(p string) (syscall.Handle, error) {
	ptr, err := syscall.UTF16PtrFromString(longPath(p))
	if err != nil {
		return 0, err
	}
	h, err := syscall.CreateFile(ptr, 0, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0x00200000|0x02000000, 0)
	if err != nil {
		return 0, err
	}
	var info syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(h, &info)
	if err != nil || info.FileAttributes&0x400 != 0 || info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		syscall.CloseHandle(h)
		return 0, fmt.Errorf("目录无法安全扫描：%s", p)
	}
	return h, nil
}
func atomicMove(from, to string, replace bool) error {
	a, _ := syscall.UTF16PtrFromString(longPath(from))
	b, _ := syscall.UTF16PtrFromString(longPath(to))
	flags := uintptr(8)
	if replace {
		flags |= 1
	}
	r, _, err := moveFileEx.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), flags)
	if r == 0 {
		return err
	}
	return nil
}
