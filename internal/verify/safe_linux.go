package verify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

const oPath = 0x200000

func longPath(p string) string        { return p }
func pathKey(p string) string         { return p }
func isSpecial(info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }
func unchangedMetadata(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x.Ctim == y.Ctim
}
func openRoot(root string) (*os.File, error) {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), root), nil
}

// Resolve every component relative to pinned directory handles. O_NOFOLLOW
// prevents both final-file and intermediate-directory symlink substitution.
func openRelative(root *os.File, rel string) (*os.File, error) {
	if rel != "." && !fs.ValidPath(rel) {
		return nil, errors.New("不安全的相对路径")
	}
	fd, err := syscall.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), filepath.Join(root.Name(), filepath.FromSlash(rel)))
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("无法读取非普通文件")
	}
	return f, nil
}
func (e *Engine) safeOpen(rel string) (*os.File, func(), error) {
	if !validPath(rel) {
		return nil, func() {}, errors.New("不安全的相对路径")
	}
	root, err := openRoot(e.Root)
	if err != nil {
		return nil, func() {}, err
	}
	f, err := openRelative(root, rel)
	if err != nil {
		root.Close()
		return nil, func() {}, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		root.Close()
		if err == nil {
			err = errors.New("不是普通文件")
		}
		return nil, func() {}, err
	}
	return f, func() { root.Close() }, nil
}

type secureFS struct{ root *os.File }

func (s secureFS) Open(name string) (fs.File, error) { return openRelative(s.root, name) }

// Snapshot entry metadata with O_PATH | O_NOFOLLOW while the parent is open,
// instead of resolving DirEntry.Info through a mutable absolute pathname.
func (s secureFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f, err := openRelative(s.root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	entries := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		fd, err := syscall.Openat(int(f.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		child := os.NewFile(uintptr(fd), name)
		info, err := child.Stat()
		child.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, fs.FileInfoToDirEntry(info))
	}
	return entries, nil
}
func (e *Engine) scan(ctx context.Context) snapshot {
	s := snapshot{}
	root, err := openRoot(e.Root)
	if err != nil {
		s.issues = []Item{{Path: ".", Status: "ERROR", Reason: "扫描失败：" + err.Error()}}
		s.blocked = []string{"."}
		return s
	}
	defer root.Close()
	err = fs.WalkDir(secureFS{root}, ".", func(rel string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if rel != "." && e.excluded(rel) {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		problem := func(reason string) {
			s.issues = append(s.issues, Item{Path: rel, Status: "ERROR", Reason: reason})
			s.blocked = append(s.blocked, rel)
		}
		if err != nil {
			problem("扫描失败：" + err.Error())
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			problem(err.Error())
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if isSpecial(info) {
			problem("无法校验符号链接：不跟随读取")
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || !validPath(rel) {
			problem("非普通文件或不安全路径")
			return nil
		}
		s.files = append(s.files, scanned{rel, info})
		if len(s.files)%100 == 0 {
			e.emit(Progress{Phase: "扫描文件", Total: len(s.files), Path: rel})
		}
		return nil
	})
	if err != nil {
		s.issues = append(s.issues, Item{Path: ".", Status: "ERROR", Reason: err.Error()})
		s.blocked = append(s.blocked, ".")
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].path < s.files[j].path })
	return s
}
func linkAt(fd int, from, to string) error {
	a, err := syscall.BytePtrFromString(from)
	if err != nil {
		return err
	}
	b, err := syscall.BytePtrFromString(to)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(fd), uintptr(unsafe.Pointer(a)), uintptr(fd), uintptr(unsafe.Pointer(b)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func (e *Engine) writeAtomic(ctx context.Context, name string, b []byte, replace bool) error {
	root, err := openRoot(e.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	temp := ".folderverify-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := syscall.Openat(int(root.Fd()), temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(int(root.Fd()), temp)
	f := os.NewFile(uintptr(fd), temp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if replace {
		err = syscall.Renameat(int(root.Fd()), temp, int(root.Fd()), name)
	} else {
		err = linkAt(int(root.Fd()), temp, name)
	}
	if err != nil {
		return err
	}
	_ = root.Sync()
	return nil
}
