package verify

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

func (e *Engine) scan(ctx context.Context) snapshot {
	s := snapshot{}
	var held []syscall.Handle
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			syscall.CloseHandle(held[i])
		}
	}()
	err := filepath.WalkDir(longPath(e.Root), func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(longPath(e.Root), p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && e.excluded(rel) {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
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
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			problem(err.Error())
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if isSpecial(info) {
			problem("无法校验特殊文件：符号链接 / Junction / 重解析点")
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			h, err := lockDirectory(p)
			if err != nil {
				problem(err.Error())
				return filepath.SkipDir
			}
			held = append(held, h)
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
func (e *Engine) writeAtomic(ctx context.Context, name string, b []byte, replace bool) error {
	h, err := lockDirectory(e.Root)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	f, err := os.CreateTemp(longPath(e.Root), ".folderverify-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
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
	return atomicMove(tmp, filepath.Join(e.Root, name), replace)
}
