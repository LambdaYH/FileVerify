package verify

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"sort"
	"strings"

	"time"
)

type scanned struct {
	path string
	info os.FileInfo
}
type snapshot struct {
	files   []scanned
	issues  []Item
	blocked []string
}

func same(a, b os.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && os.SameFile(a, b) && unchangedMetadata(a, b)
}
func (e *Engine) hash(ctx context.Context, s scanned, buf []byte) (Entry, error) {
	if e.BeforeRead != nil {
		e.BeforeRead(s.path)
	}
	f, cleanup, err := e.safeOpen(s.path)
	if err != nil {
		return Entry{}, err
	}
	defer cleanup()
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	if !same(s.info, before) {
		return Entry{}, errors.New("文件在扫描后发生变化")
	}
	h := sha512.New()
	var n int64
	for {
		if ctx.Err() != nil {
			return Entry{}, ctx.Err()
		}
		nr, er := f.Read(buf)
		if nr > 0 {
			h.Write(buf[:nr])
			n += int64(nr)
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			return Entry{}, er
		}
		if nr == 0 {
			return Entry{}, io.ErrNoProgress
		}
	}
	after, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	if !same(before, after) || n != before.Size() {
		return Entry{}, errors.New("文件在读取期间发生变化")
	}
	return Entry{Path: s.path, Size: n, SHA512: hex.EncodeToString(h.Sum(nil))}, nil
}
func (e *Engine) stable(ctx context.Context, first snapshot) error {
	next := e.scan(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(next.issues) > 0 {
		return errors.New("结束复查时扫描失败，结果未完成")
	}
	if len(first.files) != len(next.files) {
		return errors.New("处理期间文件数量发生变化，请重新运行")
	}
	for i, f := range first.files {
		if f.path != next.files[i].path || !same(f.info, next.files[i].info) {
			return fmt.Errorf("处理期间文件发生变化：%s，请重新运行", f.path)
		}
	}
	return nil
}
func (e *Engine) Generate(ctx context.Context, replace bool) Result {
	r := Result{Root: e.Root, Mode: "生成", Time: time.Now()}
	s := e.scan(ctx)
	r.ActualCount = len(s.files)
	r.Items = append(r.Items, s.issues...)
	m := Manifest{Version: 1, Algorithm: "SHA-512", Files: make([]Entry, 0, len(s.files))}
	buf := make([]byte, 1024*1024)
	for i, f := range s.files {
		if ctx.Err() != nil {
			break
		}
		e.emit(Progress{Phase: "生成清单", Path: f.path, Total: len(s.files), Done: i})
		v, err := e.hash(ctx, f, buf)
		if err != nil {
			r.Items = append(r.Items, Item{Path: f.path, Status: "ERROR", Reason: err.Error()})
		} else {
			m.Files = append(m.Files, v)
			r.Items = append(r.Items, Item{Path: f.path, Status: "PASS", Actual: v.SHA512})
		}
		e.emit(Progress{Phase: "生成清单", Path: f.path, Total: len(s.files), Done: i + 1})
	}
	if ctx.Err() != nil {
		r.Failure = "用户取消：未生成正式清单"
		return r
	}
	if r.Counts()["ERROR"] > 0 {
		r.Failure = "生成失败：存在无法读取或扫描的文件，未写入清单"
		return r
	}
	e.emit(Progress{Phase: "复查文件集合", Total: len(s.files), Done: len(s.files)})
	if err := e.stable(ctx, s); err != nil {
		r.Failure = err.Error()
		return r
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err == nil {
		err = e.writeAtomic(ctx, ManifestName, append(b, '\n'), replace)
	}
	if err != nil {
		r.Failure = "清单保存失败：" + err.Error()
		return r
	}
	r.ManifestCount = len(m.Files)
	r.Complete = true
	return r
}
func (e *Engine) Verify(ctx context.Context, m *Manifest) Result {
	r := Result{Root: e.Root, Mode: "校验", Time: time.Now(), ManifestCount: len(m.Files)}
	s := e.scan(ctx)
	r.ActualCount = len(s.files)
	r.Items = append(r.Items, s.issues...)
	expected := map[string]Entry{}
	seen := map[string]bool{}
	for _, v := range m.Files {
		expected[v.Path] = v
	}
	buf := make([]byte, 1024*1024)
	for i, f := range s.files {
		if ctx.Err() != nil {
			break
		}
		e.emit(Progress{Phase: "校验 SHA-512", Path: f.path, Total: len(s.files), Done: i})
		want, exists := expected[f.path]
		seen[f.path] = true
		item := Item{Path: f.path, Expected: want.SHA512}
		got, err := e.hash(ctx, f, buf)
		if err != nil {
			item.Status = "ERROR"
			item.Reason = err.Error()
		} else {
			item.Actual = got.SHA512
			if !exists {
				item.Status = "ADDED"
				item.Reason = "实际文件未记录在清单中"
			} else if !strings.EqualFold(want.SHA512, got.SHA512) {
				item.Status = "MODIFIED"
				item.Reason = fmt.Sprintf("SHA-512 不一致；清单大小 %d，实际大小 %d", want.Size, got.Size)
			} else if want.Size != got.Size {
				item.Status = "ERROR"
				item.Reason = "SHA-512 一致但清单大小不一致，清单元数据异常"
			} else {
				item.Status = "PASS"
			}
		}
		r.Items = append(r.Items, item)
		e.emit(Progress{Phase: "校验 SHA-512", Path: f.path, Total: len(s.files), Done: i + 1})
	}
	for _, want := range m.Files {
		if seen[want.Path] {
			continue
		}
		status, reason := "MISSING", "清单中的文件不存在"
		if ctx.Err() != nil {
			status, reason = "ERROR", "用户取消，文件未校验"
		} else {
			for _, p := range s.blocked {
				if p == "." || want.Path == p || strings.HasPrefix(want.Path, p+"/") {
					status, reason = "ERROR", "所在路径扫描失败或被拒绝，无法判断文件是否存在"
					break
				}
			}
		}
		already := false
		for _, v := range s.issues {
			if v.Path == want.Path {
				already = true
				break
			}
		}
		if !already {
			r.Items = append(r.Items, Item{Path: want.Path, Status: status, Expected: want.SHA512, Reason: reason})
		}
	}
	sort.Slice(r.Items, func(i, j int) bool { return r.Items[i].Path < r.Items[j].Path })
	if ctx.Err() != nil {
		r.Failure = "用户取消，校验未完成"
		return r
	}
	if len(s.issues) > 0 {
		r.Failure = "扫描不完整，无法给出完整校验结论"
		return r
	}
	e.emit(Progress{Phase: "复查文件集合", Total: len(s.files), Done: len(s.files)})
	if err := e.stable(ctx, s); err != nil {
		r.Failure = err.Error()
		return r
	}
	r.Complete = true
	return r
}
