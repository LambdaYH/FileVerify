package verify

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const ManifestName = "sha512-manifest.json"
const ReportName = "verify-report.txt"

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA512 string `json:"sha512"`
}
type Manifest struct {
	Version   int     `json:"version"`
	Algorithm string  `json:"algorithm"`
	Files     []Entry `json:"files"`
}
type Item struct{ Path, Status, Expected, Actual, Reason string }
type Result struct {
	Mode, Root                 string
	Time                       time.Time
	ManifestCount, ActualCount int
	Items                      []Item
	Complete                   bool
	Failure                    string
}
type Progress struct {
	Phase, Path string
	Total, Done int
}
type Engine struct {
	Root, Exe  string
	Progress   func(Progress)
	BeforeRead func(string)
}

func New(root, exe string) *Engine { return &Engine{Root: root, Exe: exe} }
func (e *Engine) emit(p Progress) {
	if e.Progress != nil {
		e.Progress(p)
	}
}
func (e *Engine) excluded(rel string) bool {
	if strings.EqualFold(filepath.Join(e.Root, filepath.FromSlash(rel)), e.Exe) {
		return true
	}
	if strings.Contains(rel, "/") {
		return false
	}
	s := strings.ToLower(rel)
	return s == ManifestName || s == ReportName || strings.HasPrefix(s, ".folderverify-")
}
func (r Result) Counts() map[string]int {
	m := map[string]int{}
	for _, v := range r.Items {
		m[v.Status]++
	}
	return m
}
func (r Result) Conclusion() string {
	if !r.Complete {
		return "校验未完成"
	}
	c := r.Counts()
	if c["MODIFIED"]+c["MISSING"]+c["ADDED"]+c["ERROR"] > 0 {
		return "不通过"
	}
	if r.Mode == "生成" {
		return "清单生成成功"
	}
	return "通过"
}
func (r Result) Summary() string {
	c := r.Counts()
	return fmt.Sprintf("%s\r\n模式：%s   算法：SHA-512\r\n清单文件：%d   实际普通文件：%d\r\n通过：%d   修改：%d   缺失：%d   新增：%d   错误：%d\r\n%s", r.Conclusion(), r.Mode, r.ManifestCount, r.ActualCount, c["PASS"], c["MODIFIED"], c["MISSING"], c["ADDED"], c["ERROR"], r.Failure)
}
