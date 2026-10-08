package verify

import (
	"context"
	"fmt"
	"strings"
)

func (r Result) Report() string {
	var b strings.Builder
	b.WriteString("FolderVerify 文件完整性校验报告\r\n")
	fmt.Fprintf(&b, "校验时间：%s\r\n校验目录：%s\r\n%s\r\n\r\n", r.Time.Format("2006-01-02 15:04:05 -07:00"), r.Root, r.Summary())
	for _, v := range r.Items {
		if v.Status == "PASS" {
			continue
		}
		fmt.Fprintf(&b, "[%s] %s\r\n原因：%s\r\n预期 SHA-512：%s\r\n实际 SHA-512：%s\r\n\r\n", v.Status, v.Path, v.Reason, v.Expected, v.Actual)
	}
	b.WriteString("哈希校验只能判断清单与文件是否一致；不能防止文件和清单被同时恶意修改。\r\n")
	return b.String()
}
func (e *Engine) Export(r Result) error {
	return e.writeAtomic(context.Background(), ReportName, append([]byte{0xef, 0xbb, 0xbf}, []byte(r.Report())...), true)
}
