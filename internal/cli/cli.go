package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"folderverify/internal/verify"
)

// Run accepts the executable path explicitly so tests can exercise real roots
// without changing the process working directory.
func Run(ctx context.Context, args []string, input io.Reader, out, errOut io.Writer, exe string) int {
	flags := flag.NewFlagSet("FolderVerify", flag.ContinueOnError)
	flags.SetOutput(errOut)
	regenerate := flags.Bool("regenerate", false, "重新生成清单，需要两次输入 YES 确认")
	report := flags.Bool("report", false, "导出 / 覆盖根目录 verify-report.txt")
	details := flags.Bool("details", false, "显示所有文件的结果及完整 SHA-512")
	quiet := flags.Bool("quiet", false, "不显示处理进度")
	flags.Usage = func() {
		fmt.Fprintf(errOut, "用法：./%s [--report] [--details] [--quiet] [--regenerate]\n默认校验程序所在目录：无清单则生成，有清单则校验。\n", filepath.Base(exe))
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	exe, err := filepath.Abs(exe)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	e := verify.New(filepath.Dir(exe), exe)
	fmt.Fprintf(out, "FolderVerify | SHA-512\n目录：%q\n", e.Root)
	fmt.Fprintln(out, "哈希校验只能判断清单与文件是否一致，不能防止两者同时被恶意修改。")
	if *regenerate {
		reader := bufio.NewReader(input)
		for _, prompt := range []string{"重新生成会将当前文件作为新基准。输入 YES 继续：", "再次确认覆盖原始清单。输入 YES："} {
			fmt.Fprintln(out, prompt)
			if !confirm(ctx, reader) {
				fmt.Fprintln(errOut, "已取消重新生成，原清单未修改。")
				return 130
			}
		}
	}
	var last time.Time
	if !*quiet {
		e.Progress = func(p verify.Progress) {
			if time.Since(last) < 200*time.Millisecond && p.Done != p.Total {
				return
			}
			last = time.Now()
			fmt.Fprintf(errOut, "%s %d/%d %q\n", p.Phase, p.Done, p.Total, p.Path)
		}
	}
	mode, m, err := e.Detect()
	if err != nil && !*regenerate {
		fmt.Fprintln(errOut, "清单无法读取或无效，禁止自动生成：", err)
		return 2
	}
	var result verify.Result
	if *regenerate {
		result = e.Generate(ctx, true)
	} else if mode == "生成" {
		result = e.Generate(ctx, false)
	} else {
		result = e.Verify(ctx, m)
	}
	fmt.Fprintln(out, strings.ReplaceAll(result.Summary(), "\r\n", "\n"))
	for _, item := range result.Items {
		if item.Status == "PASS" && !*details {
			continue
		}
		fmt.Fprintf(out, "[%s] %q\n", item.Status, item.Path)
		if item.Reason != "" {
			fmt.Fprintln(out, "原因：", item.Reason)
		}
		fmt.Fprintln(out, "预期 SHA-512：", item.Expected)
		fmt.Fprintln(out, "实际 SHA-512：", item.Actual)
	}
	if *report {
		if err := e.Export(result); err != nil {
			fmt.Fprintln(errOut, "报告保存失败：", err)
			return 2
		}
		fmt.Fprintln(out, "报告已保存：", filepath.Join(e.Root, verify.ReportName))
	}
	if ctx.Err() != nil {
		return 130
	}
	if !result.Complete || result.Counts()["ERROR"] > 0 {
		return 2
	}
	if result.Conclusion() == "不通过" {
		return 1
	}
	return 0
}
func confirm(ctx context.Context, reader *bufio.Reader) bool {
	result := make(chan bool, 1)
	go func() {
		line, err := reader.ReadString('\n')
		result <- strings.TrimSpace(line) == "YES" && (err == nil || errors.Is(err, io.EOF))
	}()
	select {
	case <-ctx.Done():
		return false
	case yes := <-result:
		return yes
	}
}
