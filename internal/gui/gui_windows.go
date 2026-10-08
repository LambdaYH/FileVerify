package gui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"folderverify/internal/verify"
)

var user = syscall.NewLazyDLL("user32.dll")
var kernel = syscall.NewLazyDLL("kernel32.dll")
var common = syscall.NewLazyDLL("comctl32.dll")
var gdi = syscall.NewLazyDLL("gdi32.dll")

func ret(result uintptr, _ uintptr, _ error) uintptr { return result }

func u(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }
func setText(h uintptr, s string) {
	ret(user.NewProc("SetWindowTextW").Call(h, uintptr(unsafe.Pointer(u(s)))))
}

//go:uintptrescapes
func send(h uintptr, m uint32, w, l uintptr) uintptr {
	return ret(user.NewProc("SendMessageW").Call(h, uintptr(m), w, l))
}

type point struct{ x, y int32 }
type rect struct{ left, top, right, bottom int32 }
type minmax struct{ reserved, maxSize, maxPosition, minTrack, maxTrack point }
type msg struct {
	hwnd           uintptr
	message        uint32
	wparam, lparam uintptr
	time           uint32
	pt             point
	private        uint32
}
type wndclass struct {
	size, style                        uint32
	proc                               uintptr
	extra, windowExtra                 int32
	instance, icon, cursor, background uintptr
	menu, class                        *uint16
	smallIcon                          uintptr
}
type lvcol struct {
	mask                                                       uint32
	format, width                                              int32
	text                                                       *uint16
	max, sub, image, order, minWidth, defaultWidth, idealWidth int32
}
type lvitem struct {
	mask             uint32
	index, sub       int32
	state, stateMask uint32
	text             *uint16
	max, image       int32
	param            uintptr
	indent, group    int32
	columns          uint32
	columnPtr        *uint32
	formats          *int32
	groupIndex       int32
}
type notify struct {
	hwnd, id uintptr
	code     int32
}
type dispinfo struct {
	hdr  notify
	item lvitem
}
type app struct {
	hwnd, rootLabel, modeLabel, current, status, counts, progress, list, detail    uintptr
	cancelButton, verifyButton, regenButton, exportButton, copyButton, closeButton uintptr
	engine                                                                         *verify.Engine
	mu                                                                             sync.Mutex
	pending                                                                        verify.Progress
	finished                                                                       *verify.Result
	result                                                                         verify.Result
	cancel                                                                         context.CancelFunc
	running, started, closing                                                      bool
	textBuffer                                                                     []uint16
	fontPixels                                                                     int32
}

var active *app
var font uintptr
var dpi int32 = 96
var workArea rect

func scale(value int32) int32 { return (value*dpi + 48) / 96 }
func limit(value, maximum int32) int32 {
	if maximum > 0 && value > maximum {
		return maximum
	}
	return value
}

func Run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ret(user.NewProc("SetProcessDPIAware").Call())
	dc := ret(user.NewProc("GetDC").Call(0))
	if dc != 0 {
		if value := int32(ret(gdi.NewProc("GetDeviceCaps").Call(dc, 90))); value > 0 {
			dpi = value
		}
		ret(user.NewProc("ReleaseDC").Call(0, dc))
	}
	ret(user.NewProc("SystemParametersInfoW").Call(0x30, 0, uintptr(unsafe.Pointer(&workArea)), 0))
	init := struct{ size, classes uint32 }{8, 0x21}
	ret(common.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init))))
	exe, err := os.Executable()
	if err != nil {
		message(0, "无法获取 EXE 所在目录："+err.Error(), 0x10)
		return
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		message(0, err.Error(), 0x10)
		return
	}
	a := &app{engine: verify.New(filepath.Dir(exe), exe)}
	active = a
	a.engine.Progress = func(p verify.Progress) { a.mu.Lock(); a.pending = p; a.mu.Unlock() }
	instance := ret(kernel.NewProc("GetModuleHandleW").Call(0))
	class := u("FolderVerifyNativeWindow")
	wc := wndclass{size: uint32(unsafe.Sizeof(wndclass{})), proc: syscall.NewCallback(windowProc), instance: instance, cursor: ret(user.NewProc("LoadCursorW").Call(0, 32512)), icon: ret(user.NewProc("LoadIconW").Call(0, 32516)), background: 16, class: class}
	if ret(user.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))) == 0 {
		message(0, "窗口注册失败", 0x10)
		return
	}
	width := limit(scale(1160), workArea.right-workArea.left)
	height := limit(scale(880), workArea.bottom-workArea.top)
	h := ret(user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(u("FolderVerify · 文件完整性校验"))), 0x00cf0000, 0x80000000, 0x80000000, uintptr(width), uintptr(height), 0, 0, instance, 0))
	if h == 0 {
		message(0, "窗口创建失败", 0x10)
		return
	}
	a.hwnd = h
	ret(user.NewProc("ShowWindow").Call(h, 5))
	ret(user.NewProc("UpdateWindow").Call(h))
	var m msg
	for {
		r, _, _ := user.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if ret(user.NewProc("IsDialogMessageW").Call(h, uintptr(unsafe.Pointer(&m)))) == 0 {
			ret(user.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&m))))
			ret(user.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&m))))
		}
	}
	if font != 0 {
		ret(gdi.NewProc("DeleteObject").Call(font))
	}
}
func message(h uintptr, s string, flags uintptr) uintptr {
	return ret(user.NewProc("MessageBoxW").Call(h, uintptr(unsafe.Pointer(u(s))), uintptr(unsafe.Pointer(u("FolderVerify"))), flags))
}
func (a *app) control(class, text string, style uintptr, id int) uintptr {
	h := ret(user.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(u(class))), uintptr(unsafe.Pointer(u(text))), 0x50000000|style, 0, 0, 100, 24, a.hwnd, uintptr(id), ret(kernel.NewProc("GetModuleHandleW").Call(0)), 0))
	send(h, 0x30, font, 1)
	return h
}
func (a *app) create() {
	a.rootLabel = a.control("EDIT", a.engine.Root, 0x800|0x80|0x10000, 0)
	a.modeLabel = a.control("STATIC", "正在识别工作模式…  |  SHA-512", 0, 0)
	a.current = a.control("EDIT", "准备扫描", 0x800|0x80, 0)
	a.progress = a.control("msctls_progress32", "", 0, 0)
	a.counts = a.control("STATIC", "文件总数：0   已完成：0", 0, 0)
	a.status = a.control("EDIT", "正在启动", 0x800|4|0x40|0x200000, 0)
	a.cancelButton = a.control("BUTTON", "取消任务", 0x10000, 101)
	a.verifyButton = a.control("BUTTON", "重新校验", 0x10000, 102)
	a.regenButton = a.control("BUTTON", "重新生成清单…", 0x10000, 103)
	a.exportButton = a.control("BUTTON", "导出报告", 0x10000, 104)
	a.copyButton = a.control("BUTTON", "复制摘要", 0x10000, 105)
	a.closeButton = a.control("BUTTON", "关闭", 0x10000, 106)
	a.list = a.control("SysListView32", "", 0x1000|1|4|8|0x10000|0x800000, 107)
	send(a.list, 0x1036, 0, 0x20|1|0x10000)
	for i, col := range []struct {
		name  string
		width int32
	}{{"文件相对路径", 270}, {"状态", 95}, {"预期 SHA-512", 230}, {"实际 SHA-512", 230}, {"原因", 300}} {
		c := lvcol{mask: 7, width: scale(col.width), text: u(col.name)}
		send(a.list, 0x1061, uintptr(i), uintptr(unsafe.Pointer(&c)))
	}
	a.detail = a.control("EDIT", "选择结果行可查看及复制完整 SHA-512。\r\n哈希校验只能判断清单与文件是否一致，不能防止文件和清单被同时恶意修改。", 0x800|4|0x40|0x1000|0x200000|0x10000, 108)
	a.layout()
	a.enable(false)
	ret(user.NewProc("SetTimer").Call(a.hwnd, 1, 100, 0))
}
func move(h uintptr, x, y, w, height int32) {
	if w < 1 {
		w = 1
	}
	if height < 1 {
		height = 1
	}
	ret(user.NewProc("MoveWindow").Call(h, uintptr(x), uintptr(y), uintptr(w), uintptr(height), 1))
}
func (a *app) layout() {
	var r rect
	ret(user.NewProc("GetClientRect").Call(a.hwnd, uintptr(unsafe.Pointer(&r))))
	w, h := r.right, r.bottom
	if w <= 0 || h <= 0 {
		return
	}
	// Fit to both dimensions, so short or narrow windows also reduce the font.
	pixels := w * 19 / 1120
	if vertical := h * 19 / 800; vertical < pixels {
		pixels = vertical
	}
	if pixels < 11 {
		pixels = 11
	}
	if maximum := scale(28); pixels > maximum {
		pixels = maximum
	}
	a.updateFont(pixels)
	if a.fontPixels > 0 {
		pixels = a.fontPixels
	}
	margin, gap := pixels, pixels/3
	if gap < 4 {
		gap = 4
	}
	rowHeight := pixels + pixels/2 + 2
	contentWidth := w - 2*margin
	y := margin
	for _, control := range []uintptr{a.rootLabel, a.modeLabel, a.current} {
		move(control, margin, y, contentWidth, rowHeight)
		y += rowHeight + gap
	}
	progressHeight := pixels * 3 / 4
	if progressHeight < 10 {
		progressHeight = 10
	}
	move(a.progress, margin, y, contentWidth, progressHeight)
	y += progressHeight + gap
	move(a.counts, margin, y, contentWidth, rowHeight)
	y += rowHeight + gap
	statusLines := int32(5)
	if h < pixels*32 {
		statusLines = 3
	}
	statusHeight := (pixels + pixels/3 + 2) * statusLines
	move(a.status, margin, y, contentWidth, statusHeight)
	y += statusHeight + gap
	buttons := []uintptr{a.cancelButton, a.verifyButton, a.regenButton, a.exportButton, a.copyButton, a.closeButton}
	columns := int32(6)
	if contentWidth < (pixels*8+gap*2)*6+gap*5 {
		columns = 3
	}
	buttonWidth := (contentWidth - gap*(columns-1)) / columns
	buttonHeight := rowHeight + gap
	for i, b := range buttons {
		move(b, margin+int32(i)%columns*(buttonWidth+gap), y+int32(i)/columns*(buttonHeight+gap), buttonWidth, buttonHeight)
	}
	listTop := y + (6/columns)*(buttonHeight+gap)
	available := h - listTop - margin - gap
	detailHeight := available * 2 / 5
	if preferred := (pixels + pixels/3 + 2) * 7; detailHeight > preferred {
		detailHeight = preferred
	}
	listHeight := available - detailHeight
	move(a.list, margin, listTop, contentWidth, listHeight)
	move(a.detail, margin, listTop+listHeight+gap, contentWidth, detailHeight)
}
func (a *app) updateFont(pixels int32) {
	if pixels == a.fontPixels {
		return
	}
	newFont := ret(gdi.NewProc("CreateFontW").Call(uintptr(int64(-pixels)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 0, 0, uintptr(unsafe.Pointer(u("Microsoft YaHei UI")))))
	if newFont == 0 {
		return
	}
	oldFont := font
	font, a.fontPixels = newFont, pixels
	for _, control := range []uintptr{a.rootLabel, a.modeLabel, a.current, a.counts, a.status, a.list, a.detail, a.cancelButton, a.verifyButton, a.regenButton, a.exportButton, a.copyButton, a.closeButton} {
		send(control, 0x30, font, 1)
	}
	if header := send(a.list, 0x101f, 0, 0); header != 0 {
		send(header, 0x30, font, 1)
	}
	for i, width := range []int32{16, 6, 12, 12, 18} {
		send(a.list, 0x101e, uintptr(i), uintptr(width*pixels))
	}
	if oldFont != 0 {
		ret(gdi.NewProc("DeleteObject").Call(oldFont))
	}
}
func enable(h uintptr, yes bool) {
	v := uintptr(0)
	if yes {
		v = 1
	}
	ret(user.NewProc("EnableWindow").Call(h, v))
}
func (a *app) enable(done bool) {
	enable(a.cancelButton, !done)
	enable(a.verifyButton, done)
	enable(a.regenButton, done)
	enable(a.exportButton, done && a.result.Mode != "")
	enable(a.copyButton, done && a.result.Mode != "")
}
func (a *app) start(regenerate bool) {
	if a.running {
		return
	}
	a.running = true
	a.enable(false)
	a.result = verify.Result{}
	send(a.list, 0x102f, 0, 0)
	setText(a.detail, "任务运行中，可随时取消。")
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.mu.Lock()
	a.pending = verify.Progress{Phase: "识别模式"}
	a.mu.Unlock()
	go func() {
		mode, m, err := a.engine.Detect()
		var r verify.Result
		if regenerate {
			r = a.engine.Generate(ctx, true)
		} else if err != nil {
			r = verify.Result{Root: a.engine.Root, Mode: "校验", Time: time.Now(), Failure: "清单无效，禁止自动生成：" + err.Error()}
		} else if mode == "生成" {
			r = a.engine.Generate(ctx, false)
		} else {
			r = a.engine.Verify(ctx, m)
		}
		a.mu.Lock()
		a.finished = &r
		a.mu.Unlock()
	}()
}
func (a *app) tick() {
	if !a.started {
		a.started = true
		a.start(false)
	}
	a.mu.Lock()
	p := a.pending
	result := a.finished
	a.finished = nil
	a.mu.Unlock()
	if a.running {
		setText(a.modeLabel, "模式 / 阶段："+p.Phase+"   |   SHA-512")
		setText(a.current, p.Path)
		setText(a.counts, fmt.Sprintf("文件总数：%d   已完成：%d", p.Total, p.Done))
		send(a.progress, 0x406, 0, uintptr(p.Total))
		send(a.progress, 0x402, uintptr(p.Done), 0)
		setText(a.status, p.Phase)
	}
	if result != nil {
		a.running = false
		a.cancel = nil
		a.result = *result
		a.enable(true)
		setText(a.modeLabel, "运行模式："+result.Mode+"   |   SHA-512")
		setText(a.status, result.Summary())
		send(a.list, 0x102f, uintptr(len(result.Items)), 0)
		setText(a.detail, "选择结果行可查看和复制完整 SHA-512。\r\n"+result.Failure+"\r\n哈希校验只能判断清单与文件是否一致，不能防止文件和清单被同时恶意修改。")
		if a.closing {
			ret(user.NewProc("DestroyWindow").Call(a.hwnd))
		}
	}
}
func (a *app) selected() {
	i := int32(send(a.list, 0x100c, ^uintptr(0), 2))
	if i < 0 || int(i) >= len(a.result.Items) {
		return
	}
	v := a.result.Items[i]
	setText(a.detail, fmt.Sprintf("文件：%s\r\n状态：%s\r\n预期 SHA-512：%s\r\n实际 SHA-512：%s\r\n原因：%s", v.Path, v.Status, v.Expected, v.Actual, v.Reason))
}
func (a *app) command(id uint16) {
	switch id {
	case 101:
		if a.cancel != nil {
			a.cancel()
			setText(a.status, "正在取消并清理临时文件…")
		}
	case 102:
		a.start(false)
	case 103:
		if !a.running && message(a.hwnd, "重新生成清单会将当前文件作为新的基准，原有差异将无法继续追溯。是否继续？", 0x134) == 6 && message(a.hwnd, "请再次确认：覆盖原始 sha512-manifest.json？", 0x134) == 6 {
			a.start(true)
		}
	case 104:
		if a.running {
			return
		}
		if _, err := os.Lstat(filepath.Join(a.engine.Root, verify.ReportName)); err == nil && message(a.hwnd, "verify-report.txt 已存在，是否覆盖？", 0x134) != 6 {
			return
		}
		if err := a.engine.Export(a.result); err != nil {
			message(a.hwnd, "报告保存失败："+err.Error(), 0x10)
		} else {
			message(a.hwnd, "报告已保存：\r\n"+filepath.Join(a.engine.Root, verify.ReportName), 0x40)
		}
	case 105:
		if err := clipboard(a.hwnd, a.result.Summary()); err != nil {
			message(a.hwnd, err.Error(), 0x10)
		}
	case 106:
		send(a.hwnd, 0x10, 0, 0)
	}
}
func clipboard(h uintptr, s string) error {
	if ret(user.NewProc("OpenClipboard").Call(h)) == 0 {
		return fmt.Errorf("无法打开剪贴板")
	}
	defer ret(user.NewProc("CloseClipboard").Call())
	v, _ := syscall.UTF16FromString(s)
	mem := ret(kernel.NewProc("GlobalAlloc").Call(2, uintptr(len(v)*2)))
	if mem == 0 {
		return fmt.Errorf("剪贴板内存分配失败")
	}
	p := ret(kernel.NewProc("GlobalLock").Call(mem))
	if p == 0 {
		ret(kernel.NewProc("GlobalFree").Call(mem))
		return fmt.Errorf("剪贴板内存锁定失败")
	}
	ret(kernel.NewProc("RtlMoveMemory").Call(p, uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2)))
	ret(kernel.NewProc("GlobalUnlock").Call(mem))
	if ret(user.NewProc("EmptyClipboard").Call()) == 0 || ret(user.NewProc("SetClipboardData").Call(13, mem)) == 0 {
		ret(kernel.NewProc("GlobalFree").Call(mem))
		return fmt.Errorf("复制失败")
	}
	return nil
}
func windowProc(h uintptr, m uint32, w, l uintptr) uintptr {
	a := active
	switch m {
	case 0x24:
		var bounds minmax
		ret(kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&bounds)), l, unsafe.Sizeof(bounds)))
		minimum := rect{right: 480, bottom: 360}
		ret(user.NewProc("AdjustWindowRectEx").Call(uintptr(unsafe.Pointer(&minimum)), 0x00cf0000, 0, 0))
		bounds.minTrack = point{limit(minimum.right-minimum.left, workArea.right-workArea.left), limit(minimum.bottom-minimum.top, workArea.bottom-workArea.top)}
		ret(kernel.NewProc("RtlMoveMemory").Call(l, uintptr(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds)))
		return 0
	case 1:
		a.hwnd = h
		a.create()
		return 0
	case 5:
		if a.list != 0 {
			a.layout()
		}
		return 0
	case 0x113:
		a.tick()
		return 0
	case 0x111:
		a.command(uint16(w))
		return 0
	case 0x4e:
		var n notify
		ret(kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&n)), l, unsafe.Sizeof(n)))
		if n.hwnd == a.list {
			if n.code == -177 {
				var d dispinfo
				ret(kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&d)), l, unsafe.Sizeof(d)))
				if d.item.mask&1 != 0 && d.item.index >= 0 && int(d.item.index) < len(a.result.Items) {
					v := a.result.Items[d.item.index]
					texts := []string{v.Path, v.Status, v.Expected, v.Actual, v.Reason}
					if d.item.sub >= 0 && d.item.sub < 5 {
						a.textBuffer, _ = syscall.UTF16FromString(texts[d.item.sub])
						d.item.text = &a.textBuffer[0]
						ret(kernel.NewProc("RtlMoveMemory").Call(l, uintptr(unsafe.Pointer(&d)), unsafe.Sizeof(d)))
					}
				}
				return 0
			}
			if n.code == -101 {
				a.selected()
				return 0
			}
		}
	case 0x10:
		if a.running {
			if message(h, "任务正在运行，是否取消并关闭？", 0x134) == 6 {
				a.closing = true
				a.cancel()
			}
			return 0
		}
		ret(user.NewProc("DestroyWindow").Call(h))
		return 0
	case 2:
		ret(user.NewProc("KillTimer").Call(h, 1))
		ret(user.NewProc("PostQuitMessage").Call(0))
		return 0
	}
	return ret(user.NewProc("DefWindowProcW").Call(h, uintptr(m), w, l))
}
