# FolderVerify

Windows / Linux 文件夹完整性校验工具，用于内外网文件传输后的 SHA-512 校验。Windows 使用原生 GUI，Linux 使用命令行；完全离线运行，无第三方依赖，无需安装运行环境或管理员权限。

## 使用

1. 将 `FolderVerify.exe` 放入待传输文件夹，双击自动生成 `sha512-manifest.json`。
2. 等待“清单生成成功”，将整个文件夹（包括 EXE 和清单）复制到目标电脑。
3. 再次双击 EXE，自动校验文件是否修改、缺失或新增，并展示读取错误。
4. 选中结果行可查看完整哈希；支持取消任务、复制摘要及导出 `verify-report.txt`。

程序始终以可执行文件所在目录为准，支持中文、Unicode 和长路径（受目标文件系统限制）。校验不会修改原始清单；重新生成需要两次确认。清单损坏或无法读取时停止任务，生成失败或取消时不提交新清单。

### Linux

将 Linux 二进制放入待校验文件夹，执行：

```bash
chmod +x FolderVerify-linux-amd64
./FolderVerify-linux-amd64
./FolderVerify-linux-amd64 --report --details
```

自动识别生成 / 校验模式，以二进制所在目录为准。`--report` 导出或覆盖根目录报告，`--details` 显示所有文件及完整哈希，`--quiet` 隐藏进度。`--regenerate` 需要两次输入 `YES` 才重新生成。按 Ctrl+C 可取消。

退出码：`0` 成功或全部通过，`1` 文件修改 / 缺失 / 新增，`2` 清单错误 / 读取错误 / 校验未完成，`130` 用户取消。支持 amd64 和 arm64。

两平台共用清单格式，并排除根目录两种平台的标准程序文件名。跨平台传输请使用 Windows 兼容的文件名；Linux 区分大小写，Windows 不接受仅大小写不同的重复清单路径。

## 注意

- 自动排除程序自身、根目录清单、报告及 `.folderverify-` 前缀的临时文件。
- 不跟随符号链接、Junction 或其他重解析点（包括部分云盘占位文件），遇到时报告错误。
- 扫描失败或任务取消时，结论为“校验未完成”；文件被占用时可关闭占用程序后重试。
- **哈希只能判断文件与清单是否一致，不能防止两者同时被恶意修改。**

## 编译

目标平台：Windows 10 / 11 amd64，以及 Linux amd64 / arm64。开发环境需要 Go 1.23 或更新版本。

```powershell
.\build-windows.ps1
```

也可双击 `build-windows.bat`。脚本执行测试并生成 `FolderVerify.exe`，随后启动真实 EXE 验证 GUI 流程。手动编译：

```powershell
$env:CGO_ENABLED = '0'
go test ./...
go build -trimpath -ldflags="-s -w -H windowsgui" -o FolderVerify.exe .
```

Linux 上运行 `sh build-linux.sh`（arm64 可设置 `GOARCH=arm64`）。Windows 上交叉编译：

```powershell
.\build-linux.ps1
.\build-linux.ps1 -Architecture arm64
```

## 源码与测试

- `internal/verify`：流式 SHA-512、安全扫描、清单生成与校验、报告导出。
- `internal/gui`：Win32 原生界面、后台任务及虚拟结果列表。
- `internal/cli`：Linux 命令行交互、报告、取消和退出码。

测试覆盖生成、通过、修改、删除、新增、目录迁移、损坏清单、空文件、读取失败、清单保持不变、路径穿越、Junction、取消、文件变化与真实 EXE 流程。普通符号链接测试需开发者模式或相应权限；大文件与大批量文件性能需在目标硬件验收。

Linux 使用目录句柄和 `openat(O_NOFOLLOW)` 安全遍历，拒绝符号链接及 FIFO 等特殊文件；使用文件身份、大小、mtime 和 ctime 检测处理期间的变化。Linux 专项测试覆盖权限失败、符号链接、目录替换、真实二进制及 SIGINT 取消。运行真实二进制测试前设置 `FOLDERVERIFY_TEST_EXE` 为其绝对路径，再执行 `go test ./internal/cli`。
