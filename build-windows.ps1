param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
if (-not $SkipTests) {
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
}
go build -trimpath -ldflags='-s -w -H windowsgui' -o FolderVerify.exe .
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
if (-not $SkipTests) {
    $env:FOLDERVERIFY_TEST_EXE = Join-Path $PSScriptRoot 'FolderVerify.exe'
    try {
        go test -count=1 ./internal/gui
        if ($LASTEXITCODE -ne 0) { throw 'Native EXE integration test failed' }
    } finally { Remove-Item Env:FOLDERVERIFY_TEST_EXE -ErrorAction SilentlyContinue }
}
Get-Item -LiteralPath (Join-Path $PSScriptRoot 'FolderVerify.exe') | Select-Object FullName, Length
