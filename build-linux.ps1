param([ValidateSet('amd64','arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
try {
    $env:GOOS = 'linux'
    $env:GOARCH = $Architecture
    $env:CGO_ENABLED = '0'
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Linux vet failed' }
    go build -trimpath -ldflags='-s -w' -o "FolderVerify-linux-$Architecture" .
    if ($LASTEXITCODE -ne 0) { throw 'Linux build failed' }
    Get-Item -LiteralPath "FolderVerify-linux-$Architecture" | Select-Object FullName, Length
} finally {
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
}
