param([ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')][string]$Version = 'v1.0.0')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$previousTestEXE = $env:FOLDERVERIFY_TEST_EXE
$hostOS = go env GOHOSTOS
$hostArchitecture = go env GOHOSTARCH
$outputDirectory = Join-Path $PSScriptRoot "dist/$Version"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$targets = @(
    @{ OS='windows'; Architecture='amd64'; Label='x64'; Extension='.exe'; Machine=0x8664 },
    @{ OS='windows'; Architecture='arm64'; Label='arm64'; Extension='.exe'; Machine=0xaa64 },
    @{ OS='linux'; Architecture='amd64'; Label='x64'; Extension=''; Machine=62 },
    @{ OS='linux'; Architecture='arm64'; Label='arm64'; Extension=''; Machine=183 }
)
try {
    $env:GOOS = $hostOS
    $env:GOARCH = $hostArchitecture
    $env:CGO_ENABLED = '0'
    $env:FOLDERVERIFY_TEST_EXE = $null
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Native tests failed' }
    $artifacts = @()
    foreach ($target in $targets) {
        $env:GOOS = $target.OS
        $env:GOARCH = $target.Architecture
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "Vet failed: $($target.OS)/$($target.Architecture)" }
        $artifactPath = Join-Path $outputDirectory "FolderVerify-$($target.OS)-$($target.Label)$($target.Extension)"
        $flags = '-s -w'
        if ($target.OS -eq 'windows') { $flags += ' -H windowsgui' }
        go build -trimpath "-ldflags=$flags" -o $artifactPath .
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $($target.OS)/$($target.Architecture)" }
        $bytes = [IO.File]::ReadAllBytes($artifactPath)
        if ($target.OS -eq 'windows') {
            $peOffset = [BitConverter]::ToInt32($bytes,60)
            if ([BitConverter]::ToUInt32($bytes,$peOffset) -ne 0x00004550 -or [BitConverter]::ToUInt16($bytes,$peOffset+4) -ne $target.Machine) { throw "Wrong PE architecture: $artifactPath" }
            if ([BitConverter]::ToUInt16($bytes,$peOffset+24+68) -ne 2) { throw "Not a GUI subsystem EXE: $artifactPath" }
        } else {
            if ($bytes[0] -ne 0x7f -or $bytes[1] -ne 0x45 -or $bytes[2] -ne 0x4c -or $bytes[3] -ne 0x46 -or $bytes[5] -ne 1 -or [BitConverter]::ToUInt16($bytes,18) -ne $target.Machine) { throw "Wrong ELF architecture: $artifactPath" }
            if ($bytes[4] -ne 2) { throw 'Expected ELF64' }
            $programOffset = [BitConverter]::ToUInt64($bytes,32)
            $entrySize = [BitConverter]::ToUInt16($bytes,54)
            $entryCount = [BitConverter]::ToUInt16($bytes,56)
            for ($index=0; $index -lt $entryCount; $index++) {
                if ([BitConverter]::ToUInt32($bytes,([int]$programOffset+$index*$entrySize)) -eq 3) { throw "Linux binary has an external dynamic loader: $artifactPath" }
            }
        }
        $artifacts += $artifactPath
    }
    if ($hostOS -eq 'windows') {
        foreach ($target in $targets | Where-Object { $_.OS -eq 'windows' -and $_.Architecture -eq $hostArchitecture }) {
            $env:GOOS = $hostOS
            $env:GOARCH = $hostArchitecture
            $env:FOLDERVERIFY_TEST_EXE = Join-Path $outputDirectory "FolderVerify-windows-$($target.Label).exe"
            go test -count=1 ./internal/gui
            if ($LASTEXITCODE -ne 0) { throw "GUI integration failed: $($target.Label)" }
        }
    }
    $checksums = foreach ($artifactPath in $artifacts) {
        $hash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($artifactPath))"
    }
    [IO.File]::WriteAllText((Join-Path $outputDirectory 'SHA256SUMS.txt'),($checksums -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
    Get-ChildItem -LiteralPath $outputDirectory | Select-Object Name,Length
} finally {
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
    $env:FOLDERVERIFY_TEST_EXE = $previousTestEXE
}
