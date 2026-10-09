# PortTransit build script for Windows.
#
# The Makefile in the repository root is the canonical build definition, but
# Windows has no make by default and the client's own development happens
# there. This script produces byte-identical artifact names and applies the
# same linker flags, so a release built on Windows is indistinguishable from
# one built on Linux.
#
# Usage:
#   .\scripts\build.ps1                 # build for the host platform
#   .\scripts\build.ps1 -Release        # cross-compile linux/amd64 + linux/arm64
#   .\scripts\build.ps1 -Release -Tarball
#   .\scripts\build.ps1 -Test

[CmdletBinding()]
param(
    # Cross-compile the Linux release artifacts instead of a host build.
    [switch]$Release,
    # Package the release binaries as the tarballs the install script expects.
    [switch]$Tarball,
    # Run the unit tests instead of building.
    [switch]$Test,
    # Run go vet and the gofmt check instead of building.
    [switch]$Lint,
    # Remove build output and stop.
    [switch]$Clean,
    # Override the version stamped into the binary.
    [string]$Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$binary = 'porttransit'
$cmd = './cmd/porttransit'
$dist = 'dist'

# Resolve build identity the same way the Makefile does, so the two entry
# points cannot drift. A missing git is not an error: a source tarball has no
# history and still deserves a version string.
function Get-GitValue {
    param([string[]]$GitArgs, [string]$Fallback)
    try {
        $out = & git @GitArgs 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return ($out | Select-Object -First 1).ToString().Trim() }
    } catch { }
    return $Fallback
}

if (-not $Version) {
    $Version = Get-GitValue -GitArgs @('describe', '--tags', '--always', '--dirty') -Fallback '1.0.0'
}
$commit = Get-GitValue -GitArgs @('rev-parse', '--short', 'HEAD') -Fallback 'dev'
$buildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$ldflags = @(
    '-s', '-w',
    "-X 'porttransit/internal/version.Version=$Version'",
    "-X 'porttransit/internal/version.Commit=$commit'",
    "-X 'porttransit/internal/version.BuildTime=$buildTime'",
    "-X 'porttransit/internal/version.Channel=stable'"
) -join ' '

function Invoke-Step {
    param([string]$Description, [scriptblock]$Action)
    Write-Host "==> $Description" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

if ($Clean) {
    Invoke-Step "cleaning" { Remove-Item -Recurse -Force $dist, "$binary", "$binary.exe", 'coverage.out' -ErrorAction SilentlyContinue; $global:LASTEXITCODE = 0 }
    Write-Host "done" -ForegroundColor Green
    return
}

if ($Test) {
    Invoke-Step "running tests" { go test ./... }
    Write-Host "tests passed" -ForegroundColor Green
    return
}

if ($Lint) {
    $unformatted = @(gofmt -s -l . | Where-Object { $_ -notmatch '^vendor/' })
    if ($unformatted.Count -gt 0) {
        Write-Host "these files are not gofmt'd:" -ForegroundColor Red
        $unformatted | ForEach-Object { Write-Host "  $_" }
        exit 1
    }
    Invoke-Step "go vet" { go vet ./... }
    Write-Host "lint clean" -ForegroundColor Green
    return
}

if ($Release) {
    if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
    New-Item -ItemType Directory -Path $dist | Out-Null

    # Only the two architectures the installer accepts are produced; shipping
    # a third would suggest support that has never been tested.
    $targets = @(
        @{ OS = 'linux'; Arch = 'amd64' },
        @{ OS = 'linux'; Arch = 'arm64' }
    )

    foreach ($t in $targets) {
        $out = Join-Path $dist "$binary-$($t.OS)-$($t.Arch)"
        Invoke-Step "building $($t.OS)/$($t.Arch)" {
            $env:GOOS = $t.OS
            $env:GOARCH = $t.Arch
            $env:CGO_ENABLED = '0'
            go build -trimpath -ldflags $ldflags -o $out $cmd
        }
    }
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

    if ($Tarball) {
        foreach ($t in $targets) {
            $name = "$binary-$Version-$($t.OS)-$($t.Arch)"
            $stage = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Path $stage | Out-Null
            Copy-Item (Join-Path $dist "$binary-$($t.OS)-$($t.Arch)") (Join-Path $stage $binary)
            # Also ship the platform-suffixed name. `deploy` looks for exactly
            # this file beside the running executable when the local build
            # cannot run on the target — so a Windows user who unpacks the
            # Linux tarball next to porttransit.exe can deploy immediately.
            Copy-Item (Join-Path $dist "$binary-$($t.OS)-$($t.Arch)") `
                      (Join-Path $stage "$binary-$($t.OS)-$($t.Arch)")
            Copy-Item 'scripts/install.sh' (Join-Path $stage 'install.sh')
            Copy-Item 'README.md' (Join-Path $stage 'README.md')
            $archive = Join-Path $dist "$name.tar.gz"
            Invoke-Step "packaging $name.tar.gz" { tar -czf $archive -C $stage . }
            # install.sh's `latest/download` path needs a version-less name,
            # because "latest" cannot know the version. Emit both so a release
            # works whether the operator pins a version or not.
            Copy-Item $archive (Join-Path $dist "$binary-$($t.OS)-$($t.Arch).tar.gz")
            Remove-Item -Recurse -Force $stage
        }
    }

    Get-ChildItem $dist | Format-Table Name, Length -AutoSize
    Write-Host "artifacts in $dist\" -ForegroundColor Green
    return
}

# Default: a build for the host platform.
$exe = if ($IsWindows -or $env:OS -eq 'Windows_NT') { "$binary.exe" } else { $binary }
Invoke-Step "building for the host platform" { go build -trimpath -ldflags $ldflags -o $exe $cmd }
Write-Host "built $exe" -ForegroundColor Green
