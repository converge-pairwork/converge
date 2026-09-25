# Installs converge-bridge on Windows: the one executable that connects an AI session to
# CONVERGE. The same shape as install.sh, in the shell Windows has.
#
#   irm https://converge.pairwork.net/agent/install.ps1 | iex
#
# Everything it installs comes from a published release of the public CONVERGE source
# repository, github.com/converge-pairwork/converge: the release manifest names the binary for
# this machine, its byte size and SHA-256 are checked against the manifest, and then the binary
# itself verifies the manifest's signature against the CONVERGE release key it carries
# (`converge-bridge verify-release`). Nothing is installed if any of that fails.
#
# Installs to %LOCALAPPDATA%\CONVERGE\bin, beside the rest of CONVERGE's own state. Nothing is
# run as administrator, and nothing is registered with your AI client: the last lines tell you
# the one command for that.
$ErrorActionPreference = 'Stop'

$Repo = if ($env:CONVERGE_REPO) { $env:CONVERGE_REPO } else { 'converge-pairwork/converge' }
$Version = if ($env:CONVERGE_VERSION) { $env:CONVERGE_VERSION } else { 'latest' }
$Release = if ($env:CONVERGE_RELEASE_BASE) { $env:CONVERGE_RELEASE_BASE }
           elseif ($Version -eq 'latest') { "https://github.com/$Repo/releases/latest/download" }
           else { "https://github.com/$Repo/releases/download/v$Version" }
$Site = if ($env:CONVERGE_BASE) { $env:CONVERGE_BASE } else { 'https://converge.pairwork.net' }
$Local = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE 'AppData\Local' }
$Prefix = if ($env:PREFIX) { $env:PREFIX } else { Join-Path $Local 'CONVERGE\bin' }

$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'x86_64' }
    default { throw "no published CONVERGE bridge for Windows $_; build it from source: https://github.com/$Repo" }
}
$Key = "windows-$arch"

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("converge-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    $manifestPath = Join-Path $Tmp 'manifest.json'
    try { Invoke-WebRequest -Uri "$Release/manifest.json" -OutFile $manifestPath -UseBasicParsing }
    catch { throw "could not fetch the release manifest from $Release; not installing" }
    $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json
    $entry = $manifest.bridge.$Key
    if (-not $entry -or -not ($entry.path -like 'converge-bridge-*')) {
        throw "the release manifest names no bridge for $Key; build it from source: https://github.com/$Repo"
    }
    if ($entry.sha256 -notmatch '^[0-9a-f]{64}$') { throw "the release manifest carries no SHA-256 for $($entry.path); not installing" }

    $binary = Join-Path $Tmp 'converge-bridge.exe'
    Invoke-WebRequest -Uri "$Release/$($entry.path)" -OutFile $binary -UseBasicParsing
    Write-Host "-> downloaded $($entry.path)"
    $size = (Get-Item $binary).Length
    if ($entry.size -and $size -ne [int64]$entry.size) { throw "size mismatch for $($entry.path) (expected $($entry.size) bytes, got $size); not installing" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $binary).Hash.ToLower()
    if ($got -ne $entry.sha256) { throw "checksum mismatch for $($entry.path) (expected $($entry.sha256), got $got); not installing" }
    Write-Host "-> size and sha256 verified against the release manifest"

    # The signature: the bridge carries the CONVERGE release key and the verifier.
    & $binary verify-release --release $Release --file $binary
    if ($LASTEXITCODE -ne 0) { throw "the release manifest signature does not verify against the CONVERGE release key; not installing" }

    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    $target = Join-Path $Prefix 'converge-bridge.exe'
    $staged = Join-Path $Prefix '.converge-bridge.new'
    Copy-Item -Path $binary -Destination $staged -Force
    # A running bridge cannot be overwritten on Windows; it can be renamed aside.
    if (Test-Path $target) { Move-Item -Path $target -Destination (Join-Path $Prefix '.converge-bridge.old') -Force }
    Move-Item -Path $staged -Destination $target -Force

    & $target --help *> $null
    if ($LASTEXITCODE -ne 0) { throw "the installed binary does not run" }
    Write-Host ""
    Write-Host "installed: $target"
    Write-Host ""
    Write-Host "Next, from the AI session you want to connect (Claude Code or Codex):"
    Write-Host ""
    Write-Host "  & `"$target`" setup --client claude"
    Write-Host ""
    Write-Host "It installs the skill, registers the MCP server, and prints what to do next."
    Write-Host "Full walkthrough: $Site/agent/setup.md"
    Write-Host "Source, licence and releases: https://github.com/$Repo"
} finally {
    Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
}
