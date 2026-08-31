# Bootstrap for the TrustGuard GitHub Copilot plugin (Windows).
#
# Mirror of trustguard-hook.sh: prefers a PATH-installed trustguard-copilot,
# otherwise installs the pinned release for this arch into
# %USERPROFILE%\.trustguard\bin in the background, verifying its SHA-256
# against the table below. Every bootstrap failure fails open.

param(
    [string]$Event = '',
    [switch]$InstallOnly
)

$Version = '0.1.0'

$Sha256 = @{
    'amd64' = '38f35dd1fcc1167b8e062a0408c3f52f09728cfcc12d09ad82952be0ead36949'
    'arm64' = '3a35a476e3f628fafd8bdd6f4b49a327db5bd2c2e4bab1a09c60d1e2911e7858'
}

function Invoke-Hook([string]$Exe) {
    # Inherit stdin directly: Copilot may keep the pipe open after one JSON
    # value, so ReadToEnd would hang until the hook timeout.
    & $Exe hook $Event
    if ($LASTEXITCODE -ne 0) {
        Exit-FailOpen "hook process failed with exit code $LASTEXITCODE"
    }
    exit 0
}

function Exit-FailOpen([string]$Message) {
    [Console]::Error.WriteLine("trustguard-copilot bootstrap: $Message - allowing without evaluation")
    Write-Output '{}'
    exit 0
}

function Install-Binary([string]$Url, [string]$Target, [string]$WantSha) {
    $tmp = "$Target.download.$PID"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $tmp -TimeoutSec 300
        $gotSha = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLowerInvariant()
        if ($gotSha -ne $WantSha.ToLowerInvariant()) { throw "checksum mismatch (got $gotSha, want $WantSha)" }
        Move-Item -Force $tmp $Target
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $tmp
        [Console]::Error.WriteLine("trustguard-copilot bootstrap: install failed: $($_.Exception.Message)")
    }
}

try {
    # MDM / ProgramData first — org binary must win over any developer PATH copy.
    $programData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
    $mdmBin = Join-Path $programData 'TrustGuard\bin\trustguard-copilot.exe'
    if ((Test-Path $mdmBin) -and -not $InstallOnly) { Invoke-Hook $mdmBin }

    $onPath = Get-Command 'trustguard-copilot' -ErrorAction SilentlyContinue
    if ($onPath -and -not $InstallOnly) { Invoke-Hook $onPath.Source }

    $binDir = if ($env:TRUSTGUARD_COPILOT_BIN_DIR) { $env:TRUSTGUARD_COPILOT_BIN_DIR } else { Join-Path $env:USERPROFILE '.trustguard\bin' }
    $baseUrl = if ($env:TRUSTGUARD_COPILOT_DOWNLOAD_BASE) { $env:TRUSTGUARD_COPILOT_DOWNLOAD_BASE } else { 'https://github.com/NeuralTrust/trustguard-copilot-plugin/releases/download' }

    $localBin = Join-Path $binDir 'trustguard-copilot.exe'
    if ((Test-Path $localBin) -and -not $InstallOnly) { Invoke-Hook $localBin }

    $bin = Join-Path $binDir "trustguard-copilot-$Version.exe"
    if ((Test-Path $bin) -and -not $InstallOnly) { Invoke-Hook $bin }

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { Exit-FailOpen "unsupported arch $($env:PROCESSOR_ARCHITECTURE); install trustguard-copilot manually" }
    }
    $wantSha = $Sha256[$arch]
    if (-not $wantSha) {
        Exit-FailOpen "no pinned checksum for windows/$arch (release $Version not published yet?); install trustguard-copilot manually"
    }

    $url = "$baseUrl/v$Version/trustguard-copilot_${Version}_windows_$arch.exe"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $lock = Join-Path $binDir "install-copilot-$Version.lock"

    if ($InstallOnly) {
        Install-Binary $url $bin $wantSha
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue $lock
        exit 0
    }

    if ((Test-Path $lock) -and ((Get-Item $lock).CreationTime -lt (Get-Date).AddMinutes(-10))) {
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue $lock
    }
    if (-not (Test-Path $lock)) {
        New-Item -ItemType Directory -Path $lock -ErrorAction SilentlyContinue | Out-Null
        Start-Process -FilePath 'powershell' -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InstallOnly'
        )
    }
    Exit-FailOpen "trustguard-copilot $Version not installed yet; fetching it in the background"
} catch {
    Exit-FailOpen "unexpected error: $($_.Exception.Message)"
}
