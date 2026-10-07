# Builds TEAvault and stages the binaries into one directory.
#
# Why this exists: the owner tier is a path comparison. `teavaultd` only grants it
# to `teavault-app.exe` and `teavault.exe` **in its own directory**. Cargo puts the
# Tauri app in `src-tauri/target/` and everything else in `target/`, so running
# straight out of the build tree leaves the UI in agent tier, where it cannot do
# anything at all. Staging them together is what makes a from-source run work.
#
# The unified binary (`teavault.exe`) serves as both CLI and daemon. It dispatches
# based on its own name: `teavaultd.exe` → daemon, `teavault.exe` → CLI. The build
# script copies the same PE file to both names.
#
#   .\scripts\build-local.ps1              debug build + stage
#   .\scripts\build-local.ps1 -Release     release build + stage
#
# Afterwards:
#   .\dist\teavaultd.exe        in one window, leave it running
#   .\dist\teavault init        in another, an interactive terminal
#   .\dist\teavault-app.exe     the UI

[CmdletBinding()]
param(
    [switch]$Release
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Windows PowerShell 5.1 raises on a native command writing to stderr, and cargo
# writes its "Finished" line there. The exit code is the real signal, so
# `ErrorActionPreference` is relaxed around each cargo call and the code checked
# explicitly.
function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]   $Exe,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string]   $What
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

function Invoke-Npm {
    param([Parameter(Mandatory)] [string[]] $Arguments, [string] $What)
    Push-Location (Join-Path $root 'ui')
    try {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & npm @Arguments | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
        }
        finally { $ErrorActionPreference = $previous }
    }
    finally { Pop-Location }
}

Push-Location $root
try {
    $profile = if ($Release) { 'release' } else { 'debug' }
    $stage = Join-Path $root 'dist'

    Write-Host '==> Installing frontend dependencies' -ForegroundColor Cyan
    Invoke-Npm -Arguments @('install') -What 'npm install'

    Write-Host "==> Building the frontend ($profile)" -ForegroundColor Cyan
    Invoke-Npm -Arguments @('run', 'build') -What 'the frontend build'

    Write-Host '==> Building teavault-core, -daemon, -cli (unified binary)' -ForegroundColor Cyan
    Invoke-Checked -Exe 'cargo' -Arguments @('build', "--$profile", '--workspace') `
        -What 'the Rust workspace build'

    Write-Host '==> Building the desktop UI' -ForegroundColor Cyan
    # The Tauri crate sits outside the workspace: it has its own Cargo.lock and
    # build script, so it is built on its own.
    #
    # `--features custom-protocol` is REQUIRED, and its absence is silent and
    # confusing: without it `generate_context!` embeds `build.devUrl`
    # (localhost:5173) instead of `frontendDist`, so the window opens on
    # "localhost refused the connection". `tauri build` passes this feature; a
    # plain `cargo build` does not.
    Invoke-Checked -Exe 'cargo' `
        -Arguments @('build', "--$profile", '--features', 'custom-protocol',
                     '--manifest-path', (Join-Path $root 'src-tauri\Cargo.toml')) `
        -What 'the desktop UI build'

    Write-Host "==> Staging binaries into $stage" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    # A running binary holds its own file open, and the resulting IOException
    # says nothing about why. Say it up front.
    $running = Get-Process -Name 'teavaultd', 'teavault-app', 'teavault' -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host ''
        Write-Host '  A TEAvault process is still running and holds its file open:' -ForegroundColor Yellow
        $running | ForEach-Object { Write-Host "      $($_.Name)  (PID $($_.Id))" -ForegroundColor DarkGray }
        Write-Host '  Quit it from the tray, then re-run. Or:' -ForegroundColor Yellow
        Write-Host '      Stop-Process -Name teavaultd,teavault-app' -ForegroundColor DarkGray
        throw 'cannot stage while TEAvault is running'
    }

    # The unified binary: teavault.exe runs as CLI, teavaultd.exe runs as daemon.
    # They are the same PE file — dispatched by checking `current_exe()` at runtime.
    $unifiedSrc = "target\$profile\teavault.exe"
    if (-not (Test-Path $unifiedSrc)) { throw "not built: $unifiedSrc" }
    Copy-Item -Force $unifiedSrc (Join-Path $stage 'teavault.exe')
    Write-Host "    teavault.exe    (also teavaultd.exe — unified binary)" -ForegroundColor DarkGray

    Copy-Item -Force (Join-Path $stage 'teavault.exe') (Join-Path $stage 'teavaultd.exe')
    Write-Host "    teavaultd.exe" -ForegroundColor DarkGray

    $tauriSrc = "src-tauri\target\$profile\teavault-app.exe"
    if (-not (Test-Path $tauriSrc)) { throw "not built: $tauriSrc" }
    Copy-Item -Force $tauriSrc (Join-Path $stage 'teavault-app.exe')
    Write-Host "    teavault-app.exe" -ForegroundColor DarkGray

    Write-Host ''
    Write-Host 'Done. Next:' -ForegroundColor Green
    Write-Host '  1. .\dist\teavaultd.exe       # leave running (daemon mode)'
    Write-Host '  2. .\dist\teavault init       # an interactive terminal (CLI mode)'
    Write-Host '  3. .\dist\teavault-app.exe    # the UI'
    Write-Host ''
    Write-Host 'The binary is unified: teavaultd.exe → daemon, teavault.exe → CLI.' -ForegroundColor DarkGray
    Write-Host 'Day to day, use the tray icon: Open, Lock now, Recent requests, Settings, Quit.' -ForegroundColor DarkGray
}
finally {
    Pop-Location
}