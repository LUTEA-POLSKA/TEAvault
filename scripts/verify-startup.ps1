#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Starts the staged daemon and UI, then reports what actually came up.

.DESCRIPTION
    The UI cannot be verified by watching for "no crash" — a Tauri app whose web
    view never initialised also stays alive and prints nothing. This asks Windows
    directly whether the process owns a visible top-level window, which is the
    difference between "it started" and "it rendered".

    It also checks the thing that silently breaks a from-source run: whether the
    UI is in the same directory as the daemon, which is what the owner tier
    requires.

.PARAMETER VaultHome
    Use a scratch vault so this never touches a real one.

.EXAMPLE
    .\scripts\verify-startup.ps1
#>
[CmdletBinding()]
param(
    [string]$VaultHome = "$env:TEMP\teavault-verify"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $root 'dist'

Add-Type -Namespace Win32 -Name Windows -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
public delegate bool EnumWindowsProc(IntPtr h, IntPtr p);
'@

function Get-WindowsFor([int]$ProcessId) {
    # A List, not `+=`: the EnumWindows callback runs in a child scope, so `+=`
    # would mutate a copy and the result would always come back empty. That bug
    # made this script report "no window" for an app that had one.
    $found = New-Object 'System.Collections.Generic.List[object]'
    $cb = [Win32.Windows+EnumWindowsProc] {
        param($h, $p)
        $windowPid = 0
        [void][Win32.Windows]::GetWindowThreadProcessId($h, [ref]$windowPid)
        if ($windowPid -eq $ProcessId) {
            $sb = New-Object System.Text.StringBuilder 256
            [void][Win32.Windows]::GetWindowTextW($h, $sb, 256)
            $found.Add([pscustomobject]@{
                Handle  = $h
                Title   = $sb.ToString()
                Visible = [Win32.Windows]::IsWindowVisible($h)
            })
        }
        return $true
    }
    [void][Win32.Windows]::EnumWindows($cb, [IntPtr]::Zero)
    return $found.ToArray()
}

Write-Host '== Layout ==' -ForegroundColor Cyan
foreach ($n in 'teavaultd.exe', 'teavault.exe', 'teavault-app.exe') {
    $exists = Test-Path (Join-Path $stage $n)
    Write-Host ("  {0,-18} {1}" -f $n, $(if ($exists) { 'present' } else { 'MISSING' }))
}
$sameDir = ((Get-Item (Join-Path $stage 'teavaultd.exe')).DirectoryName -eq
           (Get-Item (Join-Path $stage 'teavault-app.exe')).DirectoryName)
Write-Host ("  UI and daemon in the same directory: {0}" -f $sameDir) `
    -ForegroundColor $(if ($sameDir) { 'Green' } else { 'Red' })
if (-not $sameDir) { Write-Host '  -> the UI would be agent tier and could do nothing.' -ForegroundColor Red }

if (Test-Path $VaultHome) { Remove-Item -Recurse -Force $VaultHome }
New-Item -ItemType Directory -Force -Path $VaultHome | Out-Null
$env:TEAVAULT_HOME = $VaultHome
Write-Host "  scratch vault: $VaultHome"

Write-Host ''
Write-Host '== Starting the daemon ==' -ForegroundColor Cyan
$daemonOut = Join-Path $env:TEMP 'tv-verify-daemon.out'
$daemon = Start-Process -FilePath (Join-Path $stage 'teavaultd.exe') -PassThru -NoNewWindow `
    -RedirectStandardOutput $daemonOut -RedirectStandardError "$daemonOut.err"
Start-Sleep -Seconds 3

if ($daemon.HasExited) {
    Write-Host "  the daemon exited immediately (code $($daemon.ExitCode))" -ForegroundColor Red
    Get-Content $daemonOut, "$daemonOut.err" -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "  running, PID $($daemon.Id)" -ForegroundColor Green
Get-Content $daemonOut -ErrorAction SilentlyContinue | ForEach-Object { "    $_" }

Write-Host ''
Write-Host '== Starting the UI ==' -ForegroundColor Cyan

# The failure this catches: a Tauri app built without `--features
# custom-protocol` embeds `build.devUrl` (localhost:5173) instead of
# `frontendDist`, and opens on "localhost refused the connection" with a window
# that otherwise looks perfectly healthy. Nothing crashes, so nothing else in
# this script would notice.
#
# So: occupy port 5173 with a listener and see whether the UI reaches for it.
$probe = New-Object System.Net.HttpListener
$probe.Prefixes.Add('http://localhost:5173/')
$probeFailed = $false
try {
    $probe.Start()
}
catch {
    # Something already holds it — which is itself informative.
    $probeFailed = $true
}

if ($probeFailed) {
    Write-Host '  port 5173 is already in use; cannot prove which mode the UI uses.' -ForegroundColor Yellow
}
else {
    Write-Host '  (port 5173 occupied to detect a dev-server build)' -ForegroundColor DarkGray
}

$uiOut = Join-Path $env:TEMP 'tv-verify-ui.out'
$ui = Start-Process -FilePath (Join-Path $stage 'teavault-app.exe') -PassThru -NoNewWindow `
    -RedirectStandardOutput $uiOut -RedirectStandardError "$uiOut.err"
Start-Sleep -Seconds 8

if (-not $probeFailed) {
    $toPort = @(Get-NetTCPConnection -RemotePort 5173 -ErrorAction SilentlyContinue)
    if ($toPort.Count -gt 0) {
        Write-Host ''
        Write-Host '  FAILED: the UI tried to load http://localhost:5173' -ForegroundColor Red
        Write-Host '  That means the frontend is NOT embedded. Rebuild with:' -ForegroundColor Red
        Write-Host '      .\scripts\build-local.ps1 -Release' -ForegroundColor Red
        Write-Host '  The build must pass --features custom-protocol to cargo.' -ForegroundColor Red
    }
    else {
        Write-Host '  serving the embedded frontend (no dev-server request) - correct' -ForegroundColor Green
    }
    $probe.Stop()
}

if ($ui.HasExited) {
    Write-Host "  the UI exited immediately (code $($ui.ExitCode))" -ForegroundColor Red
    Get-Content $uiOut, "$uiOut.err" -ErrorAction SilentlyContinue
    Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "  running, PID $($ui.Id)" -ForegroundColor Green

$stderr = Get-Content "$uiOut.err" -ErrorAction SilentlyContinue
if ($stderr) {
    Write-Host '  stderr:' -ForegroundColor Yellow
    $stderr | Select-Object -First 10 | ForEach-Object { "    $_" }
}

Write-Host ''
Write-Host '== Windows owned by the UI ==' -ForegroundColor Cyan
$wins = @(Get-WindowsFor $ui.Id)
if ($wins.Count -eq 0) {
    Write-Host '  none - the web view never created a window' -ForegroundColor Red
} else {
    foreach ($w in $wins) {
        Write-Host ("    visible={0,-5} title='{1}'" -f $w.Visible, $w.Title) -ForegroundColor Green
    }
}

Write-Host ''
Write-Host '== Is the CLI reaching the daemon? ==' -ForegroundColor Cyan
& (Join-Path $stage 'teavault.exe') status
Write-Host ''
Write-Host '== Recent audit log ==' -ForegroundColor DarkGray
$audit = Join-Path $VaultHome 'audit.log'
if (Test-Path $audit) { Get-Content $audit | Select-Object -Last 3 | ForEach-Object { "    $_" } }
else { Write-Host '    (none yet)' -ForegroundColor DarkGray }

Write-Host ''
Write-Host '== Cleaning up ==' -ForegroundColor Cyan
Stop-Process -Id $ui.Id, $daemon.Id -Force -ErrorAction SilentlyContinue
Write-Host '  stopped.'