# Fails if a Windows build of peach.exe imports the Visual C++ runtime DLLs.
#
# Windows builds link the C runtime statically (`+crt-static`, set via
# CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS in the workflows), so the
# binary starts on a machine without the Visual C++ Redistributable installed
# — e.g. a clean analysis VM, or winget's validation sandbox. Without the flag
# the bundled DuckDB/SQLite C/C++ builds pull in VCRUNTIME140*.dll and
# MSVCP140.dll and the exe fails at load time with STATUS_DLL_NOT_FOUND. This
# check makes a regression fail CI instead of failing on the user's machine.
#
# Usage: check_windows_runtime_deps.ps1 <path\to\peach.exe>

param(
    [Parameter(Mandatory = $true)]
    [string]$Exe
)

$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw 'No Visual Studio installation with the MSVC toolset found'
}
$dumpbin = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe') |
    Select-Object -First 1
if (-not $dumpbin) {
    throw "dumpbin.exe not found under $vsPath"
}

$output = & $dumpbin.FullName /nologo /dependents $Exe
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin failed with exit code $LASTEXITCODE"
}
$dlls = $output | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '\.dll$' }

Write-Host "DLLs imported by ${Exe}:"
$dlls | ForEach-Object { Write-Host "  $_" }

$forbidden = $dlls | Where-Object { $_ -match '^(vcruntime|msvcp|api-ms-win-crt-|ucrtbase)' }
if ($forbidden) {
    Write-Error ("$Exe depends on the dynamic C runtime, which is not present on " +
        "Windows without the Visual C++ Redistributable: $($forbidden -join ', ')")
    exit 1
}

Write-Host 'OK: no dynamic C runtime dependency.'
