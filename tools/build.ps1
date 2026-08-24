#Requires -Version 5.1
<#
.SYNOPSIS
Configure, build and test Argos with the MSVC environment already set up.

.DESCRIPTION
On Windows the project builds with MSVC + Ninja, and ninja tracks header
dependencies by parsing cl.exe's localized /showIncludes output. CMake probes
that prefix from the compiler at configure time, so a build directory
configured without cl.exe on PATH ends up with the wrong prefix and silently
stops rebuilding on header changes -- which shows up much later as a stale
object linked against a changed ABI.

This script imports the vcvars64 environment before touching CMake, then
verifies that the prefix recorded in the build directory still matches what the
compiler actually prints. On a mismatch it reconfigures from scratch instead of
producing a build that cannot be trusted.

.EXAMPLE
tools\build.ps1
Configure, build and test the dev preset.

.EXAMPLE
tools\build.ps1 -Preset release -NoTest
Build the release preset without running ctest.
#>
[CmdletBinding()]
param(
    [ValidateSet('dev', 'release', 'asan', 'tsan')]
    [string]$Preset = 'dev',

    [switch]$NoTest,

    # Copy the built server to install\bin. The MCP client runs from there, not
    # from the build tree, so a rebuild never fights a running server for the
    # same file.
    [switch]$Install,

    # Delete the build directory before configuring.
    [switch]$Clean,

    # Show the raw compiler output instead of filtering /showIncludes noise.
    [switch]$Verbose_Output
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repoRoot "build\$Preset"

function Find-VcVars {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installation = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($installation) {
            $candidate = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    # vswhere is missing on some Build Tools-only installs; fall back to the
    # conventional locations rather than giving up.
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'),
        (Join-Path $env:ProgramFiles 'Microsoft Visual Studio')
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $found = Get-ChildItem -Path $root -Filter 'vcvars64.bat' -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Import-VcEnvironment {
    param([string]$VcVarsPath)
    # Running the batch file in a child cmd and importing its environment is the
    # only supported way to get the MSVC variables into this process.
    cmd /c "`"$VcVarsPath`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -Path "env:$($matches[1])" -Value $matches[2]
        }
    }
}

function Get-ShowIncludesPrefix {
    # Ask the compiler directly instead of trusting a cached value.
    $probeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("argos-probe-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
    try {
        $source = Join-Path $probeDir 'probe.cpp'
        Set-Content -Path $source -Value '#include <cstddef>' -Encoding ascii
        Push-Location $probeDir
        try {
            $output = & cl.exe /nologo /showIncludes /c probe.cpp 2>&1
        } finally {
            Pop-Location
        }
        foreach ($line in $output) {
            $text = [string]$line
            # "<localized prefix>: <absolute path>"; the last colon before a
            # drive-qualified path ends the prefix.
            if ($text -match '^(?<prefix>.*:)\s+[A-Za-z]:\\') {
                return $matches['prefix']
            }
        }
        return $null
    } finally {
        Remove-Item -Recurse -Force $probeDir -ErrorAction SilentlyContinue
    }
}

function Get-ConfiguredPrefix {
    $rules = Join-Path $buildDir 'CMakeFiles\rules.ninja'
    if (-not (Test-Path $rules)) { return $null }
    # rules.ninja is UTF-8 even under Windows PowerShell 5.1. Reading it with
    # the active ANSI code page corrupts a localized prefix (for example,
    # "Observação") and creates a false mismatch against cl.exe's output.
    $match = Get-Content -Path $rules -Encoding UTF8 |
        Select-String -Pattern '^msvc_deps_prefix\s*=\s*(.*)$' |
        Select-Object -First 1
    if (-not $match) { return $null }
    $prefix = $match.Matches[0].Groups[1].Value.Trim()
    # CMake captures cl.exe through the native OEM code page, then writes the
    # resulting text to this UTF-8 file. Reverse that one mojibake round-trip
    # before comparing it with PowerShell's decoded compiler output.
    $oem = [System.Text.Encoding]::GetEncoding([Console]::InputEncoding.CodePage)
    $normalized = [System.Text.Encoding]::UTF8.GetString($oem.GetBytes($prefix))
    if (-not $normalized.Contains([char]0xFFFD)) {
        return $normalized
    }
    return $prefix
}

$vcvars = Find-VcVars
if (-not $vcvars) {
    throw "Could not find vcvars64.bat. Install the MSVC C++ build tools, or run this from a Developer Command Prompt."
}
Write-Host "Using $vcvars"
Import-VcEnvironment -VcVarsPath $vcvars

$probedPrefix = Get-ShowIncludesPrefix
if (-not $probedPrefix) {
    throw "cl.exe did not report a /showIncludes prefix. The MSVC environment is not usable."
}

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Removing $buildDir"
    Remove-Item -Recurse -Force $buildDir
}

$configuredPrefix = Get-ConfiguredPrefix
if ($configuredPrefix -and $configuredPrefix -ne $probedPrefix.Trim()) {
    # A build directory carrying the wrong prefix cannot be repaired by
    # reconfiguring in place: the value lives in the compiler cache.
    Write-Warning "Build directory records '$configuredPrefix' but the compiler prints '$($probedPrefix.Trim())'."
    Write-Warning "Header dependency tracking would be broken; reconfiguring from scratch."
    Remove-Item -Recurse -Force $buildDir
}

Push-Location $repoRoot
try {
    cmake --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "cmake --preset $Preset failed" }

    $configuredPrefix = Get-ConfiguredPrefix
    if ($configuredPrefix -ne $probedPrefix.Trim()) {
        throw "Configure produced msvc_deps_prefix '$configuredPrefix' but the compiler prints '$($probedPrefix.Trim())'."
    }

    $buildOutput = cmake --build --preset $Preset 2>&1
    $buildExit = $LASTEXITCODE
    foreach ($line in $buildOutput) {
        $text = [string]$line
        if (-not $Verbose_Output -and $text.StartsWith($probedPrefix)) { continue }
        Write-Host $text
    }
    if ($buildExit -ne 0) {
        if ($buildOutput -match 'LNK1104') {
            # The MCP server runs straight out of the build tree, so a live
            # server holds the very file the linker is trying to write.
            $running = Get-Process -Name argos_runtime_memory_mcp -ErrorAction SilentlyContinue
            if ($running) {
                Write-Warning "argos_runtime_memory_mcp.exe is running (PID $($running.Id -join ', ')) from:"
                $running | ForEach-Object { Write-Warning "  $($_.Path)" }
                Write-Warning "Stop the MCP server, or install to a stable path and point .mcp.json at it, then rebuild."
            }
        }
        throw "cmake --build --preset $Preset failed"
    }

    if (-not $NoTest) {
        if ($Preset -eq 'release' -or $Preset -eq 'tsan') {
            ctest --test-dir $buildDir --output-on-failure
        } else {
            ctest --preset $Preset
        }
        if ($LASTEXITCODE -ne 0) { throw "ctest failed for preset $Preset" }
    }

    if ($Install) {
        $prefix = Join-Path $repoRoot 'install'
        $running = Get-Process -Name argos_runtime_memory_mcp -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) }
        if ($running) {
            Write-Warning "The installed server is running (PID $($running.Id -join ', ')); stop the MCP client before installing."
            throw "install target is in use"
        }
        cmake --install $buildDir --prefix $prefix
        if ($LASTEXITCODE -ne 0) { throw "cmake --install failed" }
        Write-Host "Installed to $prefix\bin"
    }
} finally {
    Pop-Location
}

Write-Host "OK: preset '$Preset' built$(if ($NoTest) { '' } else { ' and tested' })."
