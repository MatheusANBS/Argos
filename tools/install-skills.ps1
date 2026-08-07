param(
    [string]$Target = $(if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME "skills" } else { Join-Path $HOME ".codex\skills" })
)
$ErrorActionPreference = "Stop"
$Source = Join-Path (Split-Path -Parent $PSScriptRoot) ".codex\skills"
New-Item -ItemType Directory -Force -Path $Target | Out-Null
Get-ChildItem -Path $Source -Directory | ForEach-Object {
    $Destination = Join-Path $Target $_.Name
    if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
    Copy-Item -Recurse -Force $_.FullName $Destination
    Write-Host "installed $($_.Name)"
}
