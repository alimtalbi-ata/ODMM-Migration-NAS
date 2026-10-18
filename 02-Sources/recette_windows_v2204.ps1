# ODMM V220.4 - Windows Chromium acceptance orchestration
# Author: Abdelhalim Talbi
param([Parameter(Mandatory=$true)][string]$Url, [string]$Output = '.\snapshots\v2204')
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = (Get-Command py -ErrorAction SilentlyContinue)
if ($python) { $exe = 'py'; $prefix = @('-3') }
else { $exe = 'python'; $prefix = @() }
& $exe @prefix (Join-Path $base 'recette_navigateur_v2203.py') --url $Url --output $Output
$browserExit = $LASTEXITCODE
& $exe @prefix (Join-Path $base 'qualification_windows_v2204.py') --directory $Output
$reportExit = $LASTEXITCODE
if ($browserExit -ne 0 -or $reportExit -ne 0) { exit 1 }
exit 0
