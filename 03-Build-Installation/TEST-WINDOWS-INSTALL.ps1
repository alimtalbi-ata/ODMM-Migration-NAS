param([Parameter(Mandatory=$true)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and $env:ODMM_ALLOW_DISPOSABLE_INSTALL_TEST -ne 'YES') { throw 'Installation smoke test requires a disposable runner (GITHUB_ACTIONS=true or ODMM_ALLOW_DISPOSABLE_INSTALL_TEST=YES)' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installer = Join-Path $root "binary/installer/ODMM-Compact-Setup-V$Version.exe"
$target = Join-Path $env:LOCALAPPDATA 'Programs/ODMM Compact'
$exe = Join-Path $target 'ODMM-Compact.exe'
$uninstaller = Join-Path $target 'unins000.exe'
$reportPath = Join-Path $root 'binary/WINDOWS-INSTALL-SMOKE.json'
$report = [ordered]@{ version=$Version; installed=$false; uninstalled=$false; passed=$false; note='Dedicated disposable Windows runner only' }
try {
  if (!(Test-Path $installer)) { throw "Installer missing: $installer" }
  if (Test-Path $target) { throw "Refusing to overwrite an existing installation: $target" }
  $p = Start-Process -FilePath $installer -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-' -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Installer exit code: $($p.ExitCode)" }
  if (!(Test-Path $exe) -or !(Test-Path $uninstaller)) { throw 'Installed executable or uninstaller missing' }
  $report.installed = $true
  $p = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Uninstaller exit code: $($p.ExitCode)" }
  Start-Sleep -Seconds 3
  if (Test-Path $exe) { throw 'Application executable remains after uninstall' }
  $report.uninstalled = $true
  $report.passed = $true
} catch {
  $report.error = $_.Exception.Message
  throw
} finally {
  $report | ConvertTo-Json -Depth 4 | Set-Content -Path $reportPath -Encoding utf8
}
