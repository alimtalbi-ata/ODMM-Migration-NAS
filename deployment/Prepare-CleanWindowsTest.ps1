# Prepare an offline Windows Sandbox with distributables only.
param(
 [Parameter(Mandatory=$true)][string]$Distribution,
 [Parameter(Mandatory=$true)][string]$Executable,
 [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Run preparation on Windows.' }
$source=(Resolve-Path -LiteralPath $Distribution).Path
if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Distribution must be an extracted portable directory.' }
if ([IO.Path]::IsPathRooted($Executable) -or $Executable -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::GetExtension($Executable) -ne '.exe') { throw 'Executable must be a relative EXE path inside the distribution.' }
$entry=Join-Path $source $Executable
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { throw "Missing executable: $entry" }
# Fail before copying: never expose a checkout, a virtual environment or linked files.
$items=@(Get-ChildItem -LiteralPath $source -Recurse -Force)
if (@($items | Where-Object {
 ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
 $_.Name -in @('.git','.venv','.venv-build','.build-venv','__pycache__') -or
 (-not $_.PSIsContainer -and $_.Extension -in @('.py','.pyw','.spec','.cs','.csproj','.sln'))
}).Count) { throw 'Distribution contains development files or links. Select only the built portable files.' }
$destination=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'OutputDirectory must be new; existing files are preserved.' }
if ($destination.StartsWith($source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'OutputDirectory must be outside Distribution.' }
New-Item -ItemType Directory -Path $destination | Out-Null
$payload=Join-Path $destination 'payload'
$reports=Join-Path $destination 'reports'
New-Item -ItemType Directory -Path $payload,$reports | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $payload 'app') -Recurse
@{executable=$Executable} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $payload 'test.json') -Encoding UTF8
Get-ChildItem -LiteralPath (Join-Path $payload 'app') -File -Recurse | ForEach-Object {
 [ordered]@{path=$_.FullName.Substring((Join-Path $payload 'app').Length+1);sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $reports 'payload-sha256.json') -Encoding UTF8
$run=@'
$ErrorActionPreference='Stop'
$report=[ordered]@{status='FAILED';passed=$false;network='disabled';source_checkout_mapped=$false;python_required=$null;utc=(Get-Date).ToUniversalTime().ToString('o')}
try {
 # The VM only receives payload and reports. No checkout or host Python is mapped.
 $env:PATH="$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
 foreach ($name in @('PYTHONHOME','PYTHONPATH','VIRTUAL_ENV','DOTNET_ROOT','DOTNET_ROOT_X64','QT_PLUGIN_PATH','QT_QPA_PLATFORM_PLUGIN_PATH','QML2_IMPORT_PATH')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
 $work='C:\Test application'
 New-Item -ItemType Directory -Path $work | Out-Null
 Copy-Item -LiteralPath 'C:\DeliveryPayload\app' -Destination (Join-Path $work 'app') -Recurse
 $config=Get-Content -LiteralPath 'C:\DeliveryPayload\test.json' -Raw | ConvertFrom-Json
 $exe=Join-Path (Join-Path $work 'app') $config.executable
 $report.executable=$config.executable
 $report.sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
 # Read-only distribution input; execute the copy using a different working directory.
 $process=Start-Process -FilePath $exe -WorkingDirectory $work -PassThru
 $report.process_id=$process.Id
 $report.status='MANUAL_VALIDATION_REQUIRED'
 $report.note='Process creation alone does not validate the GUI or application functions.'
 $report | ConvertTo-Json | Set-Content -LiteralPath 'C:\DeliveryReports\startup.json' -Encoding UTF8
 Write-Host 'Test the application in this VM. Network is disabled and the repository is inaccessible.'
 Write-Host 'Record launch, a real operation, persistence after restart, and any missing dependencies in C:\DeliveryReports.'
 Write-Host 'No PASS is claimed automatically. For an installer, finish installation and launch the installed application.'
 Read-Host 'Press Enter after recording the results; keep Sandbox open until testing is complete'
} catch {
 $report.error=$_.Exception.Message
 $report | ConvertTo-Json | Set-Content -LiteralPath 'C:\DeliveryReports\startup.json' -Encoding UTF8
 Write-Host $_
 Read-Host 'Failed. Press Enter to finish'
 exit 1
}
'@
$run | Set-Content -LiteralPath (Join-Path $payload 'Run.ps1') -Encoding UTF8
$p=[Security.SecurityElement]::Escape($payload)
$r=[Security.SecurityElement]::Escape($reports)
@"
<Configuration>
 <Networking>Disable</Networking>
 <ClipboardRedirection>Disable</ClipboardRedirection>
 <MappedFolders>
  <MappedFolder><HostFolder>$p</HostFolder><SandboxFolder>C:\DeliveryPayload</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
  <MappedFolder><HostFolder>$r</HostFolder><SandboxFolder>C:\DeliveryReports</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
 </MappedFolders>
 <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DeliveryPayload\Run.ps1</Command></LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath (Join-Path $destination 'Test-Clean-Windows.wsb') -Encoding UTF8
Write-Host "Prepared, NOT qualified: $destination\Test-Clean-Windows.wsb"
Write-Host 'Open the WSB on Windows with Windows Sandbox enabled. Only reports are writable on the host.'
