param([string]$Exe = "binary/portable/ODMM-Compact.exe")
$ErrorActionPreference = "Stop"
$source = (Resolve-Path $Exe).Path
$isolated = Join-Path $env:TEMP ("odmm-standalone-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $isolated | Out-Null
try {
  $target = Join-Path $isolated "ODMM-Compact.exe"
  Copy-Item $source $target
  # No source tree, Python interpreter or build virtualenv is copied.
  $previousPythonHome = $env:PYTHONHOME
  $previousPythonPath = $env:PYTHONPATH
  $env:PYTHONHOME = ""
  $env:PYTHONPATH = ""
  # Execute the real frozen Tk initialization with no source tree present.
  $probe = Start-Process -FilePath $target -ArgumentList '--self-test-tk' -WorkingDirectory $isolated -PassThru
  try {
    if (!$probe.WaitForExit(30000)) { throw 'Isolated Tcl/Tk self-test timed out' }
    if ($probe.ExitCode -ne 0) { throw "Isolated Tcl/Tk self-test failed: $($probe.ExitCode)" }
    Write-Output "PASS: isolated frozen Tcl/Tk initialized"
  } finally {
    if (!$probe.HasExited) { Stop-Process -Id $probe.Id -Force }
  }
  $proc = Start-Process -FilePath $target -WorkingDirectory $isolated -PassThru
  try {
    Start-Sleep -Seconds 12
    $proc.Refresh()
    if ($proc.HasExited) { throw "Standalone executable exited: $($proc.ExitCode)" }
    Write-Output "PASS: portable started from isolated directory without sources"
  } finally {
    if (!$proc.HasExited) { Stop-Process -Id $proc.Id -Force }
  }
} finally {
  $env:PYTHONHOME = $previousPythonHome
  $env:PYTHONPATH = $previousPythonPath
  Remove-Item $isolated -Recurse -Force -ErrorAction SilentlyContinue
}
