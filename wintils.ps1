#requires -Version 5.0
<#
WinTils Installer + Local Web Server (robust)
- Download with retries/progress, ZIP validation/extract
- Webroot detection, mirroring to %APPDATA%\WinTils
- Local server with:
  - Default “/” serving nested index if needed
  - SPA fallback for client routes
  - Asset fallback to the SPA directory for absolute/relative paths
  - Runtime <base href="/"> injection into all HTML served
  - Strong Ctrl+C handling (visible message, clean exit 0)
- Write-Host color logging; logs to %APPDATA%\WinTils\logs
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Configuration
$AppName              = 'WinTils'
$InstallRoot          = Join-Path $env:APPDATA $AppName
$DownloadUrl          = 'https://github.com/KrexonTX/WinTils/raw/refs/heads/Alpha/demo/demo.zip'
$ExpectedSHA256       = $null
$TempDir              = Join-Path ([IO.Path]::GetTempPath()) "$AppName-Install"
$ZipPath              = Join-Path $TempDir 'package.zip'
$BackupRoot           = Join-Path $InstallRoot '_backups'
$LogDir               = Join-Path $InstallRoot 'logs'
$LogPath              = Join-Path $LogDir ("install_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$MinDiskMB            = 100
$ServerPort           = 8993
$DefaultIndexNames    = @('index.html','index.htm')
$CommonWebDirs        = @('dist','build','public','wwwroot','site','app')
$DownloadTimeoutSec   = 120
$MaxRetries           = 3
$BaseBackoffSec       = 2
$DebugVerbose         = $true
$InternalManagedDirs  = @('_backups','logs')
#endregion

#region Error normalization
function Get-ErrorMessage {
  param([Parameter(ValueFromPipeline,Mandatory)] $ErrorRecord)
  process {
    try {
      if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $m = $ErrorRecord.Exception.Message
        if ([string]::IsNullOrWhiteSpace($m)) { $m = $ErrorRecord.ToString() }
        return [string]$m
      } elseif ($ErrorRecord -is [Exception]) {
        return [string]$ErrorRecord.Message
      } else {
        return [string]$ErrorRecord
      }
    } catch { return 'Unknown error' }
  }
}
#endregion

#region Logging
function Write-Log {
  param(
    [Parameter(Mandatory)] [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')] $Level,
    [Parameter(Mandatory)] $Message,
    [switch] $NoConsole
  )
  if ($Level -eq 'DEBUG' -and -not $DebugVerbose) { return }
  try {
    if ($Message -is [System.Array]) { $Message = ($Message | ForEach-Object { [string]$_ }) -join '; ' }
    $Message = [string]$Message
  } catch { $Message = 'Unprintable message' }
  $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$timestamp] [$Level] $Message"
  try {
    if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line
  } catch { try { Write-Host $line } catch {} }
  if (-not $NoConsole) {
    $fg = switch ($Level) {
      'DEBUG'   { 'DarkGray' }
      'WARN'    { 'Yellow' }
      'ERROR'   { 'Red' }
      'SUCCESS' { 'Green' }
      default   { 'White' }
    }
    try { Write-Host $line -ForegroundColor $fg } catch { Write-Host $line }
  }
}
function Write-Header {
  $bar = ('=' * 70)
  Write-Log INFO $bar
  Write-Log INFO "$AppName Installer and Local Server"
  Write-Log INFO $bar
}
function Confirm-YN {
  param([Parameter(Mandatory)] [string] $Prompt,[switch] $DefaultYes)
  while ($true) {
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $resp = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($resp)) { return $DefaultYes.IsPresent }
    switch ($resp.Trim().ToLower()) {
      'y' { return $true }
      'yes' { return $true }
      'n' { return $false }
      'no' { return $false }
      default { Write-Log WARN 'Please answer Y or N.' }
    }
  }
}
#endregion

#region System checks
function Test-PowerShellVersion { if ($PSVersionTable.PSVersion.Major -lt 5) { throw "PowerShell 5.0+ required. Detected: $($PSVersionTable.PSVersion)" } }
function Test-DiskSpace {
  param([string] $Path,[int] $MinMB = 100)
  $root = [IO.Path]::GetPathRoot($Path)
  $driveName = $root.TrimEnd('\').TrimEnd(':')
  $drive = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
  if (-not $drive) { return }
  $freeMB = [math]::Round($drive.Free/1MB)
  if ($freeMB -lt $MinMB) { throw ("Insufficient disk space on {0}: {1}MB available, {2}MB required." -f $drive.Name,$freeMB,$MinMB) }
  Write-Log DEBUG ("Disk space OK: {0}MB free." -f $freeMB)
}
function Test-WritePermission {
  param([string] $Dir)
  if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
  $testFile = Join-Path $Dir ".perm_test_$(Get-Random).tmp"
  try { 'test' | Set-Content -Path $testFile -Encoding ascii -Force; Remove-Item $testFile -Force }
  catch { throw "No write permission to $Dir. Run as Administrator or choose a writable location." }
  Write-Log DEBUG "Write permission OK for $Dir."
}
function Test-NetworkConnectivity {
  try { $uri = [Uri]$DownloadUrl } catch { throw ("Invalid download URL: {0}" -f $DownloadUrl) }
  $hostName = $uri.DnsSafeHost
  try {
    $ping = Test-Connection -ComputerName $hostName -Count 1 -Quiet -ErrorAction Stop
    if (-not $ping) { Write-Log WARN ("Ping to {0} failed; continuing (ICMP may be blocked)." -f $hostName) }
  } catch { Write-Log WARN ("Unable to ping {0}; continuing." -f $hostName) }
}
function Test-PortFree {
  param([int] $Port)
  $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
  try { $listener.Start(); $listener.Stop() } catch { throw ("Port {0} appears to be in use. Choose a different port." -f $Port) }
}
function Check-ExecutionPolicy { try { $policy = Get-ExecutionPolicy -Scope Process; Write-Log DEBUG ("ExecutionPolicy (Process): {0}" -f $policy) } catch { Write-Log WARN 'Unable to retrieve ExecutionPolicy.' } }
#endregion

#region Utilities
function Ensure-Dirs { foreach ($d in @($InstallRoot,$TempDir,$BackupRoot,$LogDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } } }
function Get-SHA256 { param([string] $FilePath) $sha=[System.Security.Cryptography.SHA256]::Create(); $fs=[IO.File]::OpenRead($FilePath); try { ($sha.ComputeHash($fs)|ForEach-Object{$_.ToString('x2')}) -join '' } finally { $fs.Dispose(); $sha.Dispose() } }
function Invoke-Backoff { param([int] $Attempt) $wait=[int]([math]::Pow(2,$Attempt)*$BaseBackoffSec); Write-Log WARN ("Retrying in {0}s..." -f $wait); Start-Sleep -Seconds $wait }
function New-Timestamp { (Get-Date).ToString('yyyyMMdd_HHmmss') }
#endregion

#region Download
function Download-File {
  param([string] $Url,[string] $Destination,[int] $TimeoutSec = 120,[int] $MaxRetries = 3)
  for ($attempt=1; $attempt -le $MaxRetries; $attempt++) {
    try {
      if (Test-Path $Destination) { Remove-Item $Destination -Force -ErrorAction SilentlyContinue }
      Write-Log INFO ("Downloading package (attempt {0}/{1})..." -f $attempt,$MaxRetries)
      $req=[System.Net.HttpWebRequest]::Create($Url)
      $req.UserAgent="$AppName-Installer"; $req.Timeout=$TimeoutSec*1000; $req.ReadWriteTimeout=$TimeoutSec*1000; $req.AllowAutoRedirect=$true
      $resp=$req.GetResponse()
      try {
        $length=$resp.ContentLength; $inS=$resp.GetResponseStream(); $outS=New-Object IO.FileStream($Destination,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $buffer=New-Object byte[] 65536; $total=0L; $sw=[Diagnostics.Stopwatch]::StartNew(); $last=[datetime]::UtcNow
        while ($true) {
          $read=$inS.Read($buffer,0,$buffer.Length); if ($read -le 0) { break }
          $outS.Write($buffer,0,$read); $total+=$read
          $now=[datetime]::UtcNow
          if (($now - $last).TotalMilliseconds -ge 500) {
            $elapsed=$sw.Elapsed.TotalSeconds; $speedBps=if($elapsed -gt 0){[double]$total/$elapsed}else{0}
            $percent=if($length -gt 0){[math]::Round(($total/$length)*100,2)}else{0}
            $eta=if($length -gt 0 -and $speedBps -gt 0){[timespan]::FromSeconds([math]::Max(0,($length-$total)/$speedBps))}else{[timespan]::Zero}
            $speedStr=if($speedBps -gt 1MB){'{0:N2} MB/s' -f ($speedBps/1MB)}elseif($speedBps -gt 1KB){'{0:N2} KB/s' -f ($speedBps/1KB)}else{'{0:N0} B/s' -f $speedBps}
            $etaStr=if($eta -ne [timespan]::Zero){'{0:mm\:ss}' -f $eta}else{'--:--'}
            $sizeStr=if($length -gt 0){'{0:N1} MB' -f ($length/1MB)}else{'Unknown'}
            Write-Log INFO ("Downloading: {0}% | {1}/{2} | {3} | ETA {4}" -f $percent, ('{0:N1} MB' -f ($total/1MB)), $sizeStr, $speedStr, $etaStr)
            $last=$now
          }
        }
        $sw.Stop()
      } finally { if ($inS){$inS.Dispose()} if ($outS){$outS.Dispose()} if ($resp){$resp.Dispose()} }
      Write-Log SUCCESS ("Download completed: {0}" -f $Destination); return
    } catch { Write-Log ERROR (Get-ErrorMessage $_); if ($attempt -lt $MaxRetries) { Invoke-Backoff -Attempt $attempt } else { throw "Failed to download after $MaxRetries attempts." } }
  }
}
#endregion

#region ZIP handling
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Test-ZipValid {
  param([string] $ZipFile)
  try { $count=0; $zip=[IO.Compression.ZipFile]::OpenRead($ZipFile); try { foreach($e in $zip.Entries){$count++} } finally {$zip.Dispose()} if ($count -le 0){throw 'ZIP contains no entries.'}; Write-Log DEBUG ("ZIP entries: {0}" -f $count); return $true } catch { Write-Log ERROR (Get-ErrorMessage $_); return $false }
}
function Clear-DirectoryContent { param([string] $Dir)
  if (-not (Test-Path $Dir)) { return }
  Get-ChildItem -LiteralPath $Dir -Force -Recurse -File | Remove-Item -Force -ErrorAction SilentlyContinue
  Get-ChildItem -LiteralPath $Dir -Force -Recurse -Directory | Sort-Object FullName -Descending | ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
}
function Extract-Zip { param([string] $ZipFile,[string] $Destination)
  Write-Log INFO ("Extracting to: {0}" -f $Destination)
  if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
  [IO.Compression.ZipFile]::ExtractToDirectory($ZipFile,$Destination)
  Write-Log SUCCESS 'Extraction complete.'
}
#endregion

#region Web root detection
function Detect-WebRoot {
  param([string] $BaseDir)
  foreach ($n in $DefaultIndexNames) { if (Test-Path (Join-Path $BaseDir $n)) { return $BaseDir } }
  foreach ($d in $CommonWebDirs) {
    $p = Join-Path $BaseDir $d
    if (Test-Path $p) { foreach ($n in $DefaultIndexNames) { if (Test-Path (Join-Path $p $n)) { return $p } } }
  }
  $subs = @(Get-ChildItem -LiteralPath $BaseDir -Directory -Force -ErrorAction SilentlyContinue)
  if ($subs.Length -eq 1) {
    $nested = $subs[0].FullName
    foreach ($n in $DefaultIndexNames) { if (Test-Path (Join-Path $nested $n)) { return $nested } }
    foreach ($d in $CommonWebDirs) {
      $p = Join-Path $nested $d
      if (Test-Path $p) { foreach ($n in $DefaultIndexNames) { if (Test-Path (Join-Path $p $n)) { return $p } } }
    }
  }
  $idx = Get-ChildItem -LiteralPath $BaseDir -Recurse -File -Include $DefaultIndexNames -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($idx) { return $idx.DirectoryName }
  return $BaseDir
}
#endregion

#region Backup & Rollback
function Create-Backup {
  param([string] $SourceDir)
  if (-not (Test-Path $SourceDir)) { return $null }
  $stamp = New-Timestamp; $backupDir = Join-Path $BackupRoot "backup_$stamp"
  New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
  Write-Log INFO ("Creating backup: {0}" -f $backupDir)
  $items = Get-ChildItem -LiteralPath $SourceDir -Force -ErrorAction Stop
  foreach ($it in $items) {
    $name=$it.Name
    if ($it.PSIsContainer -and ($InternalManagedDirs -contains $name)) { Write-Log DEBUG ("Skipping internal folder during backup: {0}" -f $name); continue }
    $dest = Join-Path $backupDir $name
    try { Copy-Item -Path $it.FullName -Destination $dest -Recurse -Force -ErrorAction Stop }
    catch { throw ("Backup failed while copying '{0}': {1}" -f $name, (Get-ErrorMessage $_)) }
  }
  Write-Log SUCCESS 'Backup complete.'; return $backupDir
}
function Rollback-FromBackup { param([string] $BackupDir,[string] $TargetDir)
  Write-Log WARN ("Rolling back from backup: {0}" -f $BackupDir)
  if (Test-Path $TargetDir) { Clear-DirectoryContent -Dir $TargetDir }
  Copy-Item -Path (Join-Path $BackupDir '*') -Destination $TargetDir -Recurse -Force -ErrorAction Stop
  Write-Log SUCCESS 'Rollback complete.'
}
#endregion

#region HTTP Server (synchronous handling, base injection, asset fallback)
function Get-ContentType {
  param([string] $Path)
  $map = @{
    '.html'='text/html'; '.htm'='text/html'; '.css'='text/css'; '.js'='application/javascript'; '.mjs'='application/javascript'
    '.json'='application/json'; '.map'='application/json'; '.png'='image/png'; '.jpg'='image/jpeg'; '.jpeg'='image/jpeg'
    '.gif'='image/gif'; '.svg'='image/svg+xml'; '.ico'='image/x-icon'; '.webp'='image/webp'; '.bmp'='image/bmp'
    '.ttf'='font/ttf'; '.otf'='font/otf'; '.woff'='font/woff'; '.woff2'='font/woff2'; '.txt'='text/plain'
    '.xml'='application/xml'; '.pdf'='application/pdf'; '.wasm'='application/wasm'; '.mp4'='video/mp4'
  }
  $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
  if ($map.ContainsKey($ext)) { return $map[$ext] } else { return 'application/octet-stream' }
}
function Inject-BaseIfMissing { param([byte[]] $HtmlBytes)
  try { $t=[Text.Encoding]::UTF8.GetString($HtmlBytes); if ($t -notmatch '<base\s') { $t=$t -replace '(<head[^>]*>)', '$1<base href="/" />'; return [Text.Encoding]::UTF8.GetBytes($t) } } catch {}
  return $HtmlBytes
}
function Start-LocalServer {
  param([string] $WebRoot,[int] $Port = 8993)

  $cts = New-Object System.Threading.CancellationTokenSource
  $script:CtrlC = $false
  $onCancel = {
    if (-not $script:CtrlC) {
      $script:CtrlC = $true
      Write-Log WARN 'Ctrl+C detected — cleaning up and shutting down...'
      $cts.Cancel()
    }
  }
  $global:cancelHandler = [ConsoleCancelEventHandler]{ param($s,$e) try { $e.Cancel = $true } catch {}; & $onCancel }
  [Console]::add_CancelKeyPress($global:cancelHandler)

  Write-Log INFO ("Starting local server at http://localhost:{0}" -f $Port)
  $listener = New-Object System.Net.HttpListener
  $prefix = "http://localhost:$Port/"
  $listener.Prefixes.Add($prefix)
  try { $listener.Start() } catch { Write-Log ERROR (Get-ErrorMessage $_); throw }
  Write-Log SUCCESS ("Server listening on {0}" -f $prefix)
  try { Start-Process $prefix } catch { Write-Log WARN (Get-ErrorMessage $_) }

  # Compute SPA index and dir
  $rootIndex = $null
  foreach ($n in $DefaultIndexNames) { $p=Join-Path $WebRoot $n; if (Test-Path $p) { $rootIndex=$p; break } }
  $spaIndex = $rootIndex
  if (-not $spaIndex) {
    $probe = Get-ChildItem -LiteralPath $WebRoot -Recurse -File -Include $DefaultIndexNames -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($probe) { $spaIndex = $probe.FullName; Write-Log WARN ("Root index not found; '/' and SPA -> {0}" -f $spaIndex) }
  }
  $spaDir = if ($spaIndex) { Split-Path -Parent $spaIndex } else { $null }

  Write-Log INFO ("Serving from: {0}" -f $WebRoot)
  Write-Log INFO 'Press Ctrl+C to stop.'

  while (-not $cts.IsCancellationRequested) {
    try {
      # Use the blocking GetContext with a short timeout pattern
      $ar = $listener.BeginGetContext($null,$null)
      if (-not $ar.AsyncWaitHandle.WaitOne(200)) {
        $listener.EndGetContext($ar) | Out-Null  # drain to avoid leaks if it actually completed
        continue
      }
      $ctx = $listener.EndGetContext($ar)

      # Handle request synchronously (simpler than jobs, better for logs and Ctrl+C)
      try {
        $req = $ctx.Request
        $resp = $ctx.Response
        $resp.Headers['Access-Control-Allow-Origin'] = '*'
        $resp.Headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        $resp.Headers['Access-Control-Allow-Headers'] = 'Content-Type'
        if ($req.HttpMethod -eq 'OPTIONS') { $resp.StatusCode = 200; $resp.Close(); continue }

        $rawUrl = [Uri]::UnescapeDataString($req.RawUrl)
        $relPath = $rawUrl.TrimStart('/')

        # "/" route
        if ([string]::IsNullOrWhiteSpace($relPath)) {
          $fsPath = $null
          if ($rootIndex -and (Test-Path $rootIndex)) { $fsPath = $rootIndex }
          elseif ($spaIndex -and (Test-Path $spaIndex)) { $fsPath = $spaIndex }
          if ($fsPath) {
            $ct = Get-ContentType $fsPath
            $data = [IO.File]::ReadAllBytes($fsPath)
            if ($ct -like 'text/html*') { $data = Inject-BaseIfMissing $data }
            $resp.StatusCode = 200; $resp.ContentType = $ct; $resp.ContentLength64 = $data.Length
            $resp.OutputStream.Write($data,0,$data.Length); $resp.Close()
            Write-Log DEBUG ($req.HttpMethod + ' ' + $rawUrl + ' -> ' + $ct + ' size=' + $data.Length + 'B')
            continue
          } else {
            $resp.StatusCode = 404; $nf=[Text.Encoding]::UTF8.GetBytes('404 Not Found')
            $resp.ContentType='text/plain'; $resp.ContentLength64=$nf.Length; $resp.OutputStream.Write($nf,0,$nf.Length); $resp.Close()
            Write-Log ERROR ($req.HttpMethod + ' ' + $rawUrl + ' -> 404 no-index')
            continue
          }
        }

        # Non-root: try WebRoot, then spaDir, then SPA, then 404
        $fsPath = Join-Path $WebRoot $relPath
        if (-not (Test-Path $fsPath) -and $spaDir) {
          $alt = Join-Path $spaDir $relPath
          if (Test-Path $alt) { $fsPath = $alt }
        }
        if (-not (Test-Path $fsPath)) {
          if ($spaIndex -and (Test-Path $spaIndex)) {
            $fsPath = $spaIndex
          } else {
            $resp.StatusCode = 404; $nf2=[Text.Encoding]::UTF8.GetBytes('404 Not Found')
            $resp.ContentType='text/plain'; $resp.ContentLength64=$nf2.Length; $resp.OutputStream.Write($nf2,0,$nf2.Length); $resp.Close()
            Write-Log INFO ($req.HttpMethod + ' ' + $rawUrl + ' -> 404')
            continue
          }
        }

        # Directory handling
        if ((Get-Item $fsPath).PSIsContainer) {
          $dirIndex = $null
          foreach ($n in @('index.html','index.htm')) { $c=Join-Path $fsPath $n; if (Test-Path $c) { $dirIndex=$c; break } }
          if ($dirIndex) { $fsPath = $dirIndex }
          elseif ($spaIndex -and (Test-Path $spaIndex)) { $fsPath = $spaIndex }
          else {
            $resp.StatusCode = 404; $nf3=[Text.Encoding]::UTF8.GetBytes('404 Not Found')
            $resp.ContentType='text/plain'; $resp.ContentLength64=$nf3.Length; $resp.OutputStream.Write($nf3,0,$nf3.Length); $resp.Close()
            Write-Log INFO ($req.HttpMethod + ' ' + $rawUrl + ' -> 404 dir-no-index')
            continue
          }
        }

        # Serve file with base injection for HTML
        $ct2 = Get-ContentType $fsPath
        $bytes = [IO.File]::ReadAllBytes($fsPath)
        if ($ct2 -like 'text/html*') { $bytes = Inject-BaseIfMissing $bytes }
        $resp.StatusCode = 200; $resp.ContentType = $ct2; $resp.ContentLength64 = $bytes.Length
        $resp.OutputStream.Write($bytes,0,$bytes.Length); $resp.Close()
        Write-Log DEBUG ($req.HttpMethod + ' ' + $rawUrl + ' -> ' + $ct2 + ' size=' + $bytes.Length + 'B')
      } catch {
        try {
          $ctx.Response.StatusCode = 500
          $msg='500 Internal Server Error'; $eb=[Text.Encoding]::UTF8.GetBytes($msg)
          $ctx.Response.ContentType='text/plain'; $ctx.Response.ContentLength64=$eb.Length
          $ctx.Response.OutputStream.Write($eb,0,$eb.Length); $ctx.Response.Close()
        } catch {}
        Write-Log ERROR (Get-ErrorMessage $_)
      }
    } catch {
      if (-not $cts.IsCancellationRequested) { Write-Log ERROR (Get-ErrorMessage $_) }
    }
  }

  try { $listener.Stop(); $listener.Close() } catch {}
  try { if ($global:cancelHandler) { [Console]::remove_CancelKeyPress($global:cancelHandler); $global:cancelHandler=$null } } catch {}
  Write-Log SUCCESS 'Server stopped.'
  if ($script:CtrlC) { exit 0 }
}
#endregion

#region Main
trap { Write-Log ERROR ("Unhandled: {0}" -f (Get-ErrorMessage $_)); continue }

try {
  Ensure-Dirs
  Write-Header
  Check-ExecutionPolicy
  Test-PowerShellVersion
  Test-DiskSpace -Path $InstallRoot -MinMB $MinDiskMB
  Test-WritePermission -Dir $InstallRoot
  Test-NetworkConnectivity
  Test-PortFree -Port $ServerPort

  Download-File -Url $DownloadUrl -Destination $ZipPath -TimeoutSec $DownloadTimeoutSec -MaxRetries $MaxRetries

  $actualHash = Get-SHA256 -FilePath $ZipPath
  if ([string]::IsNullOrWhiteSpace($ExpectedSHA256)) {
    Write-Log WARN 'No expected SHA256 provided. File integrity cannot be verified.'
    Write-Log WARN ("Downloaded file SHA256: {0}" -f $actualHash)
    Write-Log WARN 'Only proceed if the source is trusted.'
    $ok = Confirm-YN -Prompt 'Proceed with installation?' -DefaultYes:$false
    if (-not $ok) { throw 'User aborted due to missing hash verification.' }
  } else {
    if ($actualHash -ne $ExpectedSHA256.ToLower()) { throw ("Hash mismatch! Expected: {0}, Actual: {1}" -f $ExpectedSHA256,$actualHash) }
    else { Write-Log SUCCESS 'SHA256 verified.' }
  }

  if (-not (Test-ZipValid -ZipFile $ZipPath)) { throw 'ZIP validation failed.' }

  $hadExisting = Test-Path $InstallRoot
  $backupDir = $null
  if ($hadExisting) {
    Write-Log WARN ("An existing installation was found at: {0}" -f $InstallRoot)
    $proceed = Confirm-YN -Prompt 'Proceed to back up and replace the current installation?' -DefaultYes:$false
    if (-not $proceed) { throw 'User canceled update/replace operation.' }
    $backupDir = Create-Backup -SourceDir $InstallRoot
  }

  $extractDir = Join-Path $TempDir ("extract_" + (New-Timestamp))
  New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
  try { Extract-Zip -ZipFile $ZipPath -Destination $extractDir }
  catch { if ($backupDir) { Rollback-FromBackup -BackupDir $backupDir -TargetDir $InstallRoot }; throw }

  $detectedRoot = Detect-WebRoot -BaseDir $extractDir
  Write-Log INFO ("Detected web root: {0}" -f $detectedRoot)

  try {
    if (-not (Test-Path $InstallRoot)) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }
    Clear-DirectoryContent -Dir $InstallRoot
    $rc = $null
    try { $null = & robocopy $detectedRoot $InstallRoot /MIR /NFL /NDL /NJH /NJS /NP /R:2 /W:2; $rc=$LASTEXITCODE; Write-Log DEBUG ("robocopy exit code: {0}" -f $rc) } catch { $rc = $null }
    if ($rc -eq $null -or $rc -ge 8) { Copy-Item -Path (Join-Path $detectedRoot '*') -Destination $InstallRoot -Recurse -Force -ErrorAction Stop }
    $installedIndex = $null
    foreach ($n in $DefaultIndexNames) { $p = Join-Path $InstallRoot $n; if (Test-Path $p) { $installedIndex=$p; break } }
    if (-not $installedIndex) {
      $probe = Get-ChildItem -LiteralPath $InstallRoot -Recurse -File -Include $DefaultIndexNames -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($probe) { Write-Log WARN ("index.* not at root; first found at: {0}" -f $probe.FullName) } else { Write-Log WARN 'No index.html found after install.' }
    }
    Write-Log SUCCESS ("Installed to: {0}" -f $InstallRoot)
  } catch {
    Write-Log ERROR ("Install copy failed: {0}" -f (Get-ErrorMessage $_))
    if ($backupDir) { Rollback-FromBackup -BackupDir $backupDir -TargetDir $InstallRoot }
    throw
  }

  try { Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } catch {}

  Start-LocalServer -WebRoot $InstallRoot -Port $ServerPort

} catch {
  Write-Log ERROR (Get-ErrorMessage $_)
  Write-Log ERROR 'Installation failed.'
  exit 1
} finally {
  try { if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}
#endregion
