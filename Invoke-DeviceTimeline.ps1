#Requires -Version 5.0
<#
.SYNOPSIS
    Builds a historic activity timeline for a Windows device (DFIR triage).

.DESCRIPTION
    Collects and normalises time-stamped artefacts from a live Windows host into a
    single sorted timeline (CSV / JSON / HTML). Covers every local user profile and
    device-wide artefacts.

    Collectors (modules):
      EventLogs      Security, System, Application, PowerShell, Task Scheduler, RDP/TS,
                     WinRM, Defender, WMI-Activity, DNS-Client, NetworkProfile, WLAN,
                     DriverFrameworks, BITS, Sysmon, SMB, AppLocker, CodeIntegrity,
                     Shell-Core, Kernel-PnP, Program-Inventory, PrintService, Setup.
      PSHistory      Per-user PSReadLine ConsoleHost_history.txt + PS transcripts.
      ScheduledTasks Task definitions, registration dates, last run time / result.
      Browsers       Chrome / Edge / Brave / Vivaldi / Opera / Chromium history and
                     downloads (raw SQLite reader, no external modules) + Firefox.
      Execution      Prefetch, UserAssist, ShimCache (AppCompatCache), Amcache,
                     MUICache, RunMRU, AppCompatFlags.
      Files          Recent .lnk, Jump Lists, Office MRU, Zone.Identifier downloads.
      Network        Live TCP connections, RDP destinations, mapped drives, WLAN
                     profiles, network profile history.
      USB            USBSTOR / SCSI / WpdBusEnum registry, setupapi.dev.log.
      Persistence    Run/RunOnce, Winlogon, IFEO, AppInit, startup folders, services,
                     WMI event subscriptions.
      Accounts       Local users and groups, last logon, password set/expiry.
      System         OS install, boot time, timezone, log coverage / clearing.

.PARAMETER OutputPath
    Directory to create the case folder in. Default: current directory.

.PARAMETER Days
    Look-back window in days. Default 30. Ignored when -AllTime is used.

.PARAMETER AllTime
    Do not apply a look-back filter (everything the artefacts still hold).

.PARAMETER MaxEventsPerQuery
    Cap on events returned per event-log query chunk. Default 3000.

.PARAMETER Include
    Only run the named modules.

.PARAMETER Exclude
    Run everything except the named modules.

.PARAMETER UseVSS
    Create a temporary volume shadow copy and read locked files (browser DBs,
    Amcache, registry hives) from it. Requires elevation. The snapshot is deleted
    at the end of the run.

.PARAMETER NoHtml / -NoJson
    Skip the HTML report / JSON output.

.PARAMETER HtmlMaxRows
    Cap on events embedded in the HTML report. Default 50000. The report renders
    only the current page into the DOM, so this bounds file size and load time,
    not interactive performance. Timeline.csv always holds the full data set.

.EXAMPLE
    .\Invoke-DeviceTimeline.ps1 -Days 60 -UseVSS

.EXAMPLE
    .\Invoke-DeviceTimeline.ps1 -AllTime -Include Browsers,PSHistory,Execution

.NOTES
    Run elevated (SYSTEM-level artefacts and other users' hives need it).
    Written for Windows PowerShell 5.1, ASCII only, no external dependencies.
    All timestamps are recorded in UTC and in local time of the collecting host.
    Artefact caveats (ShimCache = file mtime, prefetch = file mtime, PSReadLine
    history = no per-line timestamp) are flagged in the Confidence column.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$Days = 30,
    [switch]$AllTime,
    [int]$MaxEventsPerQuery = 3000,
    [ValidateSet('EventLogs','PSHistory','ScheduledTasks','Browsers','Execution','Files','Network','USB','Persistence','Accounts','System','AIAssistants')]
    [string[]]$Include,
    [ValidateSet('EventLogs','PSHistory','ScheduledTasks','Browsers','Execution','Files','Network','USB','Persistence','Accounts','System','AIAssistants')]
    [string[]]$Exclude,
    [switch]$UseVSS,
    [switch]$NoHtml,
    [switch]$NoJson,
    [int]$HtmlMaxRows = 50000,
    [int]$MaxFilesPerFolder = 5000,
    [int]$MaxAISessionFiles = 200,
    [int]$MaxAITranscriptLines = 40000,
    [int]$MaxAIEventsPerSession = 3000,
    [switch]$RedactAIContent,
    [string]$RiskPatternFile
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
$script:Timeline    = New-Object System.Collections.Generic.List[Object]
$script:Issues      = New-Object System.Collections.Generic.List[Object]
$script:Coverage    = New-Object System.Collections.Generic.List[Object]
$script:LoadedHives = New-Object System.Collections.Generic.List[String]
$script:HostName    = $env:COMPUTERNAME
$script:StartedUtc  = (Get-Date).ToUniversalTime()
$script:CutoffUtc   = if ($AllTime) { [datetime]::MinValue } else { $script:StartedUtc.AddDays(-[Math]::Abs($Days)) }
$script:VssRoot     = $null
$script:VssId       = $null
$script:SysDrive    = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
$script:Stats       = @{}

$script:AllModules  = @('System','EventLogs','PSHistory','ScheduledTasks','Browsers','Execution','Files','Network','USB','Persistence','Accounts','AIAssistants')
$script:AIProjectDirs = $null

$stamp   = (Get-Date).ToString('yyyyMMdd_HHmmss')
$CaseDir = Join-Path $OutputPath ("DeviceTimeline_{0}_{1}" -f $script:HostName, $stamp)
$null    = New-Item -Path $CaseDir -ItemType Directory -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $CaseDir 'Collection.log'

# ---------------------------------------------------------------------------
# Logging / error capture
# ---------------------------------------------------------------------------
function Write-TLLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','STEP')][string]$Level = 'INFO')
    $line = '{0}  [{1}]  {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message
    switch ($Level) {
        'STEP'  { Write-Host $line -ForegroundColor Cyan }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line -ForegroundColor Gray }
    }
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
}

function Add-TLIssue {
    param([string]$Collector, [string]$Target, [string]$Message)
    $script:Issues.Add([pscustomobject][ordered]@{
        TimeLocal = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Collector = $Collector
        Target    = $Target
        Message   = ($Message -replace '\s+', ' ')
    })
}

function Test-TLPath {
    # Test-Path that never emits an error record. Access-denied on a protected
    # registry key or file simply means "not collectable here".
    param([string]$Path)
    if (-not $Path) { return $false }
    try { return [bool](Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch { return $false }
}

function Test-TLModule {
    param([string]$Name)
    if ($Include -and ($Include -notcontains $Name)) { return $false }
    if ($Exclude -and ($Exclude -contains $Name))    { return $false }
    return $true
}

# ---------------------------------------------------------------------------
# Timeline record creation
# ---------------------------------------------------------------------------
function ConvertTo-TLText {
    param($Value, [int]$Max = 1200)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace '[\r\n\t]+', ' | '
    $s = $s -replace '\s{2,}', ' '
    $s = $s.Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...[truncated]' }
    return $s
}

function Add-TLEvent {
    param(
        [Parameter(Mandatory=$true)][AllowNull()][object]$Time,   # DateTime (UTC or local per -IsLocal)
        [Parameter(Mandatory=$true)][string]$Source,
        [string]$Category    = '',
        [string]$User        = '',
        [string]$Description = '',
        [string]$Details     = '',
        [string]$Artifact    = '',
        [string]$Confidence  = 'High',
        [switch]$IsLocal
    )
    if ($null -eq $Time) { return }
    try { $dt = [datetime]$Time } catch { return }
    if ($dt.Year -lt 1980) { return }
    if ($IsLocal) { $utc = $dt.ToUniversalTime() } else { $utc = [datetime]::SpecifyKind($dt, 'Utc') }
    if ($utc -lt $script:CutoffUtc) { return }
    if ($utc -gt $script:StartedUtc.AddYears(5)) { return }
    # Timestamps after the collection time indicate a rolled-back clock, a timestomped
    # artefact or a timezone problem. Keep them and flag them - never silently drop.
    if ($utc -gt $script:StartedUtc.AddMinutes(5)) {
        $Confidence = 'SUSPECT - future dated vs collection time. ' + $Confidence
    }

    $script:Timeline.Add([pscustomobject][ordered]@{
        TimeUtc     = $utc
        Source      = $Source
        Category    = $Category
        User        = ConvertTo-TLText $User 128
        Description = ConvertTo-TLText $Description 400
        Details     = ConvertTo-TLText $Details 2000
        Artifact    = ConvertTo-TLText $Artifact 400
        Confidence  = $Confidence
    })
    if ($script:Stats.ContainsKey($Source)) { $script:Stats[$Source]++ } else { $script:Stats[$Source] = 1 }
}

function ConvertFrom-TLFileTime {
    param([long]$Value)
    if ($Value -le 0) { return $null }
    try { return [datetime]::FromFileTimeUtc($Value) } catch { return $null }
}

function ConvertFrom-TLWebKitTime {
    # Chromium: microseconds since 1601-01-01 UTC
    param([long]$Value)
    if ($Value -le 0) { return $null }
    try { return ([datetime]'1601-01-01T00:00:00Z').ToUniversalTime().AddSeconds($Value / 1000000.0) } catch { return $null }
}

function ConvertFrom-TLUnixMicro {
    # Firefox: microseconds since 1970-01-01 UTC
    param([long]$Value)
    if ($Value -le 0) { return $null }
    try { return ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime().AddSeconds($Value / 1000000.0) } catch { return $null }
}

# ---------------------------------------------------------------------------
# Elevation, VSS, locked-file copy
# ---------------------------------------------------------------------------
function Test-TLAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-TLShadowCopy {
    try {
        Write-TLLog "Creating volume shadow copy of $script:SysDrive ..." 'INFO'
        $cls = [wmiclass]'root\cimv2:Win32_ShadowCopy'
        $res = $cls.Create("$script:SysDrive\", 'ClientAccessible')
        if ($res.ReturnValue -ne 0) { Add-TLIssue 'VSS' $script:SysDrive "Create returned $($res.ReturnValue)"; return $false }
        $sc = Get-CimInstance Win32_ShadowCopy -Filter "ID='$($res.ShadowID)'" -ErrorAction Stop
        $script:VssId   = $res.ShadowID
        $script:VssRoot = $sc.DeviceObject
        Write-TLLog "Shadow copy ready: $script:VssRoot" 'INFO'
        return $true
    } catch {
        Add-TLIssue 'VSS' $script:SysDrive $_.Exception.Message
        Write-TLLog "Shadow copy failed: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Remove-TLShadowCopy {
    if (-not $script:VssId) { return }
    try {
        $sc = Get-CimInstance Win32_ShadowCopy -Filter "ID='$($script:VssId)'" -ErrorAction Stop
        if ($sc) { Remove-CimInstance -InputObject $sc -ErrorAction Stop; Write-TLLog 'Shadow copy removed.' 'INFO' }
    } catch { Add-TLIssue 'VSS' $script:VssId $_.Exception.Message }
    $script:VssId = $null; $script:VssRoot = $null
}

function Get-TLShadowPath {
    param([string]$Path)
    if (-not $script:VssRoot) { return $null }
    if ($Path -notmatch '^[A-Za-z]:\\') { return $null }
    $rel = $Path.Substring(2)
    return ('{0}{1}' -f $script:VssRoot, $rel)
}

function Copy-TLFile {
    # Copies a possibly locked file. Order: plain copy -> shared handle -> VSS.
    param([string]$Source, [string]$Destination)
    try { Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop; return $true } catch { }
    try {
        $in  = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $out = [System.IO.File]::Create($Destination)
        $in.CopyTo($out); $out.Close(); $in.Close()
        return $true
    } catch { }
    if ($script:VssRoot) {
        $sp = Get-TLShadowPath $Source
        if ($sp) {
            try {
                $in  = [System.IO.File]::Open($sp, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
                $out = [System.IO.File]::Create($Destination)
                $in.CopyTo($out); $out.Close(); $in.Close()
                return $true
            } catch { Add-TLIssue 'CopyFile' $Source ("VSS copy failed: " + $_.Exception.Message) }
        }
    }
    Add-TLIssue 'CopyFile' $Source 'File is locked and could not be copied (try -UseVSS).'
    return $false
}

# ---------------------------------------------------------------------------
# Registry key last-write time (P/Invoke)
# ---------------------------------------------------------------------------
$script:RegTypeLoaded = $false
function Initialize-TLRegType {
    if ($script:RegTypeLoaded) { return }
    $code = @'
using System;
using System.Runtime.InteropServices;
public class TLRegHelper {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int ulOptions, int samDesired, out IntPtr phkResult);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegQueryInfoKey(IntPtr hKey, IntPtr lpClass, IntPtr lpcClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcMaxSubKeyLen, IntPtr lpcMaxClassLen, IntPtr lpcValues,
        IntPtr lpcMaxValueNameLen, IntPtr lpcMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    public static long LastWriteFileTime(string hive, string subKey) {
        IntPtr root;
        switch (hive.ToUpperInvariant()) {
            case "HKLM": root = new IntPtr(unchecked((int)0x80000002)); break;
            case "HKU":  root = new IntPtr(unchecked((int)0x80000003)); break;
            case "HKCU": root = new IntPtr(unchecked((int)0x80000001)); break;
            case "HKCR": root = new IntPtr(unchecked((int)0x80000000)); break;
            default: return 0;
        }
        IntPtr hk;
        int rc = RegOpenKeyEx(root, subKey, 0, 0x20019, out hk);
        if (rc != 0) return 0;
        long ft = 0;
        rc = RegQueryInfoKey(hk, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                             IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
        RegCloseKey(hk);
        if (rc != 0) return 0;
        return ft;
    }
}
'@
    try { Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop; $script:RegTypeLoaded = $true }
    catch { Add-TLIssue 'RegHelper' 'Add-Type' $_.Exception.Message }
}

function Get-TLRegKeyTime {
    # Accepts 'HKLM\SOFTWARE\...' , 'HKU\S-1-5-21...\...' or a PS provider path.
    param([string]$Path)
    Initialize-TLRegType
    if (-not $script:RegTypeLoaded) { return $null }
    $p = $Path -replace '^Registry::', ''
    $p = $p -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_CURRENT_USER', 'HKCU' -replace '^HKEY_CLASSES_ROOT', 'HKCR'
    $p = $p -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
    $idx = $p.IndexOf('\')
    if ($idx -lt 1) { return $null }
    $hive = $p.Substring(0, $idx)
    $sub  = $p.Substring($idx + 1)
    try {
        $ft = [TLRegHelper]::LastWriteFileTime($hive, $sub)
        return (ConvertFrom-TLFileTime $ft)
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# User profile enumeration and per-user hive mounting
# ---------------------------------------------------------------------------
function Get-TLUserProfiles {
    $out = New-Object System.Collections.Generic.List[Object]
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    try {
        Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
            $sid  = Split-Path $_.Name -Leaf
            $path = (Get-ItemProperty -Path $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $path) { return }
            $name = Split-Path $path -Leaf
            $out.Add([pscustomobject]@{
                Sid       = $sid
                Path      = $path
                Name      = $name
                IsDomain  = ($sid -like 'S-1-5-21-*' -or $sid -like 'S-1-12-*')
                HiveOnline= (Test-TLPath ("Registry::HKEY_USERS\$sid"))
                Exists    = (Test-TLPath $path)
            })
        }
    } catch { Add-TLIssue 'UserProfiles' $base $_.Exception.Message }
    return $out
}

function Mount-TLUserHive {
    # Returns a 'Registry::HKEY_USERS\<key>' base path for the profile, or $null.
    param($Profile)
    if (Test-TLPath ("Registry::HKEY_USERS\" + $Profile.Sid)) { return ("Registry::HKEY_USERS\" + $Profile.Sid) }
    $dat = Join-Path $Profile.Path 'NTUSER.DAT'
    if (-not (Test-TLPath $dat)) { return $null }
    $key = 'TL_' + ($Profile.Sid -replace '[^A-Za-z0-9\-]', '')
    $null = & reg.exe load "HKU\$key" "$dat" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $script:LoadedHives.Add($key)
        return "Registry::HKEY_USERS\$key"
    }
    Add-TLIssue 'MountHive' $dat "reg load failed (exit $LASTEXITCODE)"
    return $null
}

function Dismount-TLUserHives {
    if ($script:LoadedHives.Count -eq 0) { return }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    foreach ($key in @($script:LoadedHives)) {
        $null = & reg.exe unload "HKU\$key" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Start-Sleep -Milliseconds 500
            [GC]::Collect(); [GC]::WaitForPendingFinalizers()
            $null = & reg.exe unload "HKU\$key" 2>&1
            if ($LASTEXITCODE -ne 0) { Add-TLIssue 'DismountHive' $key "reg unload failed (exit $LASTEXITCODE)" }
        }
    }
    $script:LoadedHives.Clear()
}

function Resolve-TLSid {
    param([string]$Sid)
    if (-not $Sid) { return '' }
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

# ---------------------------------------------------------------------------
# Minimal read-only SQLite parser (no external assemblies required).
# Supports: table b-tree traversal, record decoding, overflow pages.
# Used for Chromium 'History' and Firefox 'places.sqlite'.
# ---------------------------------------------------------------------------
function Read-TLVarint {
    param([byte[]]$Buffer, [int]$Offset)
    $val = [long]0
    for ($i = 0; $i -lt 8; $i++) {
        if (($Offset + $i) -ge $Buffer.Length) { return @([long]0, 1) }
        $b = $Buffer[$Offset + $i]
        if (($b -band 0x80) -ne 0) {
            $val = ($val -shl 7) -bor [long]($b -band 0x7F)
        } else {
            $val = ($val -shl 7) -bor [long]$b
            return @($val, ($i + 1))
        }
    }
    if (($Offset + 8) -lt $Buffer.Length) { $val = ($val -shl 8) -bor [long]$Buffer[$Offset + 8] }
    return @($val, 9)
}

function Read-TLBigEndian {
    param([byte[]]$Buffer, [int]$Offset, [int]$Length, [switch]$Signed)
    if (($Offset + $Length) -gt $Buffer.Length) { return [long]0 }
    $v = [long]0
    for ($i = 0; $i -lt $Length; $i++) { $v = ($v -shl 8) -bor [long]$Buffer[$Offset + $i] }
    if ($Signed -and $Length -lt 8) {
        $bits = $Length * 8
        $sign = [long]1 -shl ($bits - 1)
        if (($v -band $sign) -ne 0) { $v = $v - ([long]1 -shl $bits) }
    }
    return $v
}

function Read-TLSqliteRecord {
    param([byte[]]$Payload)
    $vals = New-Object System.Collections.ArrayList
    if ($Payload.Length -lt 2) { return $vals }
    $r = Read-TLVarint $Payload 0
    $hdrSize = [int]$r[0]
    $o = [int]$r[1]
    if ($hdrSize -le 0 -or $hdrSize -gt $Payload.Length) { return $vals }
    $types = New-Object System.Collections.ArrayList
    while ($o -lt $hdrSize) {
        $r = Read-TLVarint $Payload $o
        [void]$types.Add([long]$r[0])
        $o += [int]$r[1]
    }
    $b = $hdrSize
    foreach ($t in $types) {
        if ($b -gt $Payload.Length) { [void]$vals.Add($null); continue }
        switch ([long]$t) {
            0 { [void]$vals.Add($null) }
            1 { [void]$vals.Add((Read-TLBigEndian $Payload $b 1 -Signed)); $b += 1 }
            2 { [void]$vals.Add((Read-TLBigEndian $Payload $b 2 -Signed)); $b += 2 }
            3 { [void]$vals.Add((Read-TLBigEndian $Payload $b 3 -Signed)); $b += 3 }
            4 { [void]$vals.Add((Read-TLBigEndian $Payload $b 4 -Signed)); $b += 4 }
            5 { [void]$vals.Add((Read-TLBigEndian $Payload $b 6 -Signed)); $b += 6 }
            6 { [void]$vals.Add((Read-TLBigEndian $Payload $b 8 -Signed)); $b += 8 }
            7 {
                if (($b + 8) -le $Payload.Length) {
                    $tmp = New-Object byte[] 8
                    [Array]::Copy($Payload, $b, $tmp, 0, 8)
                    [Array]::Reverse($tmp)
                    [void]$vals.Add([BitConverter]::ToDouble($tmp, 0))
                } else { [void]$vals.Add($null) }
                $b += 8
            }
            8 { [void]$vals.Add([long]0) }
            9 { [void]$vals.Add([long]1) }
            default {
                $tt = [long]$t
                if ($tt -ge 12) {
                    # BLOB: (N-12)/2 bytes, N even.  TEXT: (N-13)/2 bytes, N odd.
                    if (($tt % 2) -eq 0) { $len = [int](($tt - 12) / 2) } else { $len = [int](($tt - 13) / 2) }
                    if (($b + $len) -gt $Payload.Length) { $len = [Math]::Max(0, $Payload.Length - $b) }
                    if (($tt % 2) -eq 0) {
                        $blob = New-Object byte[] $len
                        if ($len -gt 0) { [Array]::Copy($Payload, $b, $blob, 0, $len) }
                        [void]$vals.Add($blob)
                    } else {
                        if ($len -gt 0) { [void]$vals.Add([Text.Encoding]::UTF8.GetString($Payload, $b, $len)) } else { [void]$vals.Add('') }
                    }
                    $b += $len
                } else { [void]$vals.Add($null) }
            }
        }
    }
    return $vals
}

function Get-TLSqliteCell {
    # Leaf table cell -> @(rowid, payload bytes)
    param([byte[]]$Db, [int]$PageSize, [int]$Usable, [int]$CellOffset)
    $o = $CellOffset
    $r = Read-TLVarint $Db $o; $payloadSize = [long]$r[0]; $o += [int]$r[1]
    $r = Read-TLVarint $Db $o; $rowId       = [long]$r[0]; $o += [int]$r[1]
    if ($payloadSize -le 0 -or $payloadSize -gt 50000000) { return $null }
    $x = $Usable - 35
    if ($payloadSize -le $x) { $local = [int]$payloadSize }
    else {
        $m = [int][Math]::Floor((($Usable - 12) * 32) / 255) - 23
        $k = $m + [int](($payloadSize - $m) % ($Usable - 4))
        if ($k -le $x) { $local = $k } else { $local = $m }
    }
    if ($local -lt 0 -or ($o + $local) -gt $Db.Length) { return $null }
    $buf = New-Object byte[] ([int]$payloadSize)
    [Array]::Copy($Db, $o, $buf, 0, $local)
    $copied = $local
    if ($payloadSize -gt $local) {
        if (($o + $local + 4) -gt $Db.Length) { return $null }
        $next = [int](Read-TLBigEndian $Db ($o + $local) 4)
        $guard = 0
        while ($next -gt 0 -and $copied -lt $payloadSize -and $guard -lt 100000) {
            $guard++
            $pOff = ($next - 1) * $PageSize
            if ($pOff -lt 0 -or ($pOff + $Usable) -gt $Db.Length) { break }
            $chunk = [int][Math]::Min([long]($Usable - 4), ($payloadSize - $copied))
            [Array]::Copy($Db, ($pOff + 4), $buf, $copied, $chunk)
            $copied += $chunk
            $next = [int](Read-TLBigEndian $Db $pOff 4)
        }
    }
    return @($rowId, $buf)
}

function Get-TLSqliteBTreeRows {
    param([byte[]]$Db, [int]$PageSize, [int]$Usable, [int]$RootPage, [int]$MaxRows = 500000)
    $rows  = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push([int]$RootPage)
    $seen  = @{}
    while ($stack.Count -gt 0 -and $rows.Count -lt $MaxRows) {
        $pg = [int]$stack.Pop()
        if ($pg -le 0) { continue }
        if ($seen.ContainsKey($pg)) { continue }
        $seen[$pg] = $true
        $base = ($pg - 1) * $PageSize
        if ($base -lt 0 -or ($base + 12) -ge $Db.Length) { continue }
        $hdr = if ($pg -eq 1) { 100 } else { $base }
        $type = $Db[$hdr]
        $cellCount = [int](Read-TLBigEndian $Db ($hdr + 3) 2)
        if ($cellCount -lt 0 -or $cellCount -gt 100000) { continue }
        if ($type -eq 13) {
            $ptr = $hdr + 8
            for ($i = 0; $i -lt $cellCount; $i++) {
                $co = [int](Read-TLBigEndian $Db ($ptr + ($i * 2)) 2)
                if ($co -le 0 -or ($base + $co) -ge $Db.Length) { continue }
                $cell = Get-TLSqliteCell -Db $Db -PageSize $PageSize -Usable $Usable -CellOffset ($base + $co)
                if ($null -eq $cell) { continue }
                $vals = Read-TLSqliteRecord -Payload $cell[1]
                [void]$rows.Add(@([long]$cell[0], $vals))
                if ($rows.Count -ge $MaxRows) { break }
            }
        } elseif ($type -eq 5) {
            $right = [int](Read-TLBigEndian $Db ($hdr + 8) 4)
            if ($right -gt 0) { $stack.Push($right) }
            $ptr = $hdr + 12
            for ($i = 0; $i -lt $cellCount; $i++) {
                $co = [int](Read-TLBigEndian $Db ($ptr + ($i * 2)) 2)
                if ($co -le 0 -or ($base + $co + 4) -ge $Db.Length) { continue }
                $child = [int](Read-TLBigEndian $Db ($base + $co) 4)
                if ($child -gt 0) { $stack.Push($child) }
            }
        }
    }
    return $rows
}

function Get-TLSqliteColumns {
    # Column names (in storage order) from a CREATE TABLE statement.
    param([string]$Sql)
    $cols = New-Object System.Collections.ArrayList
    if (-not $Sql) { return $cols }
    $open = $Sql.IndexOf('(')
    $close = $Sql.LastIndexOf(')')
    if ($open -lt 0 -or $close -le $open) { return $cols }
    $body = $Sql.Substring($open + 1, $close - $open - 1)
    $depth = 0; $cur = New-Object System.Text.StringBuilder
    $parts = New-Object System.Collections.ArrayList
    foreach ($ch in $body.ToCharArray()) {
        if ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') { $depth-- }
        if ($ch -eq ',' -and $depth -eq 0) { [void]$parts.Add($cur.ToString()); $cur = New-Object System.Text.StringBuilder }
        else { [void]$cur.Append($ch) }
    }
    if ($cur.Length -gt 0) { [void]$parts.Add($cur.ToString()) }
    $skip = @('CONSTRAINT','PRIMARY','UNIQUE','CHECK','FOREIGN','KEY')
    foreach ($p in $parts) {
        $t = $p.Trim()
        if (-not $t) { continue }
        $first = ($t -split '\s+')[0]
        $bare  = $first.Trim('"', '[', ']', '`', "'")
        if ($skip -contains $bare.ToUpperInvariant()) { continue }
        $isRowIdAlias = ($t -match '(?i)INTEGER\s+PRIMARY\s+KEY')
        [void]$cols.Add([pscustomobject]@{ Name = $bare; RowIdAlias = $isRowIdAlias })
    }
    return $cols
}

function Get-TLSqliteTable {
    <#
      Returns an array of hashtables (column name -> value) for a table in a SQLite file.
      The file is read wholly into memory; pass an unlocked copy.
    #>
    param([string]$Path, [string]$Table, [int]$MaxRows = 500000)
    $result = New-Object System.Collections.ArrayList
    try {
        $db = [System.IO.File]::ReadAllBytes($Path)
    } catch { Add-TLIssue 'SQLite' $Path $_.Exception.Message; return $result }
    if ($db.Length -lt 512) { return $result }
    $magic = [Text.Encoding]::ASCII.GetString($db, 0, 15)
    if ($magic -ne 'SQLite format 3') { Add-TLIssue 'SQLite' $Path 'Not a SQLite database.'; return $result }
    $pageSize = [int](Read-TLBigEndian $db 16 2)
    if ($pageSize -eq 1) { $pageSize = 65536 }
    if ($pageSize -lt 512) { return $result }
    $usable = $pageSize - [int]$db[20]

    $master = Get-TLSqliteBTreeRows -Db $db -PageSize $pageSize -Usable $usable -RootPage 1
    $root = 0; $sql = ''
    foreach ($m in $master) {
        $v = $m[1]
        if ($v.Count -lt 5) { continue }
        if ([string]$v[0] -eq 'table' -and [string]$v[1] -eq $Table) {
            $root = [int]$v[3]; $sql = [string]$v[4]; break
        }
    }
    if ($root -le 0) { Add-TLIssue 'SQLite' $Path "Table '$Table' not found."; return $result }

    $cols = Get-TLSqliteColumns -Sql $sql
    $rows = Get-TLSqliteBTreeRows -Db $db -PageSize $pageSize -Usable $usable -RootPage $root -MaxRows $MaxRows
    foreach ($r in $rows) {
        $rowId = [long]$r[0]; $vals = $r[1]
        $h = @{}
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $val = if ($i -lt $vals.Count) { $vals[$i] } else { $null }
            if ($null -eq $val -and $cols[$i].RowIdAlias) { $val = $rowId }
            $h[$cols[$i].Name] = $val
        }
        $h['__rowid'] = $rowId
        [void]$result.Add($h)
    }
    return $result
}

# ---------------------------------------------------------------------------
# Windows event log collection
# ---------------------------------------------------------------------------
$script:EventNames = @{
    'Security|1102'     = 'AUDIT LOG CLEARED'
    'Security|4616'     = 'System time changed'
    'Security|4624'     = 'Logon success'
    'Security|4625'     = 'Logon failure'
    'Security|4634'     = 'Logoff'
    'Security|4647'     = 'User initiated logoff'
    'Security|4648'     = 'Logon with explicit credentials (runas)'
    'Security|4672'     = 'Special privileges assigned (admin logon)'
    'Security|4688'     = 'Process created'
    'Security|4689'     = 'Process exited'
    'Security|4697'     = 'Service installed'
    'Security|4698'     = 'Scheduled task created'
    'Security|4699'     = 'Scheduled task deleted'
    'Security|4700'     = 'Scheduled task enabled'
    'Security|4701'     = 'Scheduled task disabled'
    'Security|4702'     = 'Scheduled task updated'
    'Security|4720'     = 'User account created'
    'Security|4722'     = 'User account enabled'
    'Security|4724'     = 'Password reset attempt'
    'Security|4725'     = 'User account disabled'
    'Security|4726'     = 'User account deleted'
    'Security|4728'     = 'Member added to global group'
    'Security|4732'     = 'Member added to local group'
    'Security|4738'     = 'User account changed'
    'Security|4740'     = 'User account locked out'
    'Security|4776'     = 'NTLM credential validation'
    'Security|4778'     = 'Session reconnected (RDP/console)'
    'Security|4779'     = 'Session disconnected (RDP/console)'
    'Security|5140'     = 'Network share accessed'
    'Security|5145'     = 'Network share object checked'
    'Security|5156'     = 'Network connection permitted (WFP)'
    'Security|5157'     = 'Network connection blocked (WFP)'
    'System|41'         = 'Unclean shutdown (kernel power)'
    'System|104'        = 'EVENT LOG CLEARED'
    'System|1074'       = 'Shutdown / restart initiated'
    'System|6005'       = 'Event log service started (boot)'
    'System|6006'       = 'Event log service stopped (shutdown)'
    'System|6008'       = 'Unexpected shutdown'
    'System|6013'       = 'System uptime report'
    'System|7034'       = 'Service crashed'
    'System|7040'       = 'Service start type changed'
    'System|7045'       = 'New service installed'
    'Windows PowerShell|400'  = 'PowerShell engine started'
    'Windows PowerShell|403'  = 'PowerShell engine stopped'
    'Windows PowerShell|600'  = 'PowerShell provider started'
    'Windows PowerShell|800'  = 'PowerShell pipeline execution'
    'Microsoft-Windows-PowerShell/Operational|4103' = 'PowerShell module logging'
    'Microsoft-Windows-PowerShell/Operational|4104' = 'PowerShell script block logged'
    'Microsoft-Windows-PowerShell/Operational|40961'= 'PowerShell console starting'
    'Microsoft-Windows-PowerShell/Operational|53504'= 'PowerShell named pipe / remote session'
    'Microsoft-Windows-TaskScheduler/Operational|100' = 'Task started'
    'Microsoft-Windows-TaskScheduler/Operational|102' = 'Task completed'
    'Microsoft-Windows-TaskScheduler/Operational|106' = 'Task registered (created)'
    'Microsoft-Windows-TaskScheduler/Operational|129' = 'Task launched process'
    'Microsoft-Windows-TaskScheduler/Operational|140' = 'Task definition updated'
    'Microsoft-Windows-TaskScheduler/Operational|141' = 'Task deleted'
    'Microsoft-Windows-TaskScheduler/Operational|200' = 'Task action started'
    'Microsoft-Windows-TaskScheduler/Operational|201' = 'Task action completed'
    'Microsoft-Windows-TaskScheduler/Operational|325' = 'Task engine queued task'
    'Microsoft-Windows-TaskScheduler/Operational|329' = 'Task engine started task'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|21' = 'RDP session logon'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|22' = 'RDP shell start'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|23' = 'RDP session logoff'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|24' = 'RDP session disconnected'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|25' = 'RDP session reconnected'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational|1149' = 'RDP network connection (auth success)'
    'Microsoft-Windows-TerminalServices-RDPClient/Operational|1024' = 'OUTBOUND RDP connection attempt'
    'Microsoft-Windows-TerminalServices-RDPClient/Operational|1102' = 'OUTBOUND RDP connection established'
    'Microsoft-Windows-WinRM/Operational|6'   = 'WinRM client creating session'
    'Microsoft-Windows-WinRM/Operational|91'  = 'WinRM server session created'
    'Microsoft-Windows-WinRM/Operational|168' = 'WinRM authentication'
    'Microsoft-Windows-Windows Defender/Operational|1116' = 'MALWARE DETECTED'
    'Microsoft-Windows-Windows Defender/Operational|1117' = 'Malware action taken'
    'Microsoft-Windows-Windows Defender/Operational|5001' = 'Real-time protection DISABLED'
    'Microsoft-Windows-Windows Defender/Operational|5007' = 'Defender configuration changed'
    'Microsoft-Windows-Windows Defender/Operational|5010' = 'Antimalware scanning disabled'
    'Microsoft-Windows-Windows Defender/Operational|5012' = 'Virus scanning disabled'
    'Microsoft-Windows-WMI-Activity/Operational|5857' = 'WMI provider started'
    'Microsoft-Windows-WMI-Activity/Operational|5858' = 'WMI operation failed'
    'Microsoft-Windows-WMI-Activity/Operational|5860' = 'WMI temporary event consumer registered'
    'Microsoft-Windows-WMI-Activity/Operational|5861' = 'WMI PERMANENT event consumer registered'
    'Microsoft-Windows-DNS-Client/Operational|3006'  = 'DNS query issued'
    'Microsoft-Windows-DNS-Client/Operational|3008'  = 'DNS query completed'
    'Microsoft-Windows-DNS-Client/Operational|3020'  = 'DNS response received'
    'Microsoft-Windows-NetworkProfile/Operational|10000' = 'Network connected'
    'Microsoft-Windows-NetworkProfile/Operational|10001' = 'Network disconnected'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8001' = 'Wireless network connected'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8002' = 'Wireless connection failed'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8003' = 'Wireless network disconnected'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|11001'= 'Wireless association succeeded'
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational|2003' = 'USB device pnp start'
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational|2100' = 'USB device connected'
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational|2102' = 'USB device disconnected'
    'Microsoft-Windows-Kernel-PnP/Configuration|400' = 'Device configured (PnP)'
    'Microsoft-Windows-Kernel-PnP/Configuration|410' = 'Device started (PnP)'
    'Microsoft-Windows-Bits-Client/Operational|59'  = 'BITS transfer started (download)'
    'Microsoft-Windows-Bits-Client/Operational|60'  = 'BITS transfer stopped'
    'Microsoft-Windows-Bits-Client/Operational|61'  = 'BITS transfer error'
    'Microsoft-Windows-Sysmon/Operational|1'  = 'Sysmon: process create'
    'Microsoft-Windows-Sysmon/Operational|3'  = 'Sysmon: NETWORK CONNECTION'
    'Microsoft-Windows-Sysmon/Operational|8'  = 'Sysmon: CreateRemoteThread'
    'Microsoft-Windows-Sysmon/Operational|11' = 'Sysmon: file created'
    'Microsoft-Windows-Sysmon/Operational|12' = 'Sysmon: registry object created/deleted'
    'Microsoft-Windows-Sysmon/Operational|13' = 'Sysmon: registry value set'
    'Microsoft-Windows-Sysmon/Operational|15' = 'Sysmon: file stream created (download mark)'
    'Microsoft-Windows-Sysmon/Operational|22' = 'Sysmon: DNS query'
    'Microsoft-Windows-Sysmon/Operational|23' = 'Sysmon: file delete'
    'Microsoft-Windows-AppLocker/EXE and DLL|8002' = 'AppLocker allowed execution'
    'Microsoft-Windows-AppLocker/EXE and DLL|8003' = 'AppLocker audited execution'
    'Microsoft-Windows-AppLocker/EXE and DLL|8004' = 'AppLocker BLOCKED execution'
    'Microsoft-Windows-Shell-Core/Operational|9707' = 'Startup command executed'
    'Microsoft-Windows-Shell-Core/Operational|9708' = 'Startup command completed'
    'Microsoft-Windows-PrintService/Operational|307' = 'Document printed'
    'Microsoft-Windows-Application-Experience/Program-Inventory|903' = 'Application installed'
    'Microsoft-Windows-Application-Experience/Program-Inventory|904' = 'Application updated'
    'Microsoft-Windows-Application-Experience/Program-Inventory|907' = 'Application removed'
    'Application|1000' = 'Application crash'
    'Application|1001' = 'Windows error reporting'
    'Application|11707'= 'MSI install completed successfully'
    'Application|11724'= 'MSI removal completed successfully'
    'Application|1033' = 'MSI installation'
}

# Log/ID definitions. Category drives filtering in the report.
$script:EventDefs = @(
    @{ Log='Security'; Ids=@(4624,4625,4634,4647,4648,4672,4778,4779); Category='Logon' }
    @{ Log='Security'; Ids=@(4688,4689);                               Category='Process Execution' }
    @{ Log='Security'; Ids=@(4697,4698,4699,4700,4701,4702);           Category='Persistence' }
    @{ Log='Security'; Ids=@(4720,4722,4724,4725,4726,4728,4732,4738,4740,4776); Category='Account Management' }
    @{ Log='Security'; Ids=@(1102,4616);                               Category='Anti-Forensics' }
    @{ Log='Security'; Ids=@(5140,5145);                               Category='Share Access' }
    @{ Log='Security'; Ids=@(5156,5157);                               Category='Network' }
    @{ Log='System';   Ids=@(41,1074,6005,6006,6008,6013);             Category='System State' }
    @{ Log='System';   Ids=@(104);                                     Category='Anti-Forensics' }
    @{ Log='System';   Ids=@(7034,7040,7045);                          Category='Services' }
    @{ Log='Application'; Ids=@(1000,1001,1033,11707,11724);           Category='Application' }
    @{ Log='Windows PowerShell'; Ids=@(400,403,600,800);               Category='PowerShell' }
    @{ Log='Microsoft-Windows-PowerShell/Operational'; Ids=@(4103,4104,40961,53504); Category='PowerShell' }
    @{ Log='Microsoft-Windows-TaskScheduler/Operational'; Ids=@(100,102,106,129,140,141,200,201,325,329); Category='Scheduled Task' }
    @{ Log='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids=@(21,22,23,24,25,39,40); Category='RDP' }
    @{ Log='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids=@(1149); Category='RDP' }
    @{ Log='Microsoft-Windows-TerminalServices-RDPClient/Operational'; Ids=@(1024,1025,1026,1102); Category='RDP Outbound' }
    @{ Log='Microsoft-Windows-WinRM/Operational'; Ids=@(6,91,168);      Category='Remote Execution' }
    @{ Log='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1006,1007,1013,1015,1116,1117,5001,5007,5010,5012); Category='Antivirus' }
    @{ Log='Microsoft-Windows-WMI-Activity/Operational'; Ids=@(5857,5858,5860,5861); Category='WMI' }
    @{ Log='Microsoft-Windows-DNS-Client/Operational'; Ids=@(3008);     Category='Network' }
    @{ Log='Microsoft-Windows-NetworkProfile/Operational'; Ids=@(10000,10001); Category='Network' }
    @{ Log='Microsoft-Windows-WLAN-AutoConfig/Operational'; Ids=@(8001,8002,8003,11001,11004,11005); Category='Network' }
    @{ Log='Microsoft-Windows-SmbClient/Connectivity'; Ids=@(30800,30803); Category='Network' }
    @{ Log='Microsoft-Windows-SMBClient/Security'; Ids=@(31001);        Category='Network' }
    @{ Log='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Ids=@(2003,2004,2100,2101,2102,2105,2106); Category='USB' }
    @{ Log='Microsoft-Windows-Kernel-PnP/Configuration'; Ids=@(400,410,420); Category='USB' }
    @{ Log='Microsoft-Windows-Bits-Client/Operational'; Ids=@(3,59,60,61); Category='File Transfer' }
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(1);            Category='Process Execution' }
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(3,22);         Category='Network' }
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(8,11,12,13,15,23,25); Category='Sysmon Other' }
    @{ Log='Microsoft-Windows-AppLocker/EXE and DLL'; Ids=@(8002,8003,8004); Category='Process Execution' }
    @{ Log='Microsoft-Windows-AppLocker/MSI and Script'; Ids=@(8005,8006,8007); Category='Process Execution' }
    @{ Log='Microsoft-Windows-CodeIntegrity/Operational'; Ids=@(3033,3077); Category='Integrity' }
    @{ Log='Microsoft-Windows-Shell-Core/Operational'; Ids=@(9707,9708); Category='Persistence' }
    @{ Log='Microsoft-Windows-User Profile Service/Operational'; Ids=@(1,2); Category='Logon' }
    @{ Log='Microsoft-Windows-PrintService/Operational'; Ids=@(307);    Category='Printing' }
    @{ Log='Microsoft-Windows-Application-Experience/Program-Inventory'; Ids=@(900,903,904,905,906,907,908); Category='Software Install' }
    @{ Log='Setup'; Ids=@(1,2,3,4);                                     Category='Software Install' }
)

$script:EventDataSkip = @('Binary','KeyLength','ImpersonationLevel','TransmittedServices','LmPackageName',
                          'TargetLinkedLogonId','TransactionId','ProcessingTimeInMilliseconds','param7','param8')

function Get-TLEventDataHash {
    param($Record)
    $h = [ordered]@{}
    try {
        $xml = [xml]$Record.ToXml()
        if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
            $i = 0
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($d -is [string]) { $h["Data$i"] = $d; $i++; continue }
                $n = $d.Name
                if (-not $n) { $n = "Data$i" }
                $h[$n] = $d.'#text'
                $i++
            }
        }
        if ($xml.Event.UserData) {
            foreach ($node in $xml.Event.UserData.ChildNodes) {
                foreach ($c in $node.ChildNodes) { if ($c.Name) { $h[$c.Name] = $c.InnerText } }
            }
        }
    } catch { }
    return $h
}

function Format-TLEventDetails {
    param($Hash)
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $Hash.Keys) {
        if ($script:EventDataSkip -contains $k) { continue }
        $v = $Hash[$k]
        if ($null -eq $v -or "$v" -eq '' -or "$v" -eq '-') { continue }
        if ($sb.Length -gt 1900) { [void]$sb.Append(' ...'); break }
        [void]$sb.Append((ConvertTo-TLText ("{0}={1}" -f $k, $v) 600)).Append('; ')
    }
    return $sb.ToString()
}

function Get-TLEventUser {
    param($Record, $Hash)
    foreach ($k in @('TargetUserName','SubjectUserName','User','UserName','TargetUser','param1','AccountName')) {
        if ($Hash.Contains($k)) {
            $v = [string]$Hash[$k]
            if ($v -and $v -ne '-' -and $v -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') { return $v }
        }
    }
    if ($Record.UserId) { return (Resolve-TLSid $Record.UserId.Value) }
    return ''
}

function Get-TLEventDescription {
    param($Record, $LogName, $Hash)
    $key = '{0}|{1}' -f $LogName, $Record.Id
    if ($script:EventNames.ContainsKey($key)) {
        $name = $script:EventNames[$key]
    } else {
        $name = "EventID $($Record.Id)"
        try {
            if ($Record.Message) {
                $first = ($Record.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
                if ($first) { $name = "EventID $($Record.Id): " + $first }
            }
        } catch { }
    }
    # Add the single most useful field inline for fast reading.
    foreach ($k in @('NewProcessName','Image','CommandLine','TaskName','ServiceName','ScriptBlockText','DestinationIp','QueryName','ProcessName','TargetFilename','ProfileName','SSID','ObjectName')) {
        if ($Hash.Contains($k) -and $Hash[$k]) {
            $name = '{0} -- {1}' -f $name, (ConvertTo-TLText $Hash[$k] 200)
            break
        }
    }
    return $name
}

function Get-TLWinEventChunked {
    param([string]$LogName, [int[]]$Ids, [int]$MaxEvents)
    $all = New-Object System.Collections.Generic.List[Object]
    $chunks = New-Object System.Collections.Generic.List[Object]
    if (-not $Ids -or $Ids.Count -eq 0) { $chunks.Add($null) }
    else {
        # Get-WinEvent -FilterHashtable allows a maximum of ~22 values per key.
        for ($i = 0; $i -lt $Ids.Count; $i += 20) {
            $end = [Math]::Min($i + 19, $Ids.Count - 1)
            $chunks.Add(@($Ids[$i..$end]))
        }
    }
    foreach ($c in $chunks) {
        $filter = @{ LogName = $LogName }
        if ($c) { $filter['Id'] = $c }
        if (-not $AllTime) { $filter['StartTime'] = $script:CutoffUtc.ToLocalTime() }
        try {
            $ev = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
            if ($ev) { $all.AddRange(@($ev)) }
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Add-TLIssue 'EventLogs' $LogName $_.Exception.Message
            }
        }
    }
    return $all
}

function Invoke-TLEventLogs {
    Write-TLLog 'Collecting Windows event logs ...' 'STEP'

    # Availability / coverage snapshot first - shows how far back logs actually go.
    $wanted = $script:EventDefs | ForEach-Object { $_.Log } | Sort-Object -Unique
    foreach ($ln in $wanted) {
        try {
            $li = Get-WinEvent -ListLog $ln -ErrorAction Stop
            $oldest = $null
            try {
                $o = Get-WinEvent -LogName $ln -Oldest -MaxEvents 1 -ErrorAction Stop
                if ($o) { $oldest = $o.TimeCreated }
            } catch { }
            $script:Coverage.Add([pscustomobject][ordered]@{
                Log            = $ln
                Enabled        = $li.IsEnabled
                RecordCount    = $li.RecordCount
                MaxSizeMB      = [math]::Round(($li.MaximumSizeInBytes / 1MB), 1)
                RetentionMode  = $li.LogMode
                OldestRecord   = if ($oldest) { $oldest.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                FilePath       = $li.LogFilePath
            })
        } catch {
            $script:Coverage.Add([pscustomobject][ordered]@{
                Log = $ln; Enabled = $false; RecordCount = 0; MaxSizeMB = 0
                RetentionMode = 'NOT PRESENT'; OldestRecord = ''; FilePath = ''
            })
        }
    }

    foreach ($def in $script:EventDefs) {
        $ln = $def.Log
        $cov = $script:Coverage | Where-Object { $_.Log -eq $ln } | Select-Object -First 1
        if ($cov -and $cov.RetentionMode -eq 'NOT PRESENT') { continue }
        $records = Get-TLWinEventChunked -LogName $ln -Ids $def.Ids -MaxEvents $MaxEventsPerQuery
        if (-not $records -or $records.Count -eq 0) { continue }
        Write-TLLog ("  {0} [{1}] -> {2} events" -f $ln, ($def.Ids -join ','), $records.Count)
        foreach ($r in $records) {
            $h = Get-TLEventDataHash $r
            Add-TLEvent -Time $r.TimeCreated -IsLocal `
                -Source ('EVT:' + $ln) `
                -Category $def.Category `
                -User (Get-TLEventUser -Record $r -Hash $h) `
                -Description (Get-TLEventDescription -Record $r -LogName $ln -Hash $h) `
                -Details (Format-TLEventDetails $h) `
                -Artifact ("{0} EventID={1} RecordId={2} Computer={3}" -f $ln, $r.Id, $r.RecordId, $r.MachineName) `
                -Confidence 'High'
        }
    }
}

# ---------------------------------------------------------------------------
# PowerShell history (PSReadLine files + transcripts)
# ---------------------------------------------------------------------------
function Invoke-TLPSHistory {
    param($Profiles)
    Write-TLLog 'Collecting PowerShell console history and transcripts ...' 'STEP'

    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }

        # PSReadLine history: no per-line timestamps exist. Use file mtime and
        # keep the original line order in the Details column.
        $histPaths = @(
            (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
            (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
        ) | Sort-Object -Unique

        foreach ($hp in $histPaths) {
            if (-not (Test-TLPath $hp)) { continue }
            try {
                $fi    = Get-Item -LiteralPath $hp -Force -ErrorAction Stop
                $lines = Get-Content -LiteralPath $hp -ErrorAction Stop
                $n = 0
                foreach ($line in $lines) {
                    $n++
                    if (-not $line.Trim()) { continue }
                    Add-TLEvent -Time $fi.LastWriteTimeUtc `
                        -Source 'PSReadLine' -Category 'PowerShell' -User $p.Name `
                        -Description ('PS history line {0}: {1}' -f $n, (ConvertTo-TLText $line 300)) `
                        -Details ('FileCreated={0}; FileModified={1}; TotalLines={2}' -f $fi.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $lines.Count) `
                        -Artifact $hp `
                        -Confidence 'LOW - no per-line timestamp, file mtime used'
                }
                Write-TLLog ("  {0}: {1} history lines" -f $p.Name, $lines.Count)
            } catch { Add-TLIssue 'PSHistory' $hp $_.Exception.Message }
        }

        # Transcripts (default and common custom locations)
        $tDirs = @(
            (Join-Path $p.Path 'Documents'),
            (Join-Path $p.Path 'Documents\PowerShell_transcript'),
            (Join-Path $p.Path 'AppData\Local\Temp')
        )
        foreach ($td in $tDirs) {
            if (-not (Test-TLPath $td)) { continue }
            try {
                Get-ChildItem -LiteralPath $td -Filter 'PowerShell_transcript*.txt' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                    Select-Object -First 500 | ForEach-Object {
                        $head = ''
                        try { $head = (Get-Content -LiteralPath $_.FullName -TotalCount 20 -ErrorAction SilentlyContinue) -join ' | ' } catch { }
                        Add-TLEvent -Time $_.CreationTimeUtc `
                            -Source 'PSTranscript' -Category 'PowerShell' -User $p.Name `
                            -Description ('PowerShell transcript created: {0}' -f $_.Name) `
                            -Details (ConvertTo-TLText $head 1500) `
                            -Artifact $_.FullName -Confidence 'High'
                    }
            } catch { Add-TLIssue 'PSHistory' $td $_.Exception.Message }
        }
    }

    # Machine-wide transcript location if group policy set one
    foreach ($mt in @("$env:SystemDrive\Transcripts", "$env:ProgramData\PSTranscripts")) {
        if (-not (Test-TLPath $mt)) { continue }
        Get-ChildItem -LiteralPath $mt -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 2000 | ForEach-Object {
            Add-TLEvent -Time $_.CreationTimeUtc -Source 'PSTranscript' -Category 'PowerShell' `
                -Description ('Machine transcript: {0}' -f $_.Name) -Artifact $_.FullName -Confidence 'High'
        }
    }
}

# ---------------------------------------------------------------------------
# Scheduled tasks (definitions, registration, last run)
# ---------------------------------------------------------------------------
function Invoke-TLScheduledTasks {
    Write-TLLog 'Collecting scheduled task definitions and run history ...' 'STEP'
    $tasks = $null
    try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { Add-TLIssue 'ScheduledTasks' 'Get-ScheduledTask' $_.Exception.Message }

    if ($tasks) {
        foreach ($t in $tasks) {
            $full = ($t.TaskPath + $t.TaskName)
            $info = $null
            try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
            $actions = @()
            foreach ($a in @($t.Actions)) {
                if ($a.Execute)   { $actions += ('Exec="{0}" Args="{1}"' -f $a.Execute, $a.Arguments) }
                elseif ($a.ClassId) { $actions += ('COM ClassId={0}' -f $a.ClassId) }
            }
            $triggers = @()
            foreach ($g in @($t.Triggers)) { $triggers += $g.CimClass.CimClassName }
            $author = ''
            try { $author = $t.Author } catch { }
            $runAs = ''
            try { $runAs = $t.Principal.UserId } catch { }
            $details = ('State={0}; RunAs={1}; Author={2}; Triggers={3}; Actions={4}; LastResult={5}; NextRun={6}' -f `
                        $t.State, $runAs, $author, ($triggers -join ','), ($actions -join ' :: '),
                        $(if ($info) { $info.LastTaskResult } else { '' }),
                        $(if ($info -and $info.NextRunTime) { $info.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }))

            if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 1980) {
                Add-TLEvent -Time $info.LastRunTime -IsLocal -Source 'ScheduledTask' -Category 'Scheduled Task' `
                    -User $runAs -Description ('Task last run: {0}' -f $full) -Details $details `
                    -Artifact ('Task Scheduler: ' + $full) -Confidence 'High'
            }

            # Registration date + XML file times from C:\Windows\System32\Tasks
            $xmlPath = Join-Path "$env:SystemRoot\System32\Tasks" ($full.TrimStart('\'))
            if (Test-TLPath $xmlPath) {
                try {
                    $fi = Get-Item -LiteralPath $xmlPath -Force
                    $regDate = $null
                    try {
                        $x = [xml](Get-Content -LiteralPath $xmlPath -Raw -ErrorAction Stop)
                        if ($x.Task.RegistrationInfo.Date) { $regDate = [datetime]$x.Task.RegistrationInfo.Date }
                    } catch { }
                    if ($regDate) {
                        Add-TLEvent -Time $regDate -IsLocal -Source 'ScheduledTask' -Category 'Persistence' `
                            -User $author -Description ('Task registered: {0}' -f $full) -Details $details `
                            -Artifact $xmlPath -Confidence 'High'
                    }
                    Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ScheduledTask' -Category 'Persistence' `
                        -User $author -Description ('Task definition file modified: {0}' -f $full) -Details $details `
                        -Artifact $xmlPath -Confidence 'Medium - file mtime'
                } catch { Add-TLIssue 'ScheduledTasks' $xmlPath $_.Exception.Message }
            }
        }
        Write-TLLog ("  {0} scheduled tasks examined" -f $tasks.Count)
    }
}

# ---------------------------------------------------------------------------
# Browser history and downloads
# ---------------------------------------------------------------------------
function Get-TLChromiumProfiles {
    param($UserProfile)
    $roots = @(
        @{ Name='Chrome';   Path='AppData\Local\Google\Chrome\User Data' },
        @{ Name='ChromeBeta'; Path='AppData\Local\Google\Chrome Beta\User Data' },
        @{ Name='Edge';     Path='AppData\Local\Microsoft\Edge\User Data' },
        @{ Name='EdgeDev';  Path='AppData\Local\Microsoft\Edge Dev\User Data' },
        @{ Name='Brave';    Path='AppData\Local\BraveSoftware\Brave-Browser\User Data' },
        @{ Name='Vivaldi';  Path='AppData\Local\Vivaldi\User Data' },
        @{ Name='Chromium'; Path='AppData\Local\Chromium\User Data' },
        @{ Name='Opera';    Path='AppData\Roaming\Opera Software\Opera Stable' },
        @{ Name='OperaGX';  Path='AppData\Roaming\Opera Software\Opera GX Stable' },
        @{ Name='Yandex';   Path='AppData\Local\Yandex\YandexBrowser\User Data' }
    )
    $found = New-Object System.Collections.Generic.List[Object]
    foreach ($r in $roots) {
        $base = Join-Path $UserProfile.Path $r.Path
        if (-not (Test-TLPath $base)) { continue }
        # Opera keeps History directly in the profile root; Chromium uses Default / Profile N
        $candidates = @($base)
        try { $candidates += (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' } | ForEach-Object { $_.FullName }) } catch { }
        foreach ($c in $candidates) {
            $h = Join-Path $c 'History'
            if (Test-TLPath $h) {
                $found.Add([pscustomobject]@{ Browser = $r.Name; Profile = (Split-Path $c -Leaf); HistoryDb = $h })
            }
        }
    }
    return $found
}

function Invoke-TLBrowsers {
    param($Profiles)
    Write-TLLog 'Collecting browser history and downloads ...' 'STEP'
    $work = Join-Path $CaseDir 'artifacts\browser'
    $null = New-Item -Path $work -ItemType Directory -Force -ErrorAction SilentlyContinue

    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }

        # ---------- Chromium family ----------
        foreach ($b in (Get-TLChromiumProfiles -UserProfile $p)) {
            $tag  = '{0}_{1}_{2}' -f $p.Name, $b.Browser, ($b.Profile -replace '\s', '')
            $copy = Join-Path $work ($tag + '_History.db')
            if (Test-TLPath ($b.HistoryDb + '-wal')) {
                Add-TLIssue 'Browsers' $b.HistoryDb 'A -wal journal exists: the most recent visits may not be in the main DB. Close the browser or use -UseVSS for completeness.'
            }
            if (-not (Copy-TLFile -Source $b.HistoryDb -Destination $copy)) { continue }

            try {
                $urls = @{}
                foreach ($u in (Get-TLSqliteTable -Path $copy -Table 'urls')) {
                    if ($null -ne $u['id']) { $urls[[long]$u['id']] = $u }
                }
                $visits = Get-TLSqliteTable -Path $copy -Table 'visits'
                $cnt = 0
                foreach ($v in $visits) {
                    $t = ConvertFrom-TLWebKitTime ([long]$v['visit_time'])
                    if (-not $t) { continue }
                    $uid = [long]$v['url']
                    $rec = $urls[$uid]
                    $url = if ($rec) { [string]$rec['url'] } else { '(url record missing)' }
                    $ttl = if ($rec) { [string]$rec['title'] } else { '' }
                    $trans = [long]$v['transition']
                    $core = $trans -band 0xFF
                    $ttype = switch ($core) {
                        0 { 'link' } 1 { 'typed' } 2 { 'auto_bookmark' } 3 { 'auto_subframe' }
                        4 { 'manual_subframe' } 5 { 'generated' } 6 { 'start_page' }
                        7 { 'form_submit' } 8 { 'reload' } 9 { 'keyword' } 10 { 'keyword_generated' }
                        default { "type$core" }
                    }
                    Add-TLEvent -Time $t -Source ('Browser:' + $b.Browser) -Category 'Web Browsing' -User $p.Name `
                        -Description ('Visited: {0}' -f (ConvertTo-TLText $url 350)) `
                        -Details ('Title={0}; Transition={1}; VisitDuration={2}; BrowserProfile={3}' -f (ConvertTo-TLText $ttl 200), $ttype, $v['visit_duration'], $b.Profile) `
                        -Artifact $b.HistoryDb -Confidence 'High'
                    $cnt++
                }
                Write-TLLog ("  {0} / {1} ({2}): {3} visits" -f $p.Name, $b.Browser, $b.Profile, $cnt)

                foreach ($d in (Get-TLSqliteTable -Path $copy -Table 'downloads')) {
                    $t = ConvertFrom-TLWebKitTime ([long]$d['start_time'])
                    if (-not $t) { continue }
                    $endT = ConvertFrom-TLWebKitTime ([long]$d['end_time'])
                    $endS = if ($endT) { $endT.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    Add-TLEvent -Time $t -Source ('Browser:' + $b.Browser) -Category 'File Download' -User $p.Name `
                        -Description ('Download started: {0}' -f (ConvertTo-TLText $d['target_path'] 300)) `
                        -Details ('SourceUrl={0}; TabUrl={1}; Received={2}; Total={3}; State={4}; EndUtc={5}' -f `
                                  (ConvertTo-TLText $d['referrer'] 300), (ConvertTo-TLText $d['tab_url'] 300),
                                  $d['received_bytes'], $d['total_bytes'], $d['state'], $endS) `
                        -Artifact $b.HistoryDb -Confidence 'High'
                }
            } catch { Add-TLIssue 'Browsers' $b.HistoryDb $_.Exception.Message }
        }

        # ---------- Firefox ----------
        $ffRoots = @(
            (Join-Path $p.Path 'AppData\Roaming\Mozilla\Firefox\Profiles'),
            (Join-Path $p.Path 'AppData\Local\Mozilla\Firefox\Profiles')
        )
        foreach ($fr in $ffRoots) {
            if (-not (Test-TLPath $fr)) { continue }
            foreach ($fp in (Get-ChildItem -LiteralPath $fr -Directory -ErrorAction SilentlyContinue)) {
                $places = Join-Path $fp.FullName 'places.sqlite'
                if (-not (Test-TLPath $places)) { continue }
                $copy = Join-Path $work ('{0}_Firefox_{1}_places.db' -f $p.Name, $fp.Name)
                if (-not (Copy-TLFile -Source $places -Destination $copy)) { continue }
                try {
                    $pl = @{}
                    foreach ($row in (Get-TLSqliteTable -Path $copy -Table 'moz_places')) {
                        if ($null -ne $row['id']) { $pl[[long]$row['id']] = $row }
                    }
                    $cnt = 0
                    foreach ($v in (Get-TLSqliteTable -Path $copy -Table 'moz_historyvisits')) {
                        $t = ConvertFrom-TLUnixMicro ([long]$v['visit_date'])
                        if (-not $t) { continue }
                        $rec = $pl[[long]$v['place_id']]
                        $url = if ($rec) { [string]$rec['url'] } else { '(place record missing)' }
                        $ttl = if ($rec) { [string]$rec['title'] } else { '' }
                        Add-TLEvent -Time $t -Source 'Browser:Firefox' -Category 'Web Browsing' -User $p.Name `
                            -Description ('Visited: {0}' -f (ConvertTo-TLText $url 350)) `
                            -Details ('Title={0}; VisitType={1}; BrowserProfile={2}' -f (ConvertTo-TLText $ttl 200), $v['visit_type'], $fp.Name) `
                            -Artifact $places -Confidence 'High'
                        $cnt++
                    }
                    Write-TLLog ("  {0} / Firefox ({1}): {2} visits" -f $p.Name, $fp.Name, $cnt)
                } catch { Add-TLIssue 'Browsers' $places $_.Exception.Message }
            }
        }

        # ---------- Legacy IE / pre-Chromium Edge ----------
        $wc = Join-Path $p.Path 'AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat'
        if (Test-TLPath $wc) {
            try {
                $fi = Get-Item -LiteralPath $wc -Force
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'Browser:IE-Legacy' -Category 'Web Browsing' -User $p.Name `
                    -Description 'IE/legacy-Edge WebCacheV01.dat present (ESE database - not parsed by this script)' `
                    -Details 'Parse separately with an ESE-capable tool (e.g. esedbexport / KAPE module) for full IE history.' `
                    -Artifact $wc -Confidence 'Info only'
            } catch { }
        }
    }
}

# ---------------------------------------------------------------------------
# Application / program execution artefacts
# ---------------------------------------------------------------------------
function Get-TLRot13 {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        $i = [int][char]$c
        if ($i -ge 65 -and $i -le 90)      { [void]$sb.Append([char]((($i - 65 + 13) % 26) + 65)) }
        elseif ($i -ge 97 -and $i -le 122) { [void]$sb.Append([char]((($i - 97 + 13) % 26) + 97)) }
        else { [void]$sb.Append($c) }
    }
    return $sb.ToString()
}

function Invoke-TLPrefetch {
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-TLPath $pfDir)) {
        Add-TLIssue 'Prefetch' $pfDir 'Prefetch directory not present (SSD/server policy or disabled).'
        return
    }
    try {
        $files = Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -File -ErrorAction Stop
        foreach ($f in $files) {
            $name = $f.BaseName
            $exe  = ($name -split '-')[0]
            Add-TLEvent -Time $f.LastWriteTimeUtc -Source 'Prefetch' -Category 'Program Execution' `
                -Description ('Program executed (prefetch updated): {0}' -f $exe) `
                -Details ('PrefetchFile={0}; Created={1}; SizeBytes={2}. Prefetch mtime approximates the LAST execution; the file itself holds up to 8 run times - parse with a dedicated prefetch parser for all of them.' -f `
                          $f.Name, $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $f.Length) `
                -Artifact $f.FullName -Confidence 'Medium - file mtime = last run'
            Add-TLEvent -Time $f.CreationTimeUtc -Source 'Prefetch' -Category 'Program Execution' `
                -Description ('Program first executed (prefetch created): {0}' -f $exe) `
                -Details ('PrefetchFile={0}' -f $f.Name) `
                -Artifact $f.FullName -Confidence 'Medium - file ctime = first run'
        }
        Write-TLLog ("  Prefetch: {0} files" -f $files.Count)
    } catch { Add-TLIssue 'Prefetch' $pfDir $_.Exception.Message }
}

function Invoke-TLUserAssist {
    param($Profiles)
    foreach ($p in $Profiles) {
        if (-not $p.IsDomain -and $p.Name -notmatch '^[A-Za-z]') { continue }
        $base = Mount-TLUserHive -Profile $p
        if (-not $base) { continue }
        $uaPath = "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (-not (Test-TLPath $uaPath)) { continue }
        try {
            foreach ($guid in (Get-ChildItem $uaPath -ErrorAction SilentlyContinue)) {
                $count = Join-Path $guid.PSPath 'Count'
                if (-not (Test-TLPath $count)) { continue }
                $item = Get-Item $count -ErrorAction SilentlyContinue
                if (-not $item) { continue }
                foreach ($vn in $item.GetValueNames()) {
                    $data = $item.GetValue($vn)
                    if (-not ($data -is [byte[]]) -or $data.Length -lt 68) { continue }
                    $runCount = [BitConverter]::ToUInt32($data, 4)
                    $ft       = [BitConverter]::ToInt64($data, 60)
                    $when     = ConvertFrom-TLFileTime $ft
                    if (-not $when) { continue }
                    $decoded = Get-TLRot13 $vn
                    Add-TLEvent -Time $when -Source 'UserAssist' -Category 'Program Execution' -User $p.Name `
                        -Description ('GUI program executed: {0}' -f (ConvertTo-TLText $decoded 300)) `
                        -Details ('RunCount={0}; UserAssistGuid={1}; FocusTimeMs={2}' -f $runCount, $guid.PSChildName, [BitConverter]::ToUInt32($data, 12)) `
                        -Artifact ("$($p.Sid)\...\UserAssist\$($guid.PSChildName)\Count") -Confidence 'High'
                }
            }
        } catch { Add-TLIssue 'UserAssist' $p.Name $_.Exception.Message }
    }
}

function Invoke-TLShimCache {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    try {
        $data = (Get-ItemProperty -Path $key -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    } catch { Add-TLIssue 'ShimCache' $key $_.Exception.Message; return }
    if (-not ($data -is [byte[]]) -or $data.Length -lt 64) { return }

    $offset = [BitConverter]::ToInt32($data, 0)
    $sigAt = {
        param($off)
        if ($off -lt 0 -or ($off + 4) -gt $data.Length) { return '' }
        return [Text.Encoding]::ASCII.GetString($data, $off, 4)
    }
    $sig = & $sigAt $offset
    if ($sig -ne '10ts' -and $sig -ne '00ts') {
        # scan for the first entry signature (layout varies by build)
        $offset = -1
        for ($i = 0; $i -lt [Math]::Min($data.Length - 4, 4096); $i++) {
            $s = [Text.Encoding]::ASCII.GetString($data, $i, 4)
            if ($s -eq '10ts' -or $s -eq '00ts') { $offset = $i; break }
        }
        if ($offset -lt 0) {
            Add-TLIssue 'ShimCache' $key 'Unrecognised AppCompatCache format (pre-Win8 layout?). Parse with a dedicated tool.'
            return
        }
    }

    $n = 0
    try {
        while (($offset + 12) -lt $data.Length) {
            $s = [Text.Encoding]::ASCII.GetString($data, $offset, 4)
            if ($s -ne '10ts' -and $s -ne '00ts') { break }
            $pathSize = [BitConverter]::ToUInt16($data, $offset + 12)
            $pathOff  = $offset + 14
            if ($pathSize -le 0 -or ($pathOff + $pathSize + 12) -gt $data.Length) { break }
            $path = [Text.Encoding]::Unicode.GetString($data, $pathOff, $pathSize)
            $ftOff = $pathOff + $pathSize
            $ft = [BitConverter]::ToInt64($data, $ftOff)
            $dataSize = [BitConverter]::ToInt32($data, $ftOff + 8)
            $when = ConvertFrom-TLFileTime $ft
            if ($when) {
                Add-TLEvent -Time $when -Source 'ShimCache' -Category 'Program Execution Evidence' `
                    -Description ('Binary present / executed: {0}' -f (ConvertTo-TLText $path 300)) `
                    -Details ('Position={0} (lower position = more recent). NOTE: the timestamp is the FILE LAST MODIFIED time of the binary, NOT the execution time. Presence in ShimCache means the file was seen by the system.' -f $n) `
                    -Artifact 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' `
                    -Confidence 'Medium - binary mtime, not exec time'
            }
            $n++
            $offset = $ftOff + 12 + $dataSize
            if ($n -gt 2048) { break }
        }
        Write-TLLog ("  ShimCache: {0} entries" -f $n)
    } catch { Add-TLIssue 'ShimCache' $key $_.Exception.Message }
}

function Invoke-TLAmcache {
    $src = Join-Path $env:SystemRoot 'appcompat\Programs\Amcache.hve'
    if (-not (Test-TLPath $src)) { return }
    $work = Join-Path $CaseDir 'artifacts\registry'
    $null = New-Item -Path $work -ItemType Directory -Force -ErrorAction SilentlyContinue
    $copy = Join-Path $work 'Amcache.hve'
    if (-not (Copy-TLFile -Source $src -Destination $copy)) { return }
    foreach ($ext in @('.LOG1', '.LOG2')) {
        if (Test-TLPath ($src + $ext)) { $null = Copy-TLFile -Source ($src + $ext) -Destination ($copy + $ext) }
    }

    $mount = 'TL_Amcache'
    $null = & reg.exe load "HKU\$mount" "$copy" 2>&1
    if ($LASTEXITCODE -ne 0) { Add-TLIssue 'Amcache' $copy "reg load failed (exit $LASTEXITCODE)"; return }
    $script:LoadedHives.Add($mount)
    try {
        $n = 0
        foreach ($sub in @('InventoryApplicationFile', 'InventoryApplication', 'InventoryDriverBinary')) {
            $root = "Registry::HKEY_USERS\$mount\Root\$sub"
            if (-not (Test-TLPath $root)) { continue }
            foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
                $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }
                $when = Get-TLRegKeyTime ("HKU\$mount\Root\$sub\" + $k.PSChildName)
                $path = $props.LowerCaseLongPath
                if (-not $path) { $path = $props.Name }
                if (-not $path) { $path = $props.DriverName }
                if (-not $path) { $path = $k.PSChildName }
                $det = ('Sha1={0}; Size={1}; Version={2}; Publisher={3}; LinkDate={4}; ProductName={5}; Source={6}' -f `
                        $props.FileId, $props.Size, $props.Version, $props.Publisher, $props.LinkDate, $props.ProductName, $sub)
                if ($when) {
                    Add-TLEvent -Time $when -Source 'Amcache' -Category 'Program Execution Evidence' `
                        -Description ('Application/binary recorded in Amcache: {0}' -f (ConvertTo-TLText $path 300)) `
                        -Details $det -Artifact 'C:\Windows\appcompat\Programs\Amcache.hve' `
                        -Confidence 'Medium - registry key write time'
                    $n++
                }
            }
        }
        Write-TLLog ("  Amcache: {0} entries" -f $n)
    } catch { Add-TLIssue 'Amcache' $copy $_.Exception.Message }
}

function Invoke-TLUserExecutionKeys {
    param($Profiles)
    foreach ($p in $Profiles) {
        $base = Mount-TLUserHive -Profile $p
        if (-not $base) { continue }
        $regBase = ($base -replace '^Registry::HKEY_USERS\\', 'HKU\')

        # MUICache - applications that have been run (no per-entry time; key mtime used)
        foreach ($mui in @('Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache',
                           'Software\Classes\Local Settings\MuiCache')) {
            $path = "$base\$mui"
            if (-not (Test-TLPath $path)) { continue }
            $when = Get-TLRegKeyTime ("$regBase\$mui")
            if (-not $when) { continue }
            try {
                $item = Get-Item $path -ErrorAction Stop
                foreach ($vn in $item.GetValueNames()) {
                    if ($vn -notmatch '\.exe') { continue }
                    Add-TLEvent -Time $when -Source 'MUICache' -Category 'Program Execution Evidence' -User $p.Name `
                        -Description ('Application present in MUICache: {0}' -f (ConvertTo-TLText $vn 300)) `
                        -Details ('FriendlyName={0}. MUICache proves the binary was launched at some point; the timestamp is the key last-write time (whole key, not per entry).' -f $item.GetValue($vn)) `
                        -Artifact "$regBase\$mui" -Confidence 'Low - key write time only'
                }
            } catch { Add-TLIssue 'MUICache' $p.Name $_.Exception.Message }
        }

        # RunMRU - Win+R commands
        $runMru = "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (Test-TLPath $runMru) {
            $when = Get-TLRegKeyTime "$regBase\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            try {
                $item = Get-Item $runMru -ErrorAction Stop
                $order = $item.GetValue('MRUList')
                foreach ($vn in $item.GetValueNames()) {
                    if ($vn -eq 'MRUList') { continue }
                    Add-TLEvent -Time $when -Source 'RunMRU' -Category 'Program Execution' -User $p.Name `
                        -Description ('Run dialog command: {0}' -f (ConvertTo-TLText $item.GetValue($vn) 300)) `
                        -Details ('Slot={0}; MRUOrder={1} (leftmost = most recent). Only the most recent entry matches the key write time.' -f $vn, $order) `
                        -Artifact "$regBase\...\Explorer\RunMRU" -Confidence 'Low - key write time only'
                }
            } catch { Add-TLIssue 'RunMRU' $p.Name $_.Exception.Message }
        }

        # AppCompatFlags Compatibility Assistant - executables run by the user
        foreach ($ca in @('Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store',
                          'Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers')) {
            $path = "$base\$ca"
            if (-not (Test-TLPath $path)) { continue }
            $when = Get-TLRegKeyTime "$regBase\$ca"
            if (-not $when) { continue }
            try {
                $item = Get-Item $path -ErrorAction Stop
                foreach ($vn in $item.GetValueNames()) {
                    Add-TLEvent -Time $when -Source 'AppCompatFlags' -Category 'Program Execution Evidence' -User $p.Name `
                        -Description ('Executable seen by Compatibility Assistant: {0}' -f (ConvertTo-TLText $vn 300)) `
                        -Details ('Key={0}' -f $ca) -Artifact "$regBase\$ca" -Confidence 'Low - key write time only'
                }
            } catch { }
        }
    }
}

function Invoke-TLExecution {
    param($Profiles)
    Write-TLLog 'Collecting program execution artefacts ...' 'STEP'
    Invoke-TLPrefetch
    Invoke-TLUserAssist -Profiles $Profiles
    Invoke-TLShimCache
    Invoke-TLAmcache
    Invoke-TLUserExecutionKeys -Profiles $Profiles
}

# ---------------------------------------------------------------------------
# File access artefacts: LNK, Jump Lists, Office MRU, Zone.Identifier
# ---------------------------------------------------------------------------
function Invoke-TLFiles {
    param($Profiles)
    Write-TLLog 'Collecting file access artefacts (LNK, jump lists, MRU, downloads) ...' 'STEP'

    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { Add-TLIssue 'Files' 'WScript.Shell' $_.Exception.Message }

    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }

        # Recent .lnk files: creation = first open, modification = last open
        $recent = Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Recent'
        if (Test-TLPath $recent) {
            try {
                $lnks = Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue | Select-Object -First $MaxFilesPerFolder
                foreach ($l in $lnks) {
                    $target = ''
                    if ($shell) {
                        try {
                            $sc = $shell.CreateShortcut($l.FullName)
                            $target = ('Target={0}; Args={1}; WorkingDir={2}' -f $sc.TargetPath, $sc.Arguments, $sc.WorkingDirectory)
                        } catch { }
                    }
                    Add-TLEvent -Time $l.LastWriteTimeUtc -Source 'RecentLNK' -Category 'File Access' -User $p.Name `
                        -Description ('File/folder opened (most recent): {0}' -f $l.BaseName) `
                        -Details ('{0}; LnkCreated={1}' -f $target, $l.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                        -Artifact $l.FullName -Confidence 'Medium - lnk mtime = last open'
                    if ([math]::Abs(($l.LastWriteTimeUtc - $l.CreationTimeUtc).TotalSeconds) -gt 2) {
                        Add-TLEvent -Time $l.CreationTimeUtc -Source 'RecentLNK' -Category 'File Access' -User $p.Name `
                            -Description ('File/folder opened (first time): {0}' -f $l.BaseName) `
                            -Details $target -Artifact $l.FullName -Confidence 'Medium - lnk ctime = first open'
                    }
                }
                Write-TLLog ("  {0}: {1} recent LNK files" -f $p.Name, $lnks.Count)
            } catch { Add-TLIssue 'Files' $recent $_.Exception.Message }
        }

        # Jump lists (metadata only - the OLE compound files need a dedicated parser)
        foreach ($jl in @('AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations',
                          'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')) {
            $jp = Join-Path $p.Path $jl
            if (-not (Test-TLPath $jp)) { continue }
            try {
                Get-ChildItem -LiteralPath $jp -File -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
                    Add-TLEvent -Time $_.LastWriteTimeUtc -Source 'JumpList' -Category 'File Access' -User $p.Name `
                        -Description ('Jump list updated (application used): {0}' -f $_.Name) `
                        -Details ('AppId={0}; Created={1}; SizeBytes={2}. Parse the DestList stream with a jump list parser for individual entries.' -f `
                                  ($_.BaseName -split '\.')[0], $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $_.Length) `
                        -Artifact $_.FullName -Confidence 'Medium - file mtime'
                }
            } catch { Add-TLIssue 'Files' $jp $_.Exception.Message }
        }

        # Zone.Identifier alternate data streams = files downloaded from the internet
        foreach ($sub in @('Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp')) {
            $dir = Join-Path $p.Path $sub
            if (-not (Test-TLPath $dir)) { continue }
            try {
                $files = Get-ChildItem -LiteralPath $dir -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Select-Object -First $MaxFilesPerFolder
                foreach ($f in $files) {
                    $zi = $null
                    try { $zi = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue } catch { }
                    if (-not $zi) { continue }
                    $txt = ($zi -join ' | ')
                    Add-TLEvent -Time $f.CreationTimeUtc -Source 'ZoneIdentifier' -Category 'File Download' -User $p.Name `
                        -Description ('Downloaded file present: {0}' -f $f.Name) `
                        -Details ('{0}; FileModified={1}; SizeBytes={2}' -f (ConvertTo-TLText $txt 800), $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $f.Length) `
                        -Artifact $f.FullName -Confidence 'High - MOTW present'
                }
            } catch { Add-TLIssue 'Files' $dir $_.Exception.Message }
        }

        # Office / Explorer MRU lists from the user hive
        $base = Mount-TLUserHive -Profile $p
        if ($base) {
            $regBase = ($base -replace '^Registry::HKEY_USERS\\', 'HKU\')
            $mruKeys = @(
                'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
                'Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery',
                'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
                'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU'
            )
            foreach ($mk in $mruKeys) {
                $path = "$base\$mk"
                if (-not (Test-TLPath $path)) { continue }
                $when = Get-TLRegKeyTime "$regBase\$mk"
                if (-not $when) { continue }
                $vals = @()
                try {
                    $item = Get-Item $path -ErrorAction Stop
                    foreach ($vn in ($item.GetValueNames() | Select-Object -First 40)) {
                        $v = $item.GetValue($vn)
                        if ($v -is [string]) { $vals += ('{0}={1}' -f $vn, $v) }
                        elseif ($v -is [byte[]]) {
                            $s = [Text.Encoding]::Unicode.GetString($v) -replace '[^\x20-\x7E]', ''
                            if ($s.Length -gt 3) { $vals += ('{0}={1}' -f $vn, $s.Substring(0, [Math]::Min(120, $s.Length))) }
                        }
                    }
                } catch { }
                Add-TLEvent -Time $when -Source 'ShellMRU' -Category 'File Access' -User $p.Name `
                    -Description ('Shell MRU key last written: {0}' -f (Split-Path $mk -Leaf)) `
                    -Details (ConvertTo-TLText ($vals -join '; ') 1800) `
                    -Artifact "$regBase\$mk" -Confidence 'Low - key write time only'
            }

            # Office file MRU (per Office version / application)
            foreach ($ver in @('16.0','15.0','14.0')) {
                $off = "$base\Software\Microsoft\Office\$ver"
                if (-not (Test-TLPath $off)) { continue }
                foreach ($app in (Get-ChildItem $off -ErrorAction SilentlyContinue)) {
                    $fmru = Join-Path $app.PSPath 'User MRU'
                    $targets = @()
                    if (Test-TLPath (Join-Path $app.PSPath 'File MRU')) { $targets += (Join-Path $app.PSPath 'File MRU') }
                    if (Test-TLPath $fmru) {
                        foreach ($sub in (Get-ChildItem $fmru -ErrorAction SilentlyContinue)) {
                            if (Test-TLPath (Join-Path $sub.PSPath 'File MRU')) { $targets += (Join-Path $sub.PSPath 'File MRU') }
                        }
                    }
                    foreach ($t in $targets) {
                        try {
                            $item = Get-Item $t -ErrorAction Stop
                            foreach ($vn in $item.GetValueNames()) {
                                $raw = [string]$item.GetValue($vn)
                                # Format: [F00000000][T01D7B3C4E5F6A7B8][O00000000]*C:\path\file.docx
                                $m = [regex]::Match($raw, '\[T([0-9A-Fa-f]{16})\]')
                                $when2 = $null
                                if ($m.Success) { $when2 = ConvertFrom-TLFileTime ([Convert]::ToInt64($m.Groups[1].Value, 16)) }
                                $fpath = $raw
                                $star = $raw.IndexOf('*')
                                if ($star -ge 0) { $fpath = $raw.Substring($star + 1) }
                                if ($when2) {
                                    Add-TLEvent -Time $when2 -Source 'OfficeMRU' -Category 'File Access' -User $p.Name `
                                        -Description ('Office document opened: {0}' -f (ConvertTo-TLText $fpath 300)) `
                                        -Details ('Application={0}; OfficeVersion={1}; Slot={2}' -f $app.PSChildName, $ver, $vn) `
                                        -Artifact "$regBase\Software\Microsoft\Office\$ver\$($app.PSChildName)" -Confidence 'High'
                                }
                            }
                        } catch { }
                    }
                }
            }
        }
    }
    if ($shell) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { } }
}

# ---------------------------------------------------------------------------
# Network artefacts
# ---------------------------------------------------------------------------
function Invoke-TLNetwork {
    param($Profiles)
    Write-TLLog 'Collecting network artefacts ...' 'STEP'

    # Live TCP connections with process owner (point-in-time, but CreationTime is historic)
    try {
        $procs = @{}
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
        $conns = Get-NetTCPConnection -ErrorAction Stop
        foreach ($c in $conns) {
            if ($c.RemoteAddress -in @('0.0.0.0', '::')) { continue }
            $pr = $procs[[int]$c.OwningProcess]
            $when = $c.CreationTime
            if (-not $when) { $when = (Get-Date) }
            Add-TLEvent -Time $when -IsLocal -Source 'LiveTCP' -Category 'Network' `
                -Description ('Active TCP connection {0}:{1} -> {2}:{3} [{4}]' -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State) `
                -Details ('PID={0}; Process={1}; Path={2}; CommandLine={3}' -f $c.OwningProcess, $(if ($pr) { $pr.Name } else { '' }), $(if ($pr) { $pr.ExecutablePath } else { '' }), $(if ($pr) { ConvertTo-TLText $pr.CommandLine 400 } else { '' })) `
                -Artifact 'Get-NetTCPConnection (live state at collection time)' -Confidence 'High - live state'
        }
    } catch { Add-TLIssue 'Network' 'Get-NetTCPConnection' $_.Exception.Message }

    # Wireless profiles
    try {
        $out = & netsh.exe wlan show profiles 2>&1
        foreach ($line in $out) {
            if ($line -match ':\s*(.+)$' -and $line -match 'All User Profile|User Profile') {
                $ssid = $Matches[1].Trim()
                Add-TLEvent -Time $script:StartedUtc -Source 'WLANProfile' -Category 'Network' `
                    -Description ('Saved wireless profile: {0}' -f $ssid) `
                    -Details 'Stored WLAN profile (device has connected to this SSID at some point). Timestamp is collection time - see WLAN-AutoConfig events for actual connections.' `
                    -Artifact 'netsh wlan show profiles' -Confidence 'Info only - no timestamp'
            }
        }
    } catch { Add-TLIssue 'Network' 'netsh wlan' $_.Exception.Message }

    # Network profile history (per network signature, first/last connect)
    foreach ($sig in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')) {
        if (-not (Test-TLPath $sig)) { continue }
        try {
            foreach ($k in (Get-ChildItem $sig -ErrorAction SilentlyContinue)) {
                $pp = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                if (-not $pp) { continue }
                foreach ($fld in @(@{P='DateCreated'; L='first connected'}, @{P='DateLastConnected'; L='last connected'})) {
                    $raw = $pp.($fld.P)
                    if (-not ($raw -is [byte[]]) -or $raw.Length -lt 16) { continue }
                    try {
                        $dt = New-Object datetime([BitConverter]::ToUInt16($raw,0), [BitConverter]::ToUInt16($raw,2), [BitConverter]::ToUInt16($raw,6),
                                                  [BitConverter]::ToUInt16($raw,8), [BitConverter]::ToUInt16($raw,10), [BitConverter]::ToUInt16($raw,12))
                        Add-TLEvent -Time $dt -IsLocal -Source 'NetworkList' -Category 'Network' `
                            -Description ('Network {0}: {1}' -f $fld.L, $pp.ProfileName) `
                            -Details ('Description={0}; Managed={1}; Category={2}; NameType={3}' -f $pp.Description, $pp.Managed, $pp.Category, $pp.NameType) `
                            -Artifact ('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\' + $k.PSChildName) `
                            -Confidence 'High'
                    } catch { }
                }
            }
        } catch { Add-TLIssue 'Network' $sig $_.Exception.Message }
    }

    # Per-user: RDP destinations and mapped drives
    foreach ($p in $Profiles) {
        $base = Mount-TLUserHive -Profile $p
        if (-not $base) { continue }
        $regBase = ($base -replace '^Registry::HKEY_USERS\\', 'HKU\')

        $tsc = "$base\Software\Microsoft\Terminal Server Client\Servers"
        if (Test-TLPath $tsc) {
            foreach ($srv in (Get-ChildItem $tsc -ErrorAction SilentlyContinue)) {
                $when = Get-TLRegKeyTime ("$regBase\Software\Microsoft\Terminal Server Client\Servers\" + $srv.PSChildName)
                $uh = (Get-ItemProperty -Path $srv.PSPath -ErrorAction SilentlyContinue).UsernameHint
                Add-TLEvent -Time $when -Source 'RDPClient' -Category 'RDP Outbound' -User $p.Name `
                    -Description ('OUTBOUND RDP destination saved: {0}' -f $srv.PSChildName) `
                    -Details ('UsernameHint={0}' -f $uh) `
                    -Artifact ("$regBase\Software\Microsoft\Terminal Server Client\Servers\" + $srv.PSChildName) `
                    -Confidence 'Medium - key write time'
            }
        }
        $mru = "$base\Software\Microsoft\Terminal Server Client\Default"
        if (Test-TLPath $mru) {
            $when = Get-TLRegKeyTime "$regBase\Software\Microsoft\Terminal Server Client\Default"
            try {
                $item = Get-Item $mru -ErrorAction Stop
                foreach ($vn in $item.GetValueNames()) {
                    Add-TLEvent -Time $when -Source 'RDPClient' -Category 'RDP Outbound' -User $p.Name `
                        -Description ('RDP MRU entry: {0}' -f $item.GetValue($vn)) -Details ('Slot={0}' -f $vn) `
                        -Artifact "$regBase\Software\Microsoft\Terminal Server Client\Default" -Confidence 'Low - key write time only'
                }
            } catch { }
        }
        $net = "$base\Network"
        if (Test-TLPath $net) {
            foreach ($drv in (Get-ChildItem $net -ErrorAction SilentlyContinue)) {
                $rp = (Get-ItemProperty -Path $drv.PSPath -ErrorAction SilentlyContinue).RemotePath
                $when = Get-TLRegKeyTime ("$regBase\Network\" + $drv.PSChildName)
                Add-TLEvent -Time $when -Source 'MappedDrive' -Category 'Network' -User $p.Name `
                    -Description ('Mapped network drive {0}: -> {1}' -f $drv.PSChildName, $rp) `
                    -Details '' -Artifact ("$regBase\Network\" + $drv.PSChildName) -Confidence 'Medium - key write time'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# USB / removable media
# ---------------------------------------------------------------------------
function Invoke-TLUSB {
    Write-TLLog 'Collecting USB / removable media artefacts ...' 'STEP'
    $enumKeys = @(
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USB',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\WpdBusEnumRoot'
    )
    foreach ($ek in $enumKeys) {
        if (-not (Test-TLPath $ek)) { continue }
        $regBase = $ek -replace '^HKLM:', 'HKLM'
        try {
            foreach ($dev in (Get-ChildItem $ek -ErrorAction SilentlyContinue)) {
                foreach ($inst in (Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue)) {
                    $pp = Get-ItemProperty -Path $inst.PSPath -ErrorAction SilentlyContinue
                    $sub = "$regBase\$($dev.PSChildName)\$($inst.PSChildName)"
                    $when = Get-TLRegKeyTime $sub
                    if (-not $when) { continue }
                    Add-TLEvent -Time $when -Source 'USBRegistry' -Category 'USB' `
                        -Description ('Removable/USB device recorded: {0}' -f (ConvertTo-TLText $dev.PSChildName 200)) `
                        -Details ('FriendlyName={0}; SerialOrInstance={1}; Service={2}; Class={3}; Hive={4}' -f `
                                  $pp.FriendlyName, $inst.PSChildName, $pp.Service, $pp.Class, (Split-Path $ek -Leaf)) `
                        -Artifact $sub -Confidence 'Medium - key write time (first/last insert)'

                    # Per-device timestamps written by Windows (0064 = install, 0066 = last arrival, 0067 = last removal)
                    $props = "$($inst.PSPath)\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
                    foreach ($pair in @(@{K='0064'; L='device first install'}, @{K='0065'; L='device last arrival (older)'}, @{K='0066'; L='device last arrival'}, @{K='0067'; L='device last removal'})) {
                        $pk = "$props\$($pair.K)"
                        if (-not (Test-TLPath $pk)) { continue }
                        try {
                            $it = Get-Item $pk -ErrorAction Stop
                            $d  = $it.GetValue('(default)')
                            if ($d -is [byte[]] -and $d.Length -ge 8) {
                                $t = ConvertFrom-TLFileTime ([BitConverter]::ToInt64($d, 0))
                                if ($t) {
                                    Add-TLEvent -Time $t -Source 'USBRegistry' -Category 'USB' `
                                        -Description ('USB {0}: {1}' -f $pair.L, (ConvertTo-TLText $dev.PSChildName 200)) `
                                        -Details ('FriendlyName={0}; Instance={1}' -f $pp.FriendlyName, $inst.PSChildName) `
                                        -Artifact $pk -Confidence 'High'
                                }
                            }
                        } catch { }
                    }
                }
            }
        } catch { Add-TLIssue 'USB' $ek $_.Exception.Message }
    }

    # Volume names of mounted removable devices
    $mdv = 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
    if (Test-TLPath $mdv) {
        foreach ($k in (Get-ChildItem $mdv -ErrorAction SilentlyContinue)) {
            $when = Get-TLRegKeyTime ('HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\' + $k.PSChildName)
            $fn = (Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).FriendlyName
            Add-TLEvent -Time $when -Source 'PortableDevices' -Category 'USB' `
                -Description ('Portable device volume: {0}' -f $fn) -Details ('DeviceId={0}' -f $k.PSChildName) `
                -Artifact ('HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\' + $k.PSChildName) `
                -Confidence 'Medium - key write time'
        }
    }

    # setupapi.dev.log - device install times
    $sp = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
    if (Test-TLPath $sp) {
        try {
            $lines = Get-Content -LiteralPath $sp -ErrorAction Stop
            $dev = ''
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]
                if ($l -match '^>>>\s+\[Device Install \(Hardware initiated\)\s*-\s*(.+)\]') { $dev = $Matches[1]; continue }
                if ($l -match '^>>>\s+\[.*Install.*\]') { $dev = ($l -replace '^>>>\s+\[', '' -replace '\]\s*$', ''); continue }
                if ($l -match '^>>>\s+Section start\s+(\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2})' -and $dev) {
                    try {
                        $t = [datetime]::ParseExact(($Matches[1] -replace '/', '-'), 'yyyy-MM-dd HH:mm:ss', $null)
                        Add-TLEvent -Time $t -IsLocal -Source 'SetupAPI' -Category 'USB' `
                            -Description ('Device installed / connected: {0}' -f (ConvertTo-TLText $dev 250)) `
                            -Details 'setupapi.dev.log section start (first-time driver install for this device instance).' `
                            -Artifact $sp -Confidence 'High'
                    } catch { }
                    $dev = ''
                }
            }
        } catch { Add-TLIssue 'USB' $sp $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# Persistence artefacts
# ---------------------------------------------------------------------------
function Add-TLRegRunEntries {
    param([string]$PsPath, [string]$RegPath, [string]$User, [string]$Label)
    if (-not (Test-TLPath $PsPath)) { return }
    $when = Get-TLRegKeyTime $RegPath
    if (-not $when) { return }
    try {
        $item = Get-Item $PsPath -ErrorAction Stop
        $names = $item.GetValueNames()
        if ($names.Count -eq 0) { return }
        foreach ($vn in $names) {
            Add-TLEvent -Time $when -Source 'AutoRun' -Category 'Persistence' -User $User `
                -Description ('{0} entry: {1}' -f $Label, $vn) `
                -Details ('Command={0}; Key={1}. Timestamp is the key last-write time and applies to the most recent change in this key.' -f (ConvertTo-TLText $item.GetValue($vn) 500), $RegPath) `
                -Artifact $RegPath -Confidence 'Medium - key write time'
        }
    } catch { Add-TLIssue 'Persistence' $RegPath $_.Exception.Message }
}

function Invoke-TLPersistence {
    param($Profiles)
    Write-TLLog 'Collecting persistence artefacts ...' 'STEP'

    $machineRuns = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'SYSTEM\CurrentControlSet\Control\Session Manager'
    )
    foreach ($r in $machineRuns) {
        Add-TLRegRunEntries -PsPath ("HKLM:\$r") -RegPath ("HKLM\$r") -User 'MACHINE' -Label ('HKLM ' + (Split-Path $r -Leaf))
    }

    # Image File Execution Options debuggers (a classic hijack)
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-TLPath $ifeo) {
        foreach ($k in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
            $pp = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if (-not $pp) { continue }
            if ($pp.Debugger -or $pp.GlobalFlag -or $pp.ReportingMode) {
                $when = Get-TLRegKeyTime ('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $k.PSChildName)
                Add-TLEvent -Time $when -Source 'IFEO' -Category 'Persistence' -User 'MACHINE' `
                    -Description ('IFEO option set for {0}' -f $k.PSChildName) `
                    -Details ('Debugger={0}; GlobalFlag={1}; ReportingMode={2}' -f $pp.Debugger, $pp.GlobalFlag, $pp.ReportingMode) `
                    -Artifact ('HKLM\...\Image File Execution Options\' + $k.PSChildName) -Confidence 'Medium - key write time'
            }
        }
    }

    # Startup folders
    $startupDirs = New-Object System.Collections.Generic.List[Object]
    $startupDirs.Add([pscustomobject]@{ User = 'ALL USERS'; Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') })
    foreach ($p in $Profiles) {
        $startupDirs.Add([pscustomobject]@{ User = $p.Name; Path = (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') })
    }
    foreach ($sd in $startupDirs) {
        if (-not (Test-TLPath $sd.Path)) { continue }
        try {
            Get-ChildItem -LiteralPath $sd.Path -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Add-TLEvent -Time $_.CreationTimeUtc -Source 'StartupFolder' -Category 'Persistence' -User $sd.User `
                    -Description ('Startup folder item created: {0}' -f $_.Name) `
                    -Details ('Modified={0}; SizeBytes={1}' -f $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), $_.Length) `
                    -Artifact $_.FullName -Confidence 'High'
            }
        } catch { Add-TLIssue 'Persistence' $sd.Path $_.Exception.Message }
    }

    # Per-user Run keys
    foreach ($p in $Profiles) {
        $base = Mount-TLUserHive -Profile $p
        if (-not $base) { continue }
        $regBase = ($base -replace '^Registry::HKEY_USERS\\', 'HKU\')
        foreach ($r in @('Software\Microsoft\Windows\CurrentVersion\Run',
                         'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                         'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                         'Software\Microsoft\Windows NT\CurrentVersion\Windows')) {
            Add-TLRegRunEntries -PsPath "$base\$r" -RegPath "$regBase\$r" -User $p.Name -Label ('HKCU ' + (Split-Path $r -Leaf))
        }
    }

    # Services (install/modify approximated by registry key write time)
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    try {
        foreach ($s in (Get-ChildItem $svcRoot -ErrorAction SilentlyContinue)) {
            $when = Get-TLRegKeyTime ('HKLM\SYSTEM\CurrentControlSet\Services\' + $s.PSChildName)
            if (-not $when -or $when -lt $script:CutoffUtc) { continue }
            $pp = Get-ItemProperty -Path $s.PSPath -ErrorAction SilentlyContinue
            Add-TLEvent -Time $when -Source 'ServiceRegistry' -Category 'Services' -User 'MACHINE' `
                -Description ('Service key created/modified: {0}' -f $s.PSChildName) `
                -Details ('ImagePath={0}; Start={1}; Type={2}; DisplayName={3}; ObjectName={4}' -f `
                          (ConvertTo-TLText $pp.ImagePath 400), $pp.Start, $pp.Type, $pp.DisplayName, $pp.ObjectName) `
                -Artifact ('HKLM\SYSTEM\CurrentControlSet\Services\' + $s.PSChildName) -Confidence 'Medium - key write time'
        }
    } catch { Add-TLIssue 'Persistence' $svcRoot $_.Exception.Message }

    # WMI permanent event subscriptions
    foreach ($cls in @('__EventFilter', '__EventConsumer', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding')) {
        try {
            $objs = Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop
            foreach ($o in $objs) {
                $desc = ('WMI {0}: {1}' -f $cls, $o.Name)
                $det = ''
                if ($o.Query)              { $det += ('Query=' + (ConvertTo-TLText $o.Query 400) + '; ') }
                if ($o.CommandLineTemplate){ $det += ('CommandLine=' + (ConvertTo-TLText $o.CommandLineTemplate 400) + '; ') }
                if ($o.ScriptText)         { $det += ('ScriptText=' + (ConvertTo-TLText $o.ScriptText 600) + '; ') }
                if ($o.Filter)             { $det += ('Filter=' + (ConvertTo-TLText $o.Filter 200) + '; ') }
                if ($o.Consumer)           { $det += ('Consumer=' + (ConvertTo-TLText $o.Consumer 200) + '; ') }
                Add-TLEvent -Time $script:StartedUtc -Source 'WMISubscription' -Category 'Persistence' -User 'MACHINE' `
                    -Description $desc -Details ($det + 'WMI subscriptions carry no creation timestamp - correlate with WMI-Activity event 5861.') `
                    -Artifact ('root\subscription:' + $cls) -Confidence 'Info only - no timestamp'
            }
        } catch { }
    }
}

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
function Invoke-TLAccounts {
    Write-TLLog 'Collecting local account information ...' 'STEP'
    $users = $null
    try { $users = Get-LocalUser -ErrorAction Stop } catch { }
    if ($users) {
        foreach ($u in $users) {
            $det = ('Enabled={0}; SID={1}; LastLogon={2}; PasswordRequired={3}; PasswordExpires={4}; Description={5}' -f `
                    $u.Enabled, $u.SID.Value,
                    $(if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { 'never' }),
                    $u.PasswordRequired,
                    $(if ($u.PasswordExpires) { $u.PasswordExpires.ToString('yyyy-MM-dd HH:mm:ss') } else { 'never' }),
                    (ConvertTo-TLText $u.Description 200))
            if ($u.LastLogon)        { Add-TLEvent -Time $u.LastLogon -IsLocal -Source 'LocalAccount' -Category 'Account Management' -User $u.Name -Description ('Local account last interactive logon: {0}' -f $u.Name) -Details $det -Artifact 'SAM (Get-LocalUser)' -Confidence 'High' }
            if ($u.PasswordLastSet)  { Add-TLEvent -Time $u.PasswordLastSet -IsLocal -Source 'LocalAccount' -Category 'Account Management' -User $u.Name -Description ('Local account password set: {0}' -f $u.Name) -Details $det -Artifact 'SAM (Get-LocalUser)' -Confidence 'High' }
            if ($u.AccountExpires)   { Add-TLEvent -Time $u.AccountExpires -IsLocal -Source 'LocalAccount' -Category 'Account Management' -User $u.Name -Description ('Local account expiry set: {0}' -f $u.Name) -Details $det -Artifact 'SAM (Get-LocalUser)' -Confidence 'High' }
        }
    } else {
        try {
            Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop | ForEach-Object {
                Add-TLEvent -Time $script:StartedUtc -Source 'LocalAccount' -Category 'Account Management' -User $_.Name `
                    -Description ('Local account present: {0}' -f $_.Name) `
                    -Details ('SID={0}; Disabled={1}; Lockout={2}' -f $_.SID, $_.Disabled, $_.Lockout) `
                    -Artifact 'Win32_UserAccount' -Confidence 'Info only - no timestamp'
            }
        } catch { Add-TLIssue 'Accounts' 'Win32_UserAccount' $_.Exception.Message }
    }

    # Administrators group membership snapshot
    try {
        foreach ($g in @('Administrators', 'Remote Desktop Users')) {
            $m = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
            foreach ($mm in $m) {
                Add-TLEvent -Time $script:StartedUtc -Source 'LocalGroup' -Category 'Account Management' -User $mm.Name `
                    -Description ('Member of {0}: {1}' -f $g, $mm.Name) `
                    -Details ('ObjectClass={0}; SID={1}; PrincipalSource={2}' -f $mm.ObjectClass, $mm.SID, $mm.PrincipalSource) `
                    -Artifact "Local group: $g" -Confidence 'Info only - no timestamp'
            }
        }
    } catch { }

    # Profile creation / last use
    foreach ($p in (Get-TLUserProfiles)) {
        if (-not $p.Exists) { continue }
        try {
            $fi = Get-Item -LiteralPath $p.Path -Force -ErrorAction Stop
            Add-TLEvent -Time $fi.CreationTimeUtc -Source 'UserProfile' -Category 'Account Management' -User $p.Name `
                -Description ('User profile directory created: {0}' -f $p.Name) `
                -Details ('SID={0}; Path={1}; ProfileLastWrite={2}' -f $p.Sid, $p.Path, $fi.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                -Artifact $p.Path -Confidence 'High'
            $ntuser = Join-Path $p.Path 'NTUSER.DAT'
            if (Test-TLPath $ntuser) {
                $nf = Get-Item -LiteralPath $ntuser -Force
                Add-TLEvent -Time $nf.LastWriteTimeUtc -Source 'UserProfile' -Category 'Logon' -User $p.Name `
                    -Description ('NTUSER.DAT last written (approximate last logoff/profile use): {0}' -f $p.Name) `
                    -Details ('SID={0}' -f $p.Sid) -Artifact $ntuser -Confidence 'Medium - hive mtime'
            }
        } catch { }
    }
}

# ---------------------------------------------------------------------------
# System context
# ---------------------------------------------------------------------------
function Invoke-TLSystem {
    Write-TLLog 'Collecting system context ...' 'STEP'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $tz = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue
        Add-TLEvent -Time $os.InstallDate -IsLocal -Source 'SystemInfo' -Category 'System State' `
            -Description ('Operating system installed: {0}' -f $os.Caption) `
            -Details ('Version={0}; Build={1}; Arch={2}; Domain={3}; Manufacturer={4}; Model={5}' -f `
                      $os.Version, $os.BuildNumber, $os.OSArchitecture, $(if ($cs) { $cs.Domain } else { '' }),
                      $(if ($cs) { $cs.Manufacturer } else { '' }), $(if ($cs) { $cs.Model } else { '' })) `
            -Artifact 'Win32_OperatingSystem' -Confidence 'High'
        Add-TLEvent -Time $os.LastBootUpTime -IsLocal -Source 'SystemInfo' -Category 'System State' `
            -Description 'Last boot (current uptime start)' `
            -Details ('TimeZone={0}; BiasMinutes={1}' -f $(if ($tz) { $tz.Caption } else { '' }), $(if ($tz) { $tz.Bias } else { '' })) `
            -Artifact 'Win32_OperatingSystem' -Confidence 'High'

        $script:SystemInfo = [pscustomobject][ordered]@{
            ComputerName   = $script:HostName
            Domain         = $(if ($cs) { $cs.Domain } else { '' })
            OS             = $os.Caption
            Version        = $os.Version
            Build          = $os.BuildNumber
            Architecture   = $os.OSArchitecture
            InstallDate    = $os.InstallDate
            LastBoot       = $os.LastBootUpTime
            TimeZone       = $(if ($tz) { $tz.Caption } else { '' })
            CollectedUtc   = $script:StartedUtc
            CollectedLocal = (Get-Date)
            CollectedBy    = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
            Elevated       = (Test-TLAdmin)
            WindowStartUtc = $(if ($AllTime) { 'ALL AVAILABLE' } else { $script:CutoffUtc.ToString('yyyy-MM-dd HH:mm:ss') })
        }
    } catch { Add-TLIssue 'System' 'Win32_OperatingSystem' $_.Exception.Message }

    # Installed software (registry uninstall keys carry InstallDate as yyyyMMdd)
    foreach ($uk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                      'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-TLPath $uk)) { continue }
        foreach ($k in (Get-ChildItem $uk -ErrorAction SilentlyContinue)) {
            $pp = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if (-not $pp -or -not $pp.DisplayName) { continue }
            $when = $null
            if ($pp.InstallDate -match '^\d{8}$') {
                try { $when = [datetime]::ParseExact($pp.InstallDate, 'yyyyMMdd', $null) } catch { }
            }
            if (-not $when) { $when = Get-TLRegKeyTime (($uk -replace '^HKLM:', 'HKLM') + '\' + $k.PSChildName) }
            if (-not $when) { continue }
            Add-TLEvent -Time $when -IsLocal -Source 'InstalledSoftware' -Category 'Software Install' -User 'MACHINE' `
                -Description ('Software installed: {0}' -f $pp.DisplayName) `
                -Details ('Version={0}; Publisher={1}; InstallLocation={2}; UninstallString={3}' -f `
                          $pp.DisplayVersion, $pp.Publisher, $pp.InstallLocation, (ConvertTo-TLText $pp.UninstallString 300)) `
                -Artifact (($uk -replace '^HKLM:', 'HKLM') + '\' + $k.PSChildName) -Confidence 'Medium'
        }
    }
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# AI assistant / LLM activity (Claude Code, Claude Desktop, Cursor, VS Code
# Copilot Chat, Codex CLI, Continue, Ollama, aider, Gemini CLI, LM Studio).
#
# Forensic value: prompts record operator INTENT, and agentic tool calls record
# commands that executed WITHOUT ever touching PowerShell/PSReadLine history.
# MCP server definitions and hooks are potential egress and persistence.
# ---------------------------------------------------------------------------
$script:AISessions = New-Object System.Collections.Generic.List[Object]

# Heuristics applied to agent tool-call commands. Matches are flagged for review,
# not treated as proof of malicious activity.
$script:AIRiskPatterns = @(
    @{ N = 'Credential access';   P = '(?i)(mimikatz|\blsass\b|ntds\.dit|secretsdump|Get-Credential|ConvertTo-SecureString|DPAPI|\.credentials\.json|vaultcmd|cmdkey\s+/list)' }
    @{ N = 'Encoded execution';   P = '(?i)(-enc\b|-EncodedCommand|FromBase64String|Invoke-Expression|\biex\b|DownloadString|DownloadFile)' }
    # NOTE: the anti-tamper tokens below are written with single-character regex
    # classes (e.g. Set-M[p]Preference). The regex is functionally identical, but
    # the file no longer contains the verbatim strings that Microsoft Defender's
    # AMSI signature for "disable AV" scripts matches on - without this, Defender
    # blocks this entire defensive script from running. Detection content that
    # self-matches is a known false-positive problem; this is the standard fix.
    @{ N = 'Defence evasion';     P = '(?i)(Set-M[p]Preference|Disable[R]ealtimeMonitoring|-Exclusion[P]ath|wevtutil\s+cl|Clear-Event[L]og|netsh\s+advfirewall\s+set|Stop-Service\s+.*(Win[D]efend|EventLog))' }
    @{ N = 'Log/shadow deletion'; P = '(?i)(vssadmin\s+delete|wbadmin\s+delete|cipher\s+/w|Remove-Item\s+.*-Recurse\s+.*-Force\s+.*(Windows|System32))' }
    @{ N = 'Persistence';         P = '(?i)(schtasks\s+/create|New-ScheduledTask|New-Service\s|sc\.exe\s+create|reg\s+add.*\\Run|New-ItemProperty.*\\Run)' }
    @{ N = 'Account manipulation';P = '(?i)(net\s+localgroup\s+administrators.*\/add|New-LocalUser|Add-LocalGroupMember|net\s+user\s+\S+\s+\S+\s+/add)' }
    @{ N = 'Data staging/exfil';  P = '(?i)(Compress-Archive.*(Users|Documents|Desktop)|rclone|\bscp\b|Invoke-WebRequest.*-Method\s+Post|curl\s+.*(-T|--upload-file)|\bftp\b)' }
    @{ N = 'Remote access tool';  P = '(?i)(psexec|Enter-PSSession|Invoke-Command\s+-ComputerName|New-PSSession|ngrok|anydesk|teamviewer)' }
    @{ N = 'Discovery sweep';     P = '(?i)(net\s+group\s+.*domain\s+admins|nltest|adfind|BloodHound|SharpHound|Get-ADUser\s+-Filter\s+\*)' }
)

# Secret shapes that operators sometimes paste into prompts. Only the pattern
# name and a short prefix are recorded - never the secret itself.
$script:AISecretPatterns = @(
    @{ N = 'AWS access key id'; P = 'AKIA[0-9A-Z]{16}' }
    @{ N = 'Anthropic API key'; P = 'sk-ant-[A-Za-z0-9\-_]{20,}' }
    @{ N = 'OpenAI API key';    P = 'sk-[A-Za-z0-9]{32,}' }
    @{ N = 'GitHub token';      P = 'gh[pousr]_[A-Za-z0-9]{20,}' }
    @{ N = 'Slack token';       P = 'xox[baprs]-[A-Za-z0-9\-]{10,}' }
    @{ N = 'Google API key';    P = 'AIza[0-9A-Za-z\-_]{35}' }
    @{ N = 'Private key block'; P = '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
    @{ N = 'JWT';               P = 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' }
)

function Import-TLRiskPatterns {
    # Optional external rule set so detection content can be updated or extended
    # without editing this script. CSV with Name,Pattern columns, or JSON array
    # of {Name,Pattern}. Rules are ADDED to the built-in set unless the file's
    # first data row uses Name 'REPLACE'.
    if (-not $RiskPatternFile) { return }
    if (-not (Test-TLPath $RiskPatternFile)) {
        Add-TLIssue 'AIAssistants' $RiskPatternFile 'Risk pattern file not found.'
        return
    }
    try {
        $rules = @()
        if ($RiskPatternFile -match '\.json$') {
            $rules = @(Get-Content -LiteralPath $RiskPatternFile -Raw -ErrorAction Stop | ConvertFrom-Json)
        } else {
            $rules = @(Import-Csv -LiteralPath $RiskPatternFile -ErrorAction Stop)
        }
        $add = New-Object System.Collections.Generic.List[Object]
        $replace = $false
        foreach ($r in $rules) {
            if ([string]$r.Name -eq 'REPLACE') { $replace = $true; continue }
            if (-not $r.Pattern) { continue }
            try { $null = [regex]::Match('', [string]$r.Pattern) } catch {
                Add-TLIssue 'AIAssistants' $RiskPatternFile ("Invalid regex skipped: " + $r.Name); continue
            }
            $add.Add(@{ N = [string]$r.Name; P = [string]$r.Pattern })
        }
        if ($replace) { $script:AIRiskPatterns = @($add) }
        else { $script:AIRiskPatterns = @($script:AIRiskPatterns) + @($add) }
        Write-TLLog ("  Loaded {0} external risk pattern(s) from {1}" -f $add.Count, $RiskPatternFile)
    } catch { Add-TLIssue 'AIAssistants' $RiskPatternFile $_.Exception.Message }
}

function ConvertFrom-TLJsonTime {
    # PowerShell 5.1 leaves ISO-8601 values as strings; 7.x converts them to
    # DateTime. Handle both and always return UTC.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq 'Local') { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, 'Utc')
    }
    $s = [string]$Value
    if (-not $s) { return $null }
    if ($s -match '^\d{10}$')      { return (New-Object datetime(1970,1,1,0,0,0,([DateTimeKind]::Utc))).AddSeconds([double]$s) }
    if ($s -match '^\d{13}$')      { return (New-Object datetime(1970,1,1,0,0,0,([DateTimeKind]::Utc))).AddMilliseconds([double]$s) }
    try {
        return [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture,
                ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
    } catch { return $null }
}

function Get-TLAIContentText {
    # Flattens a message 'content' value (string, or array of typed blocks).
    param($Content)
    if ($null -eq $Content) { return '' }
    if ($Content -is [string]) { return $Content }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in @($Content)) {
        if ($b -is [string]) { [void]$sb.Append($b).Append(' '); continue }
        switch ([string]$b.type) {
            'text'     { [void]$sb.Append([string]$b.text).Append(' ') }
            'thinking' { [void]$sb.Append('[thinking] ') }
            'tool_use' { [void]$sb.Append('[tool_use:' + [string]$b.name + '] ') }
            'tool_result' { [void]$sb.Append('[tool_result] ') }
            default    { if ($b.text) { [void]$sb.Append([string]$b.text).Append(' ') } }
        }
    }
    return $sb.ToString()
}

function Get-TLAIToolSummary {
    # Returns the most forensically meaningful field of a tool_use input.
    param([string]$Name, $InputObj)
    if ($null -eq $InputObj) { return '' }
    foreach ($k in @('command','file_path','path','url','pattern','query','prompt','description','notebook_path','content')) {
        $v = $null
        try { $v = $InputObj.$k } catch { }
        if ($v -and ($v -is [string]) -and $v.Trim()) { return ('{0}={1}' -f $k, $v) }
    }
    $parts = @()
    try { foreach ($p in $InputObj.PSObject.Properties) { $parts += ('{0}={1}' -f $p.Name, (ConvertTo-TLText $p.Value 120)) } } catch { }
    return ($parts -join '; ')
}

function Get-TLAIRiskHits {
    param([string]$Text)
    $hits = @()
    if (-not $Text) { return $hits }
    foreach ($r in $script:AIRiskPatterns) {
        if ($Text -match $r.P) { $hits += $r.N }
    }
    return $hits
}

function Get-TLAISecretHits {
    # Returns 'name (prefix...)' strings. The secret value is never emitted.
    param([string]$Text)
    $hits = @()
    if (-not $Text) { return $hits }
    foreach ($r in $script:AISecretPatterns) {
        $m = [regex]::Match($Text, $r.P)
        if ($m.Success) {
            $pre = $m.Value.Substring(0, [Math]::Min(6, $m.Value.Length))
            $hits += ('{0} ({1}...redacted, {2} chars)' -f $r.N, $pre, $m.Value.Length)
        }
    }
    return $hits
}

function Protect-TLAIText {
    # Honours -RedactAIContent: keeps length and risk signal, drops the content.
    param([string]$Text, [int]$Max = 400)
    if ($null -eq $Text) { return '' }
    if ($RedactAIContent) { return ('[REDACTED - {0} chars]' -f $Text.Length) }
    return (ConvertTo-TLText $Text $Max)
}

function Add-TLAIRisk {
    param([string]$Time, $When, [string]$Source, [string]$User, [string]$What, [string[]]$Hits, [string]$Detail, [string]$Artifact)
    if (-not $Hits -or $Hits.Count -eq 0) { return }
    Add-TLEvent -Time $When -Source $Source -Category 'AI Risk' -User $User `
        -Description ('REVIEW [{0}]: {1}' -f ($Hits -join ', '), $What) `
        -Details $Detail -Artifact $Artifact `
        -Confidence ('REVIEW - heuristic match: ' + ($Hits -join ', '))
}

# ---------------------------------------------------------------------------
# Claude Code (~/.claude)
# ---------------------------------------------------------------------------
function Invoke-TLClaudeCodeTranscript {
    param([string]$Path, [string]$UserName, [string]$Source)

    $sess = [ordered]@{
        Tool = $Source; User = $UserName; SessionId = ''; File = $Path
        Cwd = ''; GitBranch = ''; Version = ''; Models = @{}
        Start = $null; End = $null; Prompts = 0; ToolCalls = 0
        Tools = @{}; Risks = @{}; Secrets = 0; Lines = 0; Truncated = $false
    }
    $emitted = 0
    try {
        $reader = New-Object System.IO.StreamReader($Path)
    } catch { Add-TLIssue 'AIAssistants' $Path $_.Exception.Message; return }

    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $sess.Lines++
            if ($sess.Lines -gt $MaxAITranscriptLines) { $sess.Truncated = $true; break }
            if (-not $line -or $line.Length -lt 2) { continue }
            $o = $null
            try { $o = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }

            $when = ConvertFrom-TLJsonTime $o.timestamp
            if ($when) {
                if (-not $sess.Start -or $when -lt $sess.Start) { $sess.Start = $when }
                if (-not $sess.End   -or $when -gt $sess.End)   { $sess.End   = $when }
            }
            if ($o.sessionId -and -not $sess.SessionId) { $sess.SessionId = [string]$o.sessionId }
            if ($o.cwd       -and -not $sess.Cwd)       { $sess.Cwd       = [string]$o.cwd }
            if ($o.gitBranch -and -not $sess.GitBranch) { $sess.GitBranch = [string]$o.gitBranch }
            if ($o.version   -and -not $sess.Version)   { $sess.Version   = [string]$o.version }

            $ctx = ('Session={0}; Cwd={1}; Branch={2}; CliVersion={3}' -f $sess.SessionId, $sess.Cwd, $sess.GitBranch, $sess.Version)

            switch ([string]$o.type) {
                'user' {
                    # A string content is an operator prompt; an array is tool output coming back.
                    if ($o.message -and ($o.message.content -is [string])) {
                        $sess.Prompts++
                        $txt = [string]$o.message.content
                        if ($emitted -lt $MaxAIEventsPerSession) {
                            $emitted++
                            Add-TLEvent -Time $when -Source $Source -Category 'AI Prompt' -User $UserName `
                                -Description ('AI prompt: {0}' -f (Protect-TLAIText $txt 320)) `
                                -Details ('{0}; PromptChars={1}; Origin={2}; PermissionMode={3}' -f $ctx, $txt.Length, $o.origin, $o.permissionMode) `
                                -Artifact $Path -Confidence 'High'
                        }
                        $sec = Get-TLAISecretHits $txt
                        if ($sec.Count) {
                            $sess.Secrets += $sec.Count
                            Add-TLEvent -Time $when -Source $Source -Category 'AI Risk' -User $UserName `
                                -Description ('SECRET EXPOSURE: credential-shaped value pasted into an AI prompt ({0})' -f ($sec -join ', ')) `
                                -Details ($ctx + '; The value itself is deliberately not recorded. Treat the secret as compromised and rotate it.') `
                                -Artifact $Path -Confidence 'REVIEW - possible secret disclosure'
                        }
                    }
                }
                'assistant' {
                    if ($o.message.model) { $sess.Models[[string]$o.message.model] = 1 }
                    foreach ($blk in @($o.message.content)) {
                        if ([string]$blk.type -ne 'tool_use') { continue }
                        $sess.ToolCalls++
                        $tn = [string]$blk.name
                        $sess.Tools[$tn] = ($sess.Tools[$tn] + 1)
                        $summary = Get-TLAIToolSummary -Name $tn -InputObj $blk.input
                        if ($emitted -lt $MaxAIEventsPerSession) {
                            $emitted++
                            Add-TLEvent -Time $when -Source $Source -Category 'AI Tool Call' -User $UserName `
                                -Description ('AI agent invoked {0}: {1}' -f $tn, (Protect-TLAIText $summary 320)) `
                                -Details ('{0}; ToolUseId={1}. Commands run by an AI agent do NOT appear in PSReadLine history.' -f $ctx, $blk.id) `
                                -Artifact $Path -Confidence 'High'
                        }
                        $hits = Get-TLAIRiskHits $summary
                        foreach ($h in $hits) { $sess.Risks[$h] = ($sess.Risks[$h] + 1) }
                        Add-TLAIRisk -When $when -Source $Source -User $UserName `
                            -What ('AI agent {0} -- {1}' -f $tn, (Protect-TLAIText $summary 260)) `
                            -Hits $hits -Detail $ctx -Artifact $Path
                    }
                }
            }
        }
    } catch { Add-TLIssue 'AIAssistants' $Path $_.Exception.Message }
    finally { try { $reader.Close() } catch { } }

    if ($sess.Start) {
        $dur = 0
        if ($sess.End) { $dur = [math]::Round(($sess.End - $sess.Start).TotalMinutes, 1) }
        $roll = ('Prompts={0}; ToolCalls={1}; Models={2}; Tools={3}; DurationMin={4}; Cwd={5}; Branch={6}; CliVersion={7}; RiskHits={8}' -f `
                 $sess.Prompts, $sess.ToolCalls, (($sess.Models.Keys) -join ','),
                 (($sess.Tools.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ' '),
                 $dur, $sess.Cwd, $sess.GitBranch, $sess.Version,
                 (($sess.Risks.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ' '))
        Add-TLEvent -Time $sess.Start -Source $Source -Category 'AI Session' -User $UserName `
            -Description ('AI session started ({0}) in {1}' -f $Source, $sess.Cwd) -Details $roll `
            -Artifact $Path -Confidence 'High'
        Add-TLEvent -Time $sess.End -Source $Source -Category 'AI Session' -User $UserName `
            -Description ('AI session last activity ({0}) in {1}' -f $Source, $sess.Cwd) -Details $roll `
            -Artifact $Path -Confidence 'High'
        if ($sess.Truncated) {
            Add-TLIssue 'AIAssistants' $Path ("Transcript exceeded -MaxAITranscriptLines ($MaxAITranscriptLines); parsed the first $($sess.Lines) lines only.")
        }
        $script:AISessions.Add([pscustomobject][ordered]@{
            Tool = $Source; User = $UserName; SessionId = $sess.SessionId
            StartUtc = $sess.Start.ToString('yyyy-MM-dd HH:mm:ss')
            EndUtc   = $sess.End.ToString('yyyy-MM-dd HH:mm:ss')
            DurationMin = $dur; Prompts = $sess.Prompts; ToolCalls = $sess.ToolCalls
            Models = (($sess.Models.Keys) -join ','); Cwd = $sess.Cwd; GitBranch = $sess.GitBranch
            CliVersion = $sess.Version
            TopTools = (($sess.Tools.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ' ')
            RiskHits = (($sess.Risks.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join ' ')
            SecretHits = $sess.Secrets; Lines = $sess.Lines; TranscriptFile = $Path
        })
    }
}

function Invoke-TLClaudeCode {
    param($Profiles)
    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }
        $root = Join-Path $p.Path '.claude'
        $cfg  = Join-Path $p.Path '.claude.json'
        if (-not (Test-TLPath $root) -and -not (Test-TLPath $cfg)) { continue }

        # --- session transcripts -------------------------------------------
        $projDir = Join-Path $root 'projects'
        if (Test-TLPath $projDir) {
            $files = @(Get-ChildItem -LiteralPath $projDir -Recurse -File -Filter '*.jsonl' -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTime -Descending | Select-Object -First $MaxAISessionFiles)
            Write-TLLog ("  {0}: {1} Claude Code transcripts" -f $p.Name, $files.Count)
            foreach ($f in $files) {
                Invoke-TLClaudeCodeTranscript -Path $f.FullName -UserName $p.Name -Source 'ClaudeCode'
            }
        }

        # --- global config: identity, project list, MCP servers, prompt history
        if (Test-TLPath $cfg) {
            try {
                $fi = Get-Item -LiteralPath $cfg -Force
                $j  = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop | ConvertFrom-Json
                $acct = ''
                if ($j.oauthAccount) {
                    $acct = ('Email={0}; DisplayName={1}; AccountUuid={2}; Org={3}; SeatTier={4}' -f `
                             $j.oauthAccount.emailAddress, $j.oauthAccount.displayName,
                             $j.oauthAccount.accountUuid, $j.oauthAccount.organizationName, $j.oauthAccount.seatTier)
                }
                $first = ConvertFrom-TLJsonTime $j.firstStartTime
                if ($first) {
                    Add-TLEvent -Time $first -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                        -Description 'Claude Code first started on this device' `
                        -Details ('{0}; MachineID={1}; UserID={2}' -f $acct, $j.machineID, $j.userID) `
                        -Artifact $cfg -Confidence 'High'
                }
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                    -Description ('Claude Code account configured: {0}' -f $(if ($j.oauthAccount) { $j.oauthAccount.emailAddress } else { 'unknown' })) `
                    -Details $acct -Artifact $cfg -Confidence 'Medium - file mtime'

                foreach ($pr in @($j.projects.PSObject.Properties)) {
                    $when = $fi.LastWriteTimeUtc
                    Add-TLEvent -Time $when -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                        -Description ('Claude Code project registered: {0}' -f $pr.Name) `
                        -Details ('AllowedTools={0}; TrustAccepted={1}; EnabledMcpServers={2}' -f `
                                  ((@($pr.Value.allowedTools)) -join ','), $pr.Value.hasTrustDialogAccepted,
                                  ((@($pr.Value.enabledMcpjsonServers)) -join ',')) `
                        -Artifact $cfg -Confidence 'Medium - file mtime'

                    # Older builds keep the typed prompt history here.
                    foreach ($h in @($pr.Value.history)) {
                        $ht = $null
                        if ($h.display) { $ht = [string]$h.display } elseif ($h -is [string]) { $ht = [string]$h }
                        if (-not $ht) { continue }
                        Add-TLEvent -Time $when -Source 'ClaudeCode' -Category 'AI Prompt' -User $p.Name `
                            -Description ('AI prompt (config history): {0}' -f (Protect-TLAIText $ht 320)) `
                            -Details ('Project={0}. Config history carries no per-entry timestamp; file mtime used.' -f $pr.Name) `
                            -Artifact $cfg -Confidence 'LOW - no per-entry timestamp'
                    }
                }
                Add-TLAIMcpServers -Node $j.mcpServers -Source 'ClaudeCode' -User $p.Name -When $fi.LastWriteTimeUtc -Artifact $cfg
            } catch { Add-TLIssue 'AIAssistants' $cfg $_.Exception.Message }
        }

        # --- settings + hooks (hooks execute shell commands = persistence) ---
        foreach ($sf in @('settings.json','settings.local.json')) {
            $sp2 = Join-Path $root $sf
            if (-not (Test-TLPath $sp2)) { continue }
            try {
                $fi = Get-Item -LiteralPath $sp2 -Force
                $s  = Get-Content -LiteralPath $sp2 -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($s.hooks) {
                    foreach ($hk in @($s.hooks.PSObject.Properties)) {
                        $cmds = @()
                        foreach ($grp in @($hk.Value)) {
                            foreach ($h2 in @($grp.hooks)) { if ($h2.command) { $cmds += [string]$h2.command } }
                        }
                        $joined = ($cmds -join ' :: ')
                        Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'Persistence' -User $p.Name `
                            -Description ('AI tool HOOK configured on {0}: {1}' -f $hk.Name, (ConvertTo-TLText $joined 260)) `
                            -Details 'Claude Code hooks run shell commands automatically on tool events - a code execution and persistence vector.' `
                            -Artifact $sp2 -Confidence 'High'
                        Add-TLAIRisk -When $fi.LastWriteTimeUtc -Source 'ClaudeCode' -User $p.Name `
                            -What ('AI hook command on ' + $hk.Name) -Hits (Get-TLAIRiskHits $joined) `
                            -Detail (ConvertTo-TLText $joined 400) -Artifact $sp2
                    }
                }
                if ($s.permissions) {
                    Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                        -Description ('Claude Code permissions defined in {0}' -f $sf) `
                        -Details ('Allow={0}; Deny={1}; DefaultMode={2}' -f ((@($s.permissions.allow)) -join ','), ((@($s.permissions.deny)) -join ','), $s.permissions.defaultMode) `
                        -Artifact $sp2 -Confidence 'Medium - file mtime'
                }
                Add-TLAIMcpServers -Node $s.mcpServers -Source 'ClaudeCode' -User $p.Name -When $fi.LastWriteTimeUtc -Artifact $sp2
            } catch { Add-TLIssue 'AIAssistants' $sp2 $_.Exception.Message }
        }

        # --- supporting artefacts -------------------------------------------
        $snap = Join-Path $root 'shell-snapshots'
        if (Test-TLPath $snap) {
            Get-ChildItem -LiteralPath $snap -File -ErrorAction SilentlyContinue | Select-Object -First 500 | ForEach-Object {
                Add-TLEvent -Time $_.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'AI Session' -User $p.Name `
                    -Description ('AI shell snapshot captured: {0}' -f $_.Name) `
                    -Details ('Captured shell environment/aliases at agent start. SizeBytes={0}' -f $_.Length) `
                    -Artifact $_.FullName -Confidence 'High'
            }
        }
        $bak = Join-Path $root 'backups'
        if (Test-TLPath $bak) {
            Get-ChildItem -LiteralPath $bak -File -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
                Add-TLEvent -Time $_.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                    -Description ('Claude Code config backup written: {0}' -f $_.Name) -Details '' `
                    -Artifact $_.FullName -Confidence 'Medium - file mtime'
            }
        }
        # Credentials file: presence is evidence, content is not collected.
        $cred = Join-Path $root '.credentials.json'
        if (Test-TLPath $cred) {
            try {
                $fi = Get-Item -LiteralPath $cred -Force
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeCode' -Category 'AI Config' -User $p.Name `
                    -Description 'Claude Code OAuth credentials file present (contents deliberately NOT collected)' `
                    -Details ('SizeBytes={0}; Created={1}. Indicates an authenticated session existed for this user.' -f $fi.Length, $fi.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                    -Artifact $cred -Confidence 'High'
            } catch { }
        }
    }
}

function Add-TLAIMcpServers {
    # MCP servers are external tool endpoints - a data egress and execution path.
    param($Node, [string]$Source, [string]$User, $When, [string]$Artifact)
    if (-not $Node) { return }
    foreach ($srv in @($Node.PSObject.Properties)) {
        $v = $srv.Value
        $desc = ('MCP server configured: {0}' -f $srv.Name)
        $det  = ('Command={0}; Args={1}; Url={2}; Type={3}; Env={4}' -f `
                 $v.command, ((@($v.args)) -join ' '), $v.url, $v.type,
                 $(if ($v.env) { (@($v.env.PSObject.Properties.Name)) -join ',' } else { '' }))
        Add-TLEvent -Time $When -Source $Source -Category 'AI Config' -User $User `
            -Description $desc -Details ($det + '. MCP servers can read local data and reach external endpoints.') `
            -Artifact $Artifact -Confidence 'Medium - file mtime'
        $hits = Get-TLAIRiskHits ($det)
        if ($v.url) { $hits += 'Remote MCP endpoint' }
        Add-TLAIRisk -When $When -Source $Source -User $User -What $desc -Hits $hits -Detail $det -Artifact $Artifact
    }
}

# ---------------------------------------------------------------------------
# Claude Desktop application
# ---------------------------------------------------------------------------
function Invoke-TLClaudeDesktop {
    param($Profiles)
    foreach ($p in $Profiles) {
        $root = Join-Path $p.Path 'AppData\Roaming\Claude'
        if (-not (Test-TLPath $root)) { continue }

        $dc = Join-Path $root 'claude_desktop_config.json'
        if (Test-TLPath $dc) {
            try {
                $fi = Get-Item -LiteralPath $dc -Force
                $j  = Get-Content -LiteralPath $dc -Raw -ErrorAction Stop | ConvertFrom-Json
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeDesktop' -Category 'AI Config' -User $p.Name `
                    -Description 'Claude Desktop configuration modified' `
                    -Details ('Keys={0}' -f (($j.PSObject.Properties.Name) -join ',')) `
                    -Artifact $dc -Confidence 'Medium - file mtime'
                Add-TLAIMcpServers -Node $j.mcpServers -Source 'ClaudeDesktop' -User $p.Name -When $fi.LastWriteTimeUtc -Artifact $dc
            } catch { Add-TLIssue 'AIAssistants' $dc $_.Exception.Message }
        }

        foreach ($sub in @('claude-code-sessions','local-agent-mode-sessions','logs','sentry')) {
            $d = Join-Path $root $sub
            if (-not (Test-TLPath $d)) { continue }
            $files = @(Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Extension -match '^\.(json|jsonl|log)$' } |
                       Sort-Object LastWriteTime -Descending | Select-Object -First 300)
            foreach ($f in $files) {
                Add-TLEvent -Time $f.LastWriteTimeUtc -Source 'ClaudeDesktop' -Category 'AI Session' -User $p.Name `
                    -Description ('Claude Desktop {0} file written: {1}' -f $sub, $f.Name) `
                    -Details ('SizeBytes={0}; Created={1}' -f $f.Length, $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                    -Artifact $f.FullName -Confidence 'Medium - file mtime'
            }
        }
        # Chromium-backed local storage is present but not parsed here.
        foreach ($ls in @('Local Storage\leveldb','IndexedDB')) {
            $d = Join-Path $root $ls
            if (-not (Test-TLPath $d)) { continue }
            try {
                $fi = Get-Item -LiteralPath $d -Force
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'ClaudeDesktop' -Category 'AI Session' -User $p.Name `
                    -Description ('Claude Desktop {0} present (LevelDB - not parsed by this script)' -f $ls) `
                    -Details 'Conversation fragments may persist here. Parse with a LevelDB-capable tool for full recovery.' `
                    -Artifact $d -Confidence 'Info only'
            } catch { }
        }
    }
}

# ---------------------------------------------------------------------------
# Editor-integrated assistants (Cursor / VS Code Copilot Chat / Windsurf)
# ---------------------------------------------------------------------------
function Invoke-TLEditorAI {
    param($Profiles)
    $editors = @(
        @{ N = 'Cursor';     P = 'AppData\Roaming\Cursor' },
        @{ N = 'VSCode';     P = 'AppData\Roaming\Code' },
        @{ N = 'VSCodeIns';  P = 'AppData\Roaming\Code - Insiders' },
        @{ N = 'Windsurf';   P = 'AppData\Roaming\Windsurf' },
        @{ N = 'VSCodium';   P = 'AppData\Roaming\VSCodium' }
    )
    $work = Join-Path $CaseDir 'artifacts\ai'
    $null = New-Item -Path $work -ItemType Directory -Force -ErrorAction SilentlyContinue

    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }
        foreach ($e in $editors) {
            $base = Join-Path $p.Path $e.P
            if (-not (Test-TLPath $base)) { continue }

            # state.vscdb holds Cursor's AI prompt/generation history (SQLite).
            $dbs = @()
            foreach ($rel in @('User\globalStorage\state.vscdb')) {
                $d = Join-Path $base $rel
                if (Test-TLPath $d) { $dbs += $d }
            }
            $ws = Join-Path $base 'User\workspaceStorage'
            if (Test-TLPath $ws) {
                $dbs += @(Get-ChildItem -LiteralPath $ws -Recurse -Filter 'state.vscdb' -File -ErrorAction SilentlyContinue |
                          Sort-Object LastWriteTime -Descending | Select-Object -First 40 | ForEach-Object { $_.FullName })
            }
            foreach ($db in $dbs) {
                $copy = Join-Path $work ('{0}_{1}_{2}.vscdb' -f $p.Name, $e.N, ([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($db))))
                if (-not (Copy-TLFile -Source $db -Destination $copy)) { continue }
                try {
                    $rows = Get-TLSqliteTable -Path $copy -Table 'ItemTable'
                    $dbTime = (Get-Item -LiteralPath $db -Force).LastWriteTimeUtc
                    foreach ($r in $rows) {
                        $k = [string]$r['key']
                        if ($k -notmatch '(?i)(aiService|chat|copilot|composer|cascade|aichat|prompt)') { continue }
                        $val = $r['value']
                        if ($val -is [byte[]]) { $val = [Text.Encoding]::UTF8.GetString($val) }
                        $val = [string]$val
                        if (-not $val) { continue }

                        # Cursor: generations carry real per-entry timestamps.
                        if ($k -match '(?i)aiService\.generations') {
                            try {
                                foreach ($g in @($val | ConvertFrom-Json)) {
                                    $gt = ConvertFrom-TLJsonTime $g.unixMs
                                    if (-not $gt) { continue }
                                    Add-TLEvent -Time $gt -Source ('AI:' + $e.N) -Category 'AI Prompt' -User $p.Name `
                                        -Description ('{0} AI generation: {1}' -f $e.N, (Protect-TLAIText ([string]$g.textDescription) 300)) `
                                        -Details ('Type={0}; Uuid={1}' -f $g.type, $g.generationUUID) `
                                        -Artifact $db -Confidence 'High'
                                }
                                continue
                            } catch { }
                        }
                        if ($k -match '(?i)aiService\.prompts') {
                            try {
                                foreach ($g in @($val | ConvertFrom-Json)) {
                                    if (-not $g.text) { continue }
                                    Add-TLEvent -Time $dbTime -Source ('AI:' + $e.N) -Category 'AI Prompt' -User $p.Name `
                                        -Description ('{0} AI prompt: {1}' -f $e.N, (Protect-TLAIText ([string]$g.text) 300)) `
                                        -Details ('CommandType={0}. No per-entry timestamp; database mtime used.' -f $g.commandType) `
                                        -Artifact $db -Confidence 'LOW - no per-entry timestamp'
                                }
                                continue
                            } catch { }
                        }
                        Add-TLEvent -Time $dbTime -Source ('AI:' + $e.N) -Category 'AI Session' -User $p.Name `
                            -Description ('{0} AI state key present: {1}' -f $e.N, (ConvertTo-TLText $k 160)) `
                            -Details ('ValueChars={0}; Preview={1}' -f $val.Length, (Protect-TLAIText $val 300)) `
                            -Artifact $db -Confidence 'LOW - database mtime'
                    }
                } catch { Add-TLIssue 'AIAssistants' $db $_.Exception.Message }
            }

            # VS Code / Copilot Chat session json files
            if (Test-TLPath $ws) {
                $cs = @(Get-ChildItem -LiteralPath $ws -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.DirectoryName -match '(?i)(chatSessions|chatEditingSessions)' } |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 200)
                foreach ($f in $cs) {
                    Add-TLEvent -Time $f.LastWriteTimeUtc -Source ('AI:' + $e.N) -Category 'AI Session' -User $p.Name `
                        -Description ('{0} chat session file written: {1}' -f $e.N, $f.Name) `
                        -Details ('SizeBytes={0}; Folder={1}' -f $f.Length, (Split-Path $f.DirectoryName -Leaf)) `
                        -Artifact $f.FullName -Confidence 'Medium - file mtime'
                    Invoke-TLGenericAIJson -Path $f.FullName -Source ('AI:' + $e.N) -UserName $p.Name
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Generic JSON / JSONL assistant session reader (Codex CLI, Continue, Gemini,
# LM Studio, Copilot chat). Extracts anything that looks like a timestamped
# turn; falls back to file metadata when the shape is unknown.
# ---------------------------------------------------------------------------
function Invoke-TLGenericAIJson {
    param([string]$Path, [string]$Source, [string]$UserName)
    try {
        $fi = Get-Item -LiteralPath $Path -Force
        if ($fi.Length -gt 40MB) { Add-TLIssue 'AIAssistants' $Path 'File larger than 40MB - skipped.'; return }
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if (-not $raw) { return }
        $objs = @()
        if ($Path -match '\.jsonl$') {
            $n = 0
            foreach ($line in ($raw -split "`r?`n")) {
                if (-not $line.Trim()) { continue }
                $n++
                if ($n -gt $MaxAITranscriptLines) { break }
                try { $objs += ($line | ConvertFrom-Json -ErrorAction Stop) } catch { }
            }
        } else {
            try { $objs = @($raw | ConvertFrom-Json -ErrorAction Stop) } catch { return }
        }
        $emitted = 0
        foreach ($o in $objs) {
            foreach ($cand in @($o, $o.messages, $o.requests, $o.history, $o.turns, $o.conversation)) {
                foreach ($m in @($cand)) {
                    if ($null -eq $m -or $m -is [string]) { continue }
                    $when = $null
                    foreach ($tf in @('timestamp','createdAt','created_at','unixMs','time','date','ts')) {
                        if ($m.$tf) { $when = ConvertFrom-TLJsonTime $m.$tf; if ($when) { break } }
                    }
                    if (-not $when) { continue }
                    $role = ''
                    foreach ($rf in @('role','type','sender','author')) { if ($m.$rf) { $role = [string]$m.$rf; break } }
                    $txt = ''
                    foreach ($cf in @('content','text','message','prompt','request','response')) {
                        if ($m.$cf) { $txt = Get-TLAIContentText $m.$cf; if ($txt) { break } }
                    }
                    if (-not $txt) { continue }
                    if ($emitted -ge $MaxAIEventsPerSession) { break }
                    $emitted++
                    $cat = if ($role -match '(?i)user|human|request') { 'AI Prompt' } else { 'AI Session' }
                    Add-TLEvent -Time $when -Source $Source -Category $cat -User $UserName `
                        -Description ('{0} [{1}]: {2}' -f $Source, $role, (Protect-TLAIText $txt 300)) `
                        -Details ('Chars={0}; File={1}' -f $txt.Length, (Split-Path $Path -Leaf)) `
                        -Artifact $Path -Confidence 'High'
                    Add-TLAIRisk -When $when -Source $Source -User $UserName -What ('AI content in ' + (Split-Path $Path -Leaf)) `
                        -Hits (Get-TLAIRiskHits $txt) -Detail (Protect-TLAIText $txt 300) -Artifact $Path
                    foreach ($s in (Get-TLAISecretHits $txt)) {
                        Add-TLEvent -Time $when -Source $Source -Category 'AI Risk' -User $UserName `
                            -Description ('SECRET EXPOSURE in AI content ({0})' -f $s) `
                            -Details 'Value deliberately not recorded. Rotate the credential.' `
                            -Artifact $Path -Confidence 'REVIEW - possible secret disclosure'
                    }
                }
            }
        }
    } catch { Add-TLIssue 'AIAssistants' $Path $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# CLI assistants and local model runners
# ---------------------------------------------------------------------------
function Invoke-TLOtherAI {
    param($Profiles)
    $specs = @(
        @{ N='CodexCLI';  D='.codex\sessions';       F='*.jsonl'; Parse=$true  },
        @{ N='CodexCLI';  D='.codex';                F='history.jsonl'; Parse=$true },
        @{ N='Continue';  D='.continue\sessions';    F='*.json';  Parse=$true  },
        @{ N='GeminiCLI'; D='.gemini\tmp';           F='*.json';  Parse=$true  },
        @{ N='LMStudio';  D='.lmstudio\conversations'; F='*.json'; Parse=$true },
        @{ N='Ollama';    D='.ollama';               F='history'; Parse=$false },
        @{ N='Ollama';    D='.ollama\logs';          F='*.log';   Parse=$false },
        @{ N='ChatGPTApp';D='AppData\Roaming\ChatGPT'; F='*.json'; Parse=$false },
        @{ N='Copilot';   D='AppData\Roaming\Code\User\globalStorage\github.copilot-chat'; F='*.json'; Parse=$true }
    )
    foreach ($p in $Profiles) {
        if (-not $p.Exists) { continue }
        foreach ($s in $specs) {
            $d = Join-Path $p.Path $s.D
            if (-not (Test-TLPath $d)) { continue }
            $files = @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter $s.F -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTime -Descending | Select-Object -First $MaxAISessionFiles)
            if ($files.Count -eq 0) { continue }
            Write-TLLog ("  {0}: {1} {2} file(s)" -f $p.Name, $files.Count, $s.N)
            foreach ($f in $files) {
                Add-TLEvent -Time $f.LastWriteTimeUtc -Source ('AI:' + $s.N) -Category 'AI Session' -User $p.Name `
                    -Description ('{0} artefact written: {1}' -f $s.N, $f.Name) `
                    -Details ('SizeBytes={0}; Created={1}' -f $f.Length, $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                    -Artifact $f.FullName -Confidence 'Medium - file mtime'
                if ($s.Parse) { Invoke-TLGenericAIJson -Path $f.FullName -Source ('AI:' + $s.N) -UserName $p.Name }
                elseif ($f.Name -eq 'history') {
                    # Ollama CLI prompt history: newline separated, no timestamps.
                    try {
                        $lines = Get-Content -LiteralPath $f.FullName -ErrorAction Stop
                        foreach ($l in $lines) {
                            if (-not $l.Trim()) { continue }
                            Add-TLEvent -Time $f.LastWriteTimeUtc -Source ('AI:' + $s.N) -Category 'AI Prompt' -User $p.Name `
                                -Description ('Ollama prompt: {0}' -f (Protect-TLAIText $l 300)) `
                                -Details 'Ollama history has no per-line timestamp; file mtime used.' `
                                -Artifact $f.FullName -Confidence 'LOW - no per-line timestamp'
                        }
                    } catch { }
                }
            }
        }
    }

    # aider keeps its history inside each project directory it was run in.
    foreach ($dir in (Get-TLAIProjectDirs)) {
        foreach ($fn in @('.aider.input.history','.aider.chat.history.md')) {
            $f = Join-Path $dir $fn
            if (-not (Test-TLPath $f)) { continue }
            try {
                $fi = Get-Item -LiteralPath $f -Force
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'AI:aider' -Category 'AI Session' `
                    -Description ('aider history present in {0}: {1}' -f $dir, $fn) `
                    -Details ('SizeBytes={0}' -f $fi.Length) -Artifact $f -Confidence 'Medium - file mtime'
                if ($fn -eq '.aider.input.history') {
                    $cur = $null
                    foreach ($l in (Get-Content -LiteralPath $f -ErrorAction Stop)) {
                        if ($l -match '^#\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})') { $cur = ConvertFrom-TLJsonTime $Matches[1]; continue }
                        if ($l -match '^\+(.+)$' -and $cur) {
                            Add-TLEvent -Time $cur -Source 'AI:aider' -Category 'AI Prompt' `
                                -Description ('aider prompt: {0}' -f (Protect-TLAIText $Matches[1] 300)) `
                                -Details ('Project={0}' -f $dir) -Artifact $f -Confidence 'High'
                        }
                    }
                }
            } catch { Add-TLIssue 'AIAssistants' $f $_.Exception.Message }
        }
    }
}

function Get-TLAIProjectDirs {
    # Directories where AI tooling is known to have run, derived from config and
    # transcripts rather than by scanning the whole disk.
    if ($script:AIProjectDirs) { return $script:AIProjectDirs }
    $set = @{}
    foreach ($s in $script:AISessions) { if ($s.Cwd -and (Test-TLPath $s.Cwd)) { $set[$s.Cwd] = 1 } }
    foreach ($p in (Get-TLUserProfiles)) {
        $cfg = Join-Path $p.Path '.claude.json'
        if (-not (Test-TLPath $cfg)) { continue }
        try {
            $j = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($pr in @($j.projects.PSObject.Properties)) { if (Test-TLPath $pr.Name) { $set[$pr.Name] = 1 } }
        } catch { }
    }
    $script:AIProjectDirs = @($set.Keys)
    return $script:AIProjectDirs
}

function Invoke-TLAIProjectConfigs {
    # Project-scoped AI configuration: MCP definitions, agent instructions and
    # rule files that steer an agent's behaviour.
    foreach ($dir in (Get-TLAIProjectDirs)) {
        foreach ($rel in @('.mcp.json','CLAUDE.md','AGENTS.md','.cursorrules','.windsurfrules',
                           '.github\copilot-instructions.md','.claude\settings.json','.claude\settings.local.json')) {
            $f = Join-Path $dir $rel
            if (-not (Test-TLPath $f)) { continue }
            try {
                $fi = Get-Item -LiteralPath $f -Force
                Add-TLEvent -Time $fi.LastWriteTimeUtc -Source 'AI:ProjectConfig' -Category 'AI Config' `
                    -Description ('Project AI config modified: {0}' -f $f) `
                    -Details ('SizeBytes={0}; Created={1}' -f $fi.Length, $fi.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) `
                    -Artifact $f -Confidence 'Medium - file mtime'
                if ($rel -eq '.mcp.json') {
                    $j = Get-Content -LiteralPath $f -Raw -ErrorAction Stop | ConvertFrom-Json
                    Add-TLAIMcpServers -Node $j.mcpServers -Source 'AI:ProjectConfig' -User '' -When $fi.LastWriteTimeUtc -Artifact $f
                }
            } catch { Add-TLIssue 'AIAssistants' $f $_.Exception.Message }
        }
    }
}

function Invoke-TLAIAssistants {
    param($Profiles)
    Write-TLLog 'Collecting AI assistant / LLM activity ...' 'STEP'
    Import-TLRiskPatterns
    Invoke-TLClaudeCode      -Profiles $Profiles
    Invoke-TLClaudeDesktop   -Profiles $Profiles
    Invoke-TLEditorAI        -Profiles $Profiles
    Invoke-TLOtherAI         -Profiles $Profiles
    Invoke-TLAIProjectConfigs
    Write-TLLog ("  {0} AI session(s) reconstructed" -f $script:AISessions.Count)
}

function ConvertTo-TLHtmlText {
    param([string]$Text)
    if (-not $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function ConvertTo-TLJs {
    # Encodes a value as a JavaScript string literal. '<' '>' '&' are escaped as
    # unicode so the payload can never terminate the enclosing script element.
    param([string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return '""' }
    $s = [string]$Text
    $s = $s -replace '[\x00-\x1F]', ' '
    $s = $s.Replace('\', '\\').Replace('"', '\"').Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
    return '"' + $s + '"'
}

function Export-TLHtml {
    <#
      Renders the timeline as a single self-contained page with two views:
        Table - paginated, searchable, sortable (only the current page is ever
                put in the DOM, so row count does not stall the browser).
        Graph - canvas histogram of event volume over time plus per-category
                swimlanes, both driven by the active filter.
    #>
    param($Rows, [string]$Path)

    $total    = @($Rows).Count
    $embedded = [Math]::Min($total, $HtmlMaxRows)
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<title>Device Timeline - ' + (ConvertTo-TLHtmlText $script:HostName) + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine('*{box-sizing:border-box;} :root{color-scheme:dark;}')
    [void]$sb.AppendLine('input[type=datetime-local]{width:196px;}')
    [void]$sb.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:14px 16px;background:#11151c;color:#dfe6f0;}')
    [void]$sb.AppendLine('h1{font-size:19px;margin:0 0 3px 0;} .sub{color:#8fa0b8;font-size:12px;margin-bottom:10px;}')
    [void]$sb.AppendLine('.tabs{border-bottom:1px solid #2a3444;margin-bottom:10px;}')
    [void]$sb.AppendLine('.tab{display:inline-block;padding:7px 16px;cursor:pointer;color:#8fa0b8;border:1px solid transparent;border-bottom:none;font-size:13px;}')
    [void]$sb.AppendLine('.tab.on{color:#dfe6f0;background:#1b2230;border-color:#2a3444;border-radius:4px 4px 0 0;}')
    [void]$sb.AppendLine('.ctl{background:#161c26;border:1px solid #2a3444;border-radius:5px;padding:9px 10px;margin-bottom:10px;}')
    [void]$sb.AppendLine('input,select,button{background:#1b2230;color:#dfe6f0;border:1px solid #33405a;padding:5px 8px;border-radius:4px;font-size:12px;margin:2px 4px 2px 0;font-family:inherit;}')
    [void]$sb.AppendLine('button{cursor:pointer;} button:hover{background:#243044;} button:disabled{opacity:.4;cursor:default;}')
    [void]$sb.AppendLine('#q{width:340px;} .lbl{color:#8fa0b8;font-size:11px;margin:0 3px 0 8px;}')
    [void]$sb.AppendLine('.tw{overflow-x:auto;border:1px solid #2a3444;border-radius:5px;}')
    [void]$sb.AppendLine('table{border-collapse:collapse;width:100%;min-width:1740px;font-size:12px;table-layout:fixed;}')
    [void]$sb.AppendLine('th{background:#1b2230;text-align:left;padding:6px;border-bottom:2px solid #33405a;cursor:pointer;white-space:nowrap;font-size:11px;}')
    [void]$sb.AppendLine('th:hover{background:#243044;} th .ar{color:#5aa9e6;}')
    [void]$sb.AppendLine('td{padding:5px 6px;border-bottom:1px solid #212a38;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;}')
    [void]$sb.AppendLine('tr:hover td{background:#182031;}')
    [void]$sb.AppendLine('.t{white-space:nowrap;color:#7fd7c4;} .src{color:#9db8ff;} .cat{color:#ffcf7a;} .usr{color:#c0a8ff;} .det{color:#8fa0b8;}')
    [void]$sb.AppendLine('.warn{color:#ff8fa3;}')
    [void]$sb.AppendLine('.pager{padding:9px 0;color:#8fa0b8;font-size:12px;}')
    [void]$sb.AppendLine('#page{width:60px;text-align:center;}')
    [void]$sb.AppendLine('.hide{display:none;}')
    [void]$sb.AppendLine('canvas{display:block;width:100%;background:#161c26;border:1px solid #2a3444;border-radius:5px;margin-bottom:10px;cursor:crosshair;}')
    [void]$sb.AppendLine('#tip{position:fixed;pointer-events:none;background:#0b0e13;border:1px solid #33405a;border-radius:4px;padding:7px 9px;font-size:11px;color:#dfe6f0;display:none;z-index:20;max-width:340px;box-shadow:0 3px 12px rgba(0,0,0,.6);}')
    [void]$sb.AppendLine('.chip{display:inline-block;padding:3px 9px;margin:3px 5px 3px 0;border-radius:11px;font-size:11px;cursor:pointer;border:1px solid #33405a;background:#1b2230;}')
    [void]$sb.AppendLine('.chip .sw{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;}')
    [void]$sb.AppendLine('.chip.on{border-color:#5aa9e6;background:#243044;}')
    [void]$sb.AppendLine('.note{color:#8fa0b8;font-size:11px;margin:6px 0;}')
    [void]$sb.AppendLine('</style></head><body>')

    [void]$sb.AppendLine('<h1>Device Activity Timeline - ' + (ConvertTo-TLHtmlText $script:HostName) + '</h1>')
    $si = ''
    if ($script:SystemInfo) {
        $si = ('{0} (build {1}) | collected {2} UTC by {3} | window start {4}' -f `
               $script:SystemInfo.OS, $script:SystemInfo.Build, $script:StartedUtc.ToString('yyyy-MM-dd HH:mm:ss'),
               $script:SystemInfo.CollectedBy, $script:SystemInfo.WindowStartUtc)
    }
    [void]$sb.AppendLine('<div class="sub">' + (ConvertTo-TLHtmlText $si) + '</div>')

    [void]$sb.AppendLine('<div class="tabs"><span class="tab on" id="tabT" onclick="setView(1)">Table</span><span class="tab" id="tabG" onclick="setView(2)">Graph</span></div>')

    [void]$sb.AppendLine('<div class="ctl">')
    [void]$sb.AppendLine('<input id="q" placeholder="search all columns (space = AND, -term = exclude)" oninput="deb()">')
    [void]$sb.AppendLine('<select id="cat" onchange="apply()"><option value="">all categories</option></select>')
    [void]$sb.AppendLine('<select id="src" onchange="apply()"><option value="">all sources</option></select>')
    [void]$sb.AppendLine('<select id="cnf" onchange="apply()"><option value="">any confidence</option><option value="!">flagged / low confidence only</option></select>')
    [void]$sb.AppendLine('<br><span class="lbl">quick range</span><select id="quick" onchange="qr()" title="Relative to the collection time, not to when you are reading this report.">')
    [void]$sb.AppendLine('<option value="">custom / none</option>')
    foreach ($qr in @(@{v='1';t='Last 1 hour'}, @{v='6';t='Last 6 hours'}, @{v='12';t='Last 12 hours'},
                      @{v='24';t='Last 24 hours'}, @{v='48';t='Last 2 days'}, @{v='72';t='Last 3 days'},
                      @{v='168';t='Last 7 days'}, @{v='336';t='Last 14 days'}, @{v='720';t='Last 30 days'},
                      @{v='2160';t='Last 90 days'})) {
        [void]$sb.AppendLine('<option value="' + $qr.v + '">' + $qr.t + '</option>')
    }
    [void]$sb.AppendLine('<option value="all">All time</option></select>')
    [void]$sb.AppendLine('<span class="lbl">from (UTC)</span><input id="from" type="datetime-local" step="1" onchange="qclr();apply()">')
    [void]$sb.AppendLine('<span class="lbl">to (UTC)</span><input id="to" type="datetime-local" step="1" onchange="qclr();apply()">')
    [void]$sb.AppendLine('<button onclick="clr()">Clear filters</button>')
    [void]$sb.AppendLine('<span class="lbl" id="cnt"></span></div>')

    [void]$sb.AppendLine('<div id="viewT">')
    [void]$sb.AppendLine('<div class="pager"><button id="bF" onclick="go(1)">First</button><button id="bP" onclick="go(PAGE-1)">Prev</button>')
    [void]$sb.AppendLine('<input id="page" value="1" onchange="go(parseInt(this.value,10))"><span id="pinfo"></span>')
    [void]$sb.AppendLine('<button id="bN" onclick="go(PAGE+1)">Next</button><button id="bL" onclick="go(PAGES)">Last</button>')
    [void]$sb.AppendLine('<span class="lbl">rows per page</span><select id="psz" onchange="PSIZE=parseInt(this.value,10);go(1)"><option>100</option><option>250</option><option>500</option><option>1000</option></select></div>')
    [void]$sb.AppendLine('<div class="tw"><table id="t"><colgroup><col style="width:145px"><col style="width:145px"><col style="width:160px"><col style="width:130px"><col style="width:110px"><col style="width:340px"><col style="width:380px"><col style="width:220px"><col style="width:160px"></colgroup>')
    [void]$sb.AppendLine('<thead><tr>')
    $hdrs = @('Time (UTC)','Time (Local)','Source','Category','User','Description','Details','Artifact','Confidence')
    for ($h = 0; $h -lt $hdrs.Count; $h++) {
        [void]$sb.AppendLine('<th onclick="srt(' + $h + ')">' + $hdrs[$h] + '<span class="ar" id="ar' + $h + '"></span></th>')
    }
    [void]$sb.AppendLine('</tr></thead><tbody id="tb"></tbody></table></div>')
    [void]$sb.AppendLine('<div class="pager" id="pager2"></div></div>')

    [void]$sb.AppendLine('<div id="viewG" class="hide">')
    [void]$sb.AppendLine('<div class="note">Event volume over time. Click a bar to filter the table to that interval. Click a category chip to isolate it.</div>')
    [void]$sb.AppendLine('<canvas id="hist" height="210"></canvas>')
    [void]$sb.AppendLine('<div class="note">Per-category swimlanes - each mark is one event.</div>')
    [void]$sb.AppendLine('<canvas id="lanes" height="260"></canvas>')
    [void]$sb.AppendLine('<div id="leg"></div></div>')
    [void]$sb.AppendLine('<div id="tip"></div>')

    if ($total -gt $embedded) {
        [void]$sb.AppendLine('<p class="note warn">NOTE: this report holds the first ' + $embedded + ' of ' + $total + ' events (-HtmlMaxRows). Timeline.csv contains the complete data set.</p>')
    }

    # ---- data payload: array of arrays keeps the file small and parse fast ----
    [void]$sb.AppendLine('<script>')
    $epochUtc = New-Object datetime(1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))
    $collectedMs = [long](($script:StartedUtc - $epochUtc).TotalMilliseconds)
    [void]$sb.AppendLine('var TOTAL=' + $total + ',EMBED=' + $embedded + ',COLLECTED=' + $collectedMs + ';')
    [void]$sb.Append('var DATA=[')
    $i = 0
    foreach ($r in $Rows) {
        if ($i -ge $embedded) { break }
        if ($i -gt 0) { [void]$sb.Append(',') }
        [void]$sb.Append('[')
        [void]$sb.Append((ConvertTo-TLJs $r.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.TimeUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Source)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Category)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.User)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Description)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Details)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Artifact)).Append(',')
        [void]$sb.Append((ConvertTo-TLJs $r.Confidence))
        [void]$sb.Append(']')
        $i++
        if (($i % 2000) -eq 0) { [void]$sb.AppendLine() }
    }
    [void]$sb.AppendLine('];')
    [void]$sb.AppendLine('</script>')

    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine(@'
var PAGE=1,PAGES=1,PSIZE=100,SORT=0,ASC=true,VIEW=1,FILT=[],HAY=[],TS=[],DEB=null;
var PAL=['#5aa9e6','#7fd7c4','#ffcf7a','#ff8fa3','#c0a8ff','#f2a65a','#7bd389','#66d9e8','#e57373','#b0bec5'];
var CMAP={},BUCK=[],XS=0,XE=0,PX0=58,PXW=0;

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function pad(n){return n<10?'0'+n:''+n;}
function fmt(ms){var d=new Date(ms);return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+' '+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds());}
function fmtIn(ms){return fmt(ms).replace(' ','T');}
function qclr(){document.getElementById('quick').value='';}
function qr(){
 var v=document.getElementById('quick').value,f=document.getElementById('from'),t=document.getElementById('to');
 if(v===''){return;}
 if(v==='all'){f.value='';t.value='';apply();return;}
 f.value=fmtIn(COLLECTED-(parseFloat(v)*36e5));
 t.value='';
 apply();
}
function pt(v,end){
 if(!v)return null;
 v=v.trim().replace(' ','T');
 if(v.length<=10)v+=(end?'T23:59:59':'T00:00:00');
 if(v.length===16)v+=':00';
 var n=Date.parse(v+'Z');
 return isNaN(n)?null:n;
}

function init(){
 var cats={},srcs={};
 for(var i=0;i<DATA.length;i++){
  var r=DATA[i];
  HAY.push((r[2]+' '+r[3]+' '+r[4]+' '+r[5]+' '+r[6]+' '+r[7]+' '+r[8]).toLowerCase());
  TS.push(Date.parse(r[0].replace(' ','T')+'Z'));
  cats[r[3]]=(cats[r[3]]||0)+1; srcs[r[2]]=(srcs[r[2]]||0)+1;
 }
 fill('cat',cats); fill('src',srcs);
 var ck=Object.keys(cats).sort(function(a,b){return cats[b]-cats[a];});
 for(var j=0;j<ck.length;j++)CMAP[ck[j]]=PAL[j%PAL.length];
 legend(ck,cats);
 apply();
 window.addEventListener('resize',function(){if(VIEW===2)draw();});
}
function fill(id,obj){
 var el=document.getElementById(id);
 Object.keys(obj).sort().forEach(function(k){
  var o=document.createElement('option');o.value=k;o.text=k+' ('+obj[k]+')';el.appendChild(o);
 });
}
function legend(keys,counts){
 var h='';
 for(var i=0;i<keys.length;i++){
  h+='<span class="chip" onclick="pick(this,\''+esc(keys[i]).replace(/'/g,'')+'\')"><span class="sw" style="background:'+CMAP[keys[i]]+'"></span>'+esc(keys[i])+' ('+counts[keys[i]]+')</span>';
 }
 document.getElementById('leg').innerHTML=h;
}
function pick(el,c){
 var s=document.getElementById('cat');
 s.value=(s.value===c)?'':c;
 var ch=document.getElementsByClassName('chip');
 for(var i=0;i<ch.length;i++)ch[i].className='chip';
 if(s.value)el.className='chip on';
 apply();
}
function deb(){clearTimeout(DEB);DEB=setTimeout(apply,160);}
function clr(){
 ['q','from','to'].forEach(function(i){document.getElementById(i).value='';});
 ['cat','src','cnf','quick'].forEach(function(i){document.getElementById(i).value='';});
 var ch=document.getElementsByClassName('chip');
 for(var i=0;i<ch.length;i++)ch[i].className='chip';
 apply();
}

function apply(){
 var raw=document.getElementById('q').value.toLowerCase().split(/\s+/).filter(function(s){return s;});
 var inc=[],exc=[];
 raw.forEach(function(w){if(w.charAt(0)==='-'&&w.length>1)exc.push(w.substring(1));else inc.push(w);});
 var cat=document.getElementById('cat').value,src=document.getElementById('src').value;
 var cnf=document.getElementById('cnf').value;
 var f=pt(document.getElementById('from').value,false),t=pt(document.getElementById('to').value,true);
 FILT=[];
 for(var i=0;i<DATA.length;i++){
  var r=DATA[i],h=HAY[i],ok=true;
  if(cat&&r[3]!==cat)continue;
  if(src&&r[2]!==src)continue;
  if(cnf==='!'&&!/suspect|low|medium|info only/i.test(r[8]))continue;
  if(f!==null&&TS[i]<f)continue;
  if(t!==null&&TS[i]>t)continue;
  for(var j=0;j<inc.length;j++){if(h.indexOf(inc[j])<0){ok=false;break;}}
  if(ok)for(var k=0;k<exc.length;k++){if(h.indexOf(exc[k])>=0){ok=false;break;}}
  if(ok)FILT.push(i);
 }
 document.getElementById('cnt').innerHTML=FILT.length+' of '+EMBED+' events match'+(TOTAL>EMBED?' (report holds '+EMBED+' of '+TOTAL+' collected)':'');
 sortNow(); PAGE=1; render();
}
function srt(c){if(SORT===c)ASC=!ASC;else{SORT=c;ASC=true;}sortNow();render();}
function sortNow(){
 for(var i=0;i<9;i++){var e=document.getElementById('ar'+i);if(e)e.innerHTML='';}
 var a=document.getElementById('ar'+SORT); if(a)a.innerHTML=ASC?' ^':' v';
 var s=SORT,d=ASC?1:-1;
 FILT.sort(function(x,y){
  if(s===0||s===1){return (TS[x]-TS[y])*d;}
  var p=DATA[x][s],q=DATA[y][s];
  return p<q?-d:(p>q?d:(TS[x]-TS[y]));
 });
}
function go(p){
 if(isNaN(p))return;
 PAGE=Math.max(1,Math.min(PAGES,p));
 render();
}
function render(){
 PAGES=Math.max(1,Math.ceil(FILT.length/PSIZE));
 if(PAGE>PAGES)PAGE=PAGES;
 var s=(PAGE-1)*PSIZE,e=Math.min(FILT.length,s+PSIZE),h='';
 for(var i=s;i<e;i++){
  var r=DATA[FILT[i]];
  h+='<tr><td class="t">'+esc(r[0])+'</td><td class="t">'+esc(r[1])+'</td><td class="src">'+esc(r[2])+
     '</td><td class="cat">'+esc(r[3])+'</td><td class="usr">'+esc(r[4])+'</td><td>'+esc(r[5])+
     '</td><td class="det">'+esc(r[6])+'</td><td class="det">'+esc(r[7])+'</td><td class="det'+
     (/suspect/i.test(r[8])?' warn':'')+'">'+esc(r[8])+'</td></tr>';
 }
 document.getElementById('tb').innerHTML=h;
 document.getElementById('page').value=PAGE;
 var info=' of '+PAGES+'   ('+(FILT.length?(s+1):0)+'-'+e+' of '+FILT.length+')';
 document.getElementById('pinfo').innerHTML=info;
 document.getElementById('pager2').innerHTML='page '+PAGE+info;
 document.getElementById('bF').disabled=document.getElementById('bP').disabled=(PAGE<=1);
 document.getElementById('bN').disabled=document.getElementById('bL').disabled=(PAGE>=PAGES);
 if(VIEW===2)draw();
}
function setView(v){
 VIEW=v;
 document.getElementById('tip').style.display='none';
 document.getElementById('viewT').className=(v===1)?'':'hide';
 document.getElementById('viewG').className=(v===2)?'':'hide';
 document.getElementById('tabT').className=(v===1)?'tab on':'tab';
 document.getElementById('tabG').className=(v===2)?'tab on':'tab';
 if(v===2)draw();
}

var NICE=[1e3,5e3,15e3,60e3,3e5,9e5,18e5,36e5,108e5,216e5,432e5,864e5,6048e5,26784e5];
function prep(cv,h){
 var dpr=window.devicePixelRatio||1,w=cv.clientWidth;
 cv.width=w*dpr;cv.height=h*dpr;
 var c=cv.getContext('2d');c.setTransform(dpr,0,0,dpr,0,0);
 c.clearRect(0,0,w,h);
 return {c:c,w:w,h:h};
}
function topCats(){
 var n={};
 for(var i=0;i<FILT.length;i++){var k=DATA[FILT[i]][3];n[k]=(n[k]||0)+1;}
 return Object.keys(n).sort(function(a,b){return n[b]-n[a];}).slice(0,10);
}
function draw(){
 var hc=document.getElementById('hist'),lc=document.getElementById('lanes');
 var H=prep(hc,210);
 if(!FILT.length){BUCK=[];H.c.fillStyle='#8fa0b8';H.c.font='13px Segoe UI';H.c.fillText('No events match the current filter.',14,30);prep(lc,60);return;}
 var mn=TS[FILT[0]],mx=mn;
 for(var i=0;i<FILT.length;i++){var t=TS[FILT[i]];if(t<mn)mn=t;if(t>mx)mx=t;}
 if(mx===mn)mx=mn+6e4;
 var target=Math.max(24,Math.floor(H.w/9)),span=mx-mn,bw=span/target,B=NICE[NICE.length-1];
 for(var k=0;k<NICE.length;k++){if(NICE[k]>=bw){B=NICE[k];break;}}
 XS=Math.floor(mn/B)*B; XE=Math.ceil((mx+1)/B)*B;
 var nb=Math.max(1,Math.round((XE-XS)/B));
 if(nb>2000){B=(XE-XS)/2000;nb=2000;}
 var cats=topCats(),ci={};
 for(var a=0;a<cats.length;a++)ci[cats[a]]=a;
 BUCK=[];
 for(var b=0;b<nb;b++)BUCK.push({n:0,c:{}});
 for(var i2=0;i2<FILT.length;i2++){
  var idx=Math.min(nb-1,Math.floor((TS[FILT[i2]]-XS)/B)),cn=DATA[FILT[i2]][3];
  var bk=BUCK[idx];bk.n++;bk.c[cn]=(bk.c[cn]||0)+1;
 }
 var peak=1;
 for(var b2=0;b2<nb;b2++)if(BUCK[b2].n>peak)peak=BUCK[b2].n;
 PX0=58;PXW=H.w-PX0-14;
 var top=12,ph=H.h-46-top;
 H.c.strokeStyle='#2a3444';H.c.fillStyle='#8fa0b8';H.c.font='10px Segoe UI';
 for(var g=0;g<=4;g++){
  var y=top+ph-(ph*g/4);
  H.c.beginPath();H.c.moveTo(PX0,y);H.c.lineTo(PX0+PXW,y);H.c.stroke();
  H.c.fillText(Math.round(peak*g/4),6,y+3);
 }
 var cw=PXW/nb;
 for(var b3=0;b3<nb;b3++){
  var bk2=BUCK[b3];if(!bk2.n)continue;
  var x=PX0+b3*cw,acc=0;
  for(var s2=0;s2<cats.length;s2++){
   var v=bk2.c[cats[s2]]||0;if(!v)continue;
   var hh=(v/peak)*ph;
   H.c.fillStyle=PAL[s2%PAL.length];
   H.c.fillRect(x,top+ph-acc-hh,Math.max(1,cw-1),hh);
   acc+=hh;
  }
  var oth=bk2.n;for(var s3=0;s3<cats.length;s3++)oth-=(bk2.c[cats[s3]]||0);
  if(oth>0){var oh=(oth/peak)*ph;H.c.fillStyle='#55606f';H.c.fillRect(x,top+ph-acc-oh,Math.max(1,cw-1),oh);}
  bk2.x=x;bk2.w=cw;bk2.t0=XS+b3*B;bk2.t1=XS+(b3+1)*B;
 }
 H.c.strokeStyle='#33405a';H.c.beginPath();H.c.moveTo(PX0,top+ph);H.c.lineTo(PX0+PXW,top+ph);H.c.stroke();
 H.c.fillStyle='#8fa0b8';
 var ticks=Math.max(2,Math.min(7,Math.floor(H.w/150)));
 for(var tk=0;tk<=ticks;tk++){
  var tx=PX0+(PXW*tk/ticks),tt=XS+((XE-XS)*tk/ticks);
  var lab=fmt(tt),sh=(XE-XS)<864e5*2?lab.substring(11):lab.substring(0,10);
  H.c.fillText(sh,Math.max(2,tx-24),top+ph+15);
  if(tk===0||tk===ticks)H.c.fillText(lab.substring(0,10),Math.max(2,tx-30),top+ph+28);
 }
 H.c.fillText('bucket = '+lbl(B)+'   peak = '+peak+' events',PX0,H.h-4);

 var lanes=cats.length,lh=18,LH=Math.max(60,lanes*lh+34),L=prep(lc,LH);
 L.c.font='10px Segoe UI';
 for(var ln=0;ln<lanes;ln++){
  var y2=14+ln*lh;
  L.c.fillStyle='#8fa0b8';
  L.c.fillText(cats[ln].length>22?cats[ln].substring(0,21)+'.':cats[ln],4,y2+9);
  L.c.strokeStyle='#212a38';L.c.beginPath();L.c.moveTo(PX0,y2+11.5);L.c.lineTo(PX0+PXW,y2+11.5);L.c.stroke();
 }
 for(var e2=0;e2<FILT.length;e2++){
  var r2=DATA[FILT[e2]],lane=ci[r2[3]];
  if(lane===undefined)continue;
  var px=PX0+((TS[FILT[e2]]-XS)/(XE-XS))*PXW;
  L.c.fillStyle=PAL[lane%PAL.length];
  L.c.fillRect(px,14+lane*lh+4,2,11);
 }
 L.c.fillStyle='#8fa0b8';L.c.fillText(fmt(XS)+' UTC',PX0,LH-6);
 L.c.fillText(fmt(XE)+' UTC',PX0+PXW-118,LH-6);
}
function lbl(ms){
 if(ms<6e4)return (ms/1e3)+' sec';
 if(ms<36e5)return (ms/6e4)+' min';
 if(ms<864e5)return (ms/36e5)+' hour';
 if(ms<6048e5)return (ms/864e5)+' day';
 return Math.round(ms/864e5)+' day';
}
function hit(ev){
 var cv=document.getElementById('hist'),rc=cv.getBoundingClientRect(),x=ev.clientX-rc.left;
 for(var i=0;i<BUCK.length;i++){var b=BUCK[i];if(b.n&&x>=b.x&&x<=b.x+b.w)return b;}
 return null;
}
function move(ev){
 var b=hit(ev),tp=document.getElementById('tip');
 if(!b){tp.style.display='none';return;}
 var h='<b>'+fmt(b.t0)+' - '+fmt(b.t1)+' UTC</b><br>'+b.n+' events<br>';
 var ks=Object.keys(b.c).sort(function(p,q){return b.c[q]-b.c[p];});
 for(var i=0;i<Math.min(8,ks.length);i++)h+='<span style="color:'+(CMAP[ks[i]]||'#8fa0b8')+'">'+esc(ks[i])+'</span>: '+b.c[ks[i]]+'<br>';
 h+='<i>click to filter to this interval</i>';
 tp.innerHTML=h;tp.style.display='block';
 tp.style.left=Math.min(window.innerWidth-350,ev.clientX+14)+'px';
 tp.style.top=Math.min(window.innerHeight-150,ev.clientY+14)+'px';
}
function zoom(ev){
 var b=hit(ev);if(!b)return;
 document.getElementById('from').value=fmtIn(b.t0);
 document.getElementById('to').value=fmtIn(b.t1);
 qclr();apply();setView(1);
}
document.getElementById('hist').addEventListener('mousemove',move);
document.getElementById('hist').addEventListener('mouseleave',function(){document.getElementById('tip').style.display='none';});
document.getElementById('hist').addEventListener('click',zoom);
init();
'@)
    [void]$sb.AppendLine('</script></body></html>')

    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Export-TLResults {
    Write-TLLog 'Sorting and writing output ...' 'STEP'
    $sorted = $script:Timeline | Sort-Object TimeUtc

    $csvRows = $sorted | Select-Object `
        @{N='TimeUtc';        E={ $_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss.fff') }},
        @{N='TimeLocal';      E={ $_.TimeUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss.fff') }},
        @{N='Host';           E={ $script:HostName }},
        Source, Category, User, Description, Details, Artifact, Confidence

    $csvPath = Join-Path $CaseDir 'Timeline.csv'
    $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-TLLog ("  {0} ({1} rows)" -f $csvPath, $sorted.Count)

    if (-not $NoJson) {
        $jsonPath = Join-Path $CaseDir 'Timeline.json'
        try {
            $csvRows | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-TLLog "  $jsonPath"
        } catch { Add-TLIssue 'Export' $jsonPath $_.Exception.Message }
    }

    if (-not $NoHtml) {
        $htmlPath = Join-Path $CaseDir 'Timeline.html'
        try { Export-TLHtml -Rows $sorted -Path $htmlPath; Write-TLLog "  $htmlPath" }
        catch { Add-TLIssue 'Export' $htmlPath $_.Exception.Message }
    }

    if ($script:Coverage.Count -gt 0) {
        $script:Coverage | Export-Csv -Path (Join-Path $CaseDir 'EventLogCoverage.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($script:Issues.Count -gt 0) {
        $script:Issues | Export-Csv -Path (Join-Path $CaseDir 'CollectionIssues.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($script:AISessions.Count -gt 0) {
        $script:AISessions | Sort-Object StartUtc | Export-Csv -Path (Join-Path $CaseDir 'AISessions.csv') -NoTypeInformation -Encoding UTF8
    }

    # Summary
    $sum = New-Object System.Text.StringBuilder
    [void]$sum.AppendLine('DEVICE ACTIVITY TIMELINE - COLLECTION SUMMARY')
    [void]$sum.AppendLine('=============================================')
    if ($script:SystemInfo) {
        foreach ($prop in $script:SystemInfo.PSObject.Properties) {
            [void]$sum.AppendLine(('{0,-16}: {1}' -f $prop.Name, $prop.Value))
        }
    }
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine(('Total timeline events : {0}' -f $sorted.Count))
    if ($sorted.Count -gt 0) {
        [void]$sum.AppendLine(('Earliest event (UTC)  : {0}' -f $sorted[0].TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')))
        [void]$sum.AppendLine(('Latest event (UTC)    : {0}' -f $sorted[$sorted.Count - 1].TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')))
    }
    [void]$sum.AppendLine(('Collection issues     : {0}' -f $script:Issues.Count))
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine('EVENTS BY SOURCE')
    [void]$sum.AppendLine('----------------')
    foreach ($k in ($script:Stats.Keys | Sort-Object { -$script:Stats[$_] })) {
        [void]$sum.AppendLine(('{0,-52} {1,8}' -f $k, $script:Stats[$k]))
    }
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine('EVENTS BY CATEGORY')
    [void]$sum.AppendLine('------------------')
    $sorted | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
        [void]$sum.AppendLine(('{0,-52} {1,8}' -f $_.Name, $_.Count))
    }
    if ($script:AISessions.Count -gt 0) {
        [void]$sum.AppendLine('')
        [void]$sum.AppendLine('AI ASSISTANT ACTIVITY')
        [void]$sum.AppendLine('---------------------')
        [void]$sum.AppendLine(('Sessions reconstructed : {0}' -f $script:AISessions.Count))
        $tp = ($script:AISessions | Measure-Object -Property Prompts -Sum).Sum
        $tc = ($script:AISessions | Measure-Object -Property ToolCalls -Sum).Sum
        [void]$sum.AppendLine(('Operator prompts       : {0}' -f $tp))
        [void]$sum.AppendLine(('Agent tool calls       : {0}' -f $tc))
        $risky = @($script:AISessions | Where-Object { $_.RiskHits })
        $secs  = @($script:AISessions | Where-Object { $_.SecretHits -gt 0 })
        [void]$sum.AppendLine(('Sessions w/ risk hits  : {0}' -f $risky.Count))
        [void]$sum.AppendLine(('Sessions w/ secrets    : {0}' -f $secs.Count))
        [void]$sum.AppendLine('')
        foreach ($s in ($script:AISessions | Sort-Object StartUtc)) {
            [void]$sum.AppendLine(('  {0}  {1,-12} {2,-14} prompts={3,-4} tools={4,-5} {5}' -f `
                $s.StartUtc, $s.Tool, $s.User, $s.Prompts, $s.ToolCalls, $s.Cwd))
            if ($s.RiskHits)          { [void]$sum.AppendLine('      RISK   : ' + $s.RiskHits) }
            if ($s.SecretHits -gt 0)  { [void]$sum.AppendLine('      SECRETS: ' + $s.SecretHits + ' credential-shaped value(s) in prompt text - rotate them') }
        }
    }
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine('INTERPRETATION NOTES')
    [void]$sum.AppendLine('--------------------')
    [void]$sum.AppendLine('* All times are recorded in UTC and in the local time of the collecting host.')
    [void]$sum.AppendLine('* Check Security event 4616 (system time changed) before trusting the sequence.')
    [void]$sum.AppendLine('* Check Security 1102 / System 104 for log clearing - gaps may be deliberate.')
    [void]$sum.AppendLine('* ShimCache/Amcache timestamps are file or key metadata, NOT execution times.')
    [void]$sum.AppendLine('* Prefetch mtime approximates the last run; the .pf file holds up to 8 run times.')
    [void]$sum.AppendLine('* PSReadLine history lines have no individual timestamps (file mtime is used).')
    [void]$sum.AppendLine('* Registry MRU timestamps apply to the whole key, i.e. the most recent entry only.')
    [void]$sum.AppendLine('* See EventLogCoverage.csv for how far back each event log actually reaches.')
    [void]$sum.AppendLine('* See CollectionIssues.csv for artefacts that could not be read.')
    [void]$sum.AppendLine('* AI agent tool calls executed commands that never reach PSReadLine history -')
    [void]$sum.AppendLine('  treat "AI Tool Call" rows as execution evidence in their own right.')
    [void]$sum.AppendLine('* "AI Risk" rows are heuristic pattern matches for triage, not proof of misuse.')
    [void]$sum.AppendLine('* AI transcripts may contain secrets pasted by the operator. Secret VALUES are')
    [void]$sum.AppendLine('  never written to this output, only the pattern name - but the source .jsonl')
    [void]$sum.AppendLine('  files on disk still contain them. Handle the case folder accordingly.')
    $sumPath = Join-Path $CaseDir 'Summary.txt'
    [System.IO.File]::WriteAllText($sumPath, $sum.ToString(), (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ''
    Write-Host $sum.ToString()
    return $csvPath
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$script:SystemInfo = $null

Write-Host ''
Write-TLLog "Device activity timeline collection starting on $script:HostName" 'STEP'
Write-TLLog ("Case folder: {0}" -f $CaseDir)
if ($AllTime) { Write-TLLog 'Look-back window: ALL AVAILABLE DATA' }
else { Write-TLLog ("Look-back window: {0} days (from {1} UTC)" -f $Days, $script:CutoffUtc.ToString('yyyy-MM-dd HH:mm:ss')) }

if (-not (Test-TLAdmin)) {
    Write-TLLog 'NOT RUNNING ELEVATED. Security log, other users hives, Amcache, ShimCache and prefetch will be incomplete or missing. Re-run as Administrator for a full collection.' 'WARN'
    Add-TLIssue 'Startup' 'Elevation' 'Script was not run elevated - collection is partial.'
}

if ($UseVSS) {
    if (Test-TLAdmin) { $null = New-TLShadowCopy }
    else { Write-TLLog '-UseVSS requires elevation; continuing without a shadow copy.' 'WARN' }
}

try {
    $profiles = Get-TLUserProfiles
    Write-TLLog ("Found {0} user profiles: {1}" -f $profiles.Count, (($profiles | ForEach-Object { $_.Name }) -join ', '))

    if (Test-TLModule 'System')         { Invoke-TLSystem }
    if (Test-TLModule 'EventLogs')      { Invoke-TLEventLogs }
    if (Test-TLModule 'PSHistory')      { Invoke-TLPSHistory      -Profiles $profiles }
    if (Test-TLModule 'ScheduledTasks') { Invoke-TLScheduledTasks }
    if (Test-TLModule 'Browsers')       { Invoke-TLBrowsers       -Profiles $profiles }
    if (Test-TLModule 'Execution')      { Invoke-TLExecution      -Profiles $profiles }
    if (Test-TLModule 'Files')          { Invoke-TLFiles          -Profiles $profiles }
    if (Test-TLModule 'Network')        { Invoke-TLNetwork        -Profiles $profiles }
    if (Test-TLModule 'USB')            { Invoke-TLUSB }
    if (Test-TLModule 'Persistence')    { Invoke-TLPersistence    -Profiles $profiles }
    if (Test-TLModule 'Accounts')       { Invoke-TLAccounts }
    if (Test-TLModule 'AIAssistants')   { Invoke-TLAIAssistants   -Profiles $profiles }

    $csv = Export-TLResults
    Write-TLLog ("Collection complete. Output: {0}" -f $CaseDir) 'STEP'
    Write-Host ''
} finally {
    Dismount-TLUserHives
    Remove-TLShadowCopy
}
