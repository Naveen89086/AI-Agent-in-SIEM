<# -----------------------------------------------------------------------------
  SIEM Endpoint Agent (Windows)
  Ships security-relevant Windows events to the SIEM HTTP collector.
  Works without admin for most security channels when read access is granted.
  Usage:
      .\collect.ps1 -CollectorUrl http://localhost:8000/api/v1/ingest/events `
                    -SourceName "corp-windows-01" -IntervalSeconds 60
  ---------------------------------------------------------------------------- #>
param(
    [string]$CollectorUrl = "http://localhost:8000/api/v1/ingest/events",
    [string]$SourceName = $env:COMPUTERNAME,
    [int]$IntervalSeconds = 60,
    [switch]$SysmonEnabled = $false
)

$ErrorActionPreference = "Stop"

# High-value Windows Security event IDs we care about
$EventIds = @(4624, 4625, 4634, 4647, 4672, 4688, 4720, 4724, 4726, 4732, 4733,
    4740, 4741, 4756, 4768, 4769, 4771, 4776, 1102)

function Send-Batch($events) {
    if ($events.Count -eq 0) { return }
    $payload = @{ events = @($events) } | ConvertTo-Json -Depth 10 -Compress
    try {
        Invoke-RestMethod -Uri $CollectorUrl -Method Post -ContentType "application/json" `
            -Body $payload -TimeoutSec 15 | Out-Null
    }
    catch {
        Write-Warning "Failed to ship $($events.Count) events: $($_.Exception.Message)"
    }
}

$lastId = 0
while ($true) {
    $batch = @()
    $filter = @{ Id = $EventIds; StartTime = (Get-Date).AddHours(-1) }
    if ($lastId -gt 0) { $filter.Id = $EventIds }  # incremental via record ID below
    try {
        $records = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction SilentlyContinue
        foreach ($rec in $records) {
            $props = @{}
            try { $rec.Properties | ForEach-Object { } } catch { }
            $detail = ($rec.Message -replace "`r", "" -replace "`n", " | ").Substring(0, [Math]::Min(4000, $rec.Message.Length))
            $batch += @{
                message     = $detail
                source_type = "windows"
                source_name = $SourceName
                host        = $env:COMPUTERNAME
                timestamp   = $rec.TimeCreated.ToString("o")
                extra       = @{
                    event_id = $rec.Id
                    provider = $rec.ProviderName
                    log_name = $rec.LogName
                    level    = $rec.LevelDisplayName
                    record_id = $rec.RecordId
                    computer = $rec.MachineName
                }
                tags       = @("windows", "security")
            }
        }
    }
    catch { Write-Warning "Windows event query failed: $($_.Exception.Message)" }
    Send-Batch $batch
    Start-Sleep -Seconds $IntervalSeconds
}
