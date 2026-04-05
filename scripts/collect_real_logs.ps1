param(
    [int]$Minutes = 180,
    [int]$MaxEvents = 8000,
    [string]$SystemOutPath = "",
    [string]$NetworkOutPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-ParentDirectory {
    param([string]$FilePath)

    $directory = Split-Path -Parent $FilePath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
}

function Resolve-OutputPath {
    param(
        [string]$Path,
        [string]$DefaultName
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        return Join-Path $repoRoot $DefaultName
    }

    return $Path
}

function Normalize-Text {
    param([object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return ([string]$Value -replace '\s+', ' ').Trim()
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $map = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            $name = [string]$node.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }
            $map[$name] = [string]$node.'#text'
        }
    }
    catch {
    }

    return $map
}

function Get-FirstValue {
    param(
        [hashtable]$Data,
        [string[]]$Keys
    )

    foreach ($key in $Keys) {
        if ($Data.ContainsKey($key)) {
            $value = Normalize-Text $Data[$key]
            if (-not [string]::IsNullOrWhiteSpace($value) -and $value -notin @('-', '::1', '127.0.0.1')) {
                return $value
            }
        }
    }

    return ""
}

function Get-IntValue {
    param(
        [hashtable]$Data,
        [string[]]$Keys
    )

    foreach ($key in $Keys) {
        if ($Data.ContainsKey($key)) {
            $value = Normalize-Text $Data[$key]
            if ([int]::TryParse($value, [ref]$parsed)) {
                return [int]$parsed
            }
        }
    }

    return 0
}

function Get-LogLevel {
    param(
        [int]$EventId,
        [string]$DefaultLevel = "INFORMATION"
    )

    switch ($EventId) {
        4625 { return "WARNING" }
        2011 { return "WARNING" }
        2052 { return "WARNING" }
        default { return $DefaultLevel }
    }
}

function New-EventRow {
    param(
        [string]$Timestamp,
        [string]$LogType,
        [string]$EventType,
        [int]$EventId,
        [string]$EventMessage,
        [string]$SourceIp = "",
        [string]$DestinationIp = "",
        [int]$SourcePort = 0,
        [int]$DestinationPort = 0,
        [string]$Protocol = "",
        [string]$User = "",
        [string]$Service = "",
        [int]$FailedCount = 0,
        [string]$LogLevel = "INFORMATION",
        [string]$QueryName = "",
        [string]$QueryType = "",
        [string]$Action = ""
    )

    [PSCustomObject]@{
        timestamp = $Timestamp
        log_type = $LogType
        event_type = $EventType
        event_id = $EventId
        event_message = $EventMessage
        source_ip = $SourceIp
        destination_ip = $DestinationIp
        source_port = $SourcePort
        destination_port = $DestinationPort
        protocol = $Protocol
        user = $User
        service = $Service
        failed_count = $FailedCount
        log_level = $LogLevel
        query_name = $QueryName
        query_type = $QueryType
        action = $Action
    }
}

function Group-EventRows {
    param([object[]]$Rows)

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return @()
    }

    $groups = $Rows | Group-Object -Property log_type, event_type, event_id, event_message, source_ip, destination_ip, source_port, destination_port, protocol, user, service, query_name, query_type, action, log_level

    $aggregated = foreach ($group in $groups) {
        $ordered = $group.Group | Sort-Object timestamp
        $first = $ordered[0]
        $last = $ordered[-1]
        $firstTs = [DateTimeOffset]::Parse($first.timestamp)
        $lastTs = [DateTimeOffset]::Parse($last.timestamp)
        $durationSec = [Math]::Max(($lastTs - $firstTs).TotalSeconds, 0)

        [PSCustomObject]@{
            timestamp = $first.timestamp
            log_type = $first.log_type
            event_type = $first.event_type
            event_id = [int]$first.event_id
            event_message = $first.event_message
            source_ip = $first.source_ip
            destination_ip = $first.destination_ip
            source_port = [int]$first.source_port
            destination_port = [int]$first.destination_port
            protocol = $first.protocol
            user = $first.user
            service = $first.service
            failed_count = [int]$first.failed_count
            log_level = $first.log_level
            query_name = $first.query_name
            query_type = $first.query_type
            action = $first.action
            connection_observation_count = @($group.Group).Count
            duration_sec = [Math]::Round($durationSec, 3)
        }
    }

    return $aggregated
}

function Collect-SecurityLogs {
    param(
        [int]$Minutes,
        [int]$MaxEvents
    )

    $startTime = (Get-Date).AddMinutes(-$Minutes)
    $rows = @()

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $startTime; Id = 4624, 4625 } -MaxEvents $MaxEvents -ErrorAction Stop
        foreach ($event in $events) {
            $data = Get-EventDataMap $event
            $eventType = if ($event.Id -eq 4624) { 'LOGIN_SUCCESS' } else { 'LOGIN_FAILED' }
            $sourceIp = Get-FirstValue $data @('IpAddress', 'SourceNetworkAddress', 'ClientAddress', 'SourceAddress')
            $user = Get-FirstValue $data @('TargetUserName', 'SubjectUserName', 'AccountName')
            $service = Normalize-Text $event.ProviderName
            $failedCount = if ($eventType -eq 'LOGIN_FAILED') { 1 } else { 0 }
            $logLevel = Get-LogLevel -EventId ([int]$event.Id) -DefaultLevel 'INFORMATION'

            $rows += New-EventRow `
                -Timestamp $event.TimeCreated.ToString('o') `
                -LogType 'security' `
                -EventType $eventType `
                -EventId ([int]$event.Id) `
                -EventMessage (Normalize-Text $event.Message) `
                -SourceIp $sourceIp `
                -User $user `
                -Service $service `
                -FailedCount $failedCount `
                -LogLevel $logLevel
        }
    }
    catch {
        Write-Warning "Security log query returned no accessible events: $($_.Exception.Message)"
        return @()
    }

    return Group-EventRows $rows
}

function Collect-FirewallLogs {
    param(
        [int]$Minutes,
        [int]$MaxEvents
    )

    $startTime = (Get-Date).AddMinutes(-$Minutes)
    $rows = @()

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop
        foreach ($event in $events) {
            $data = Get-EventDataMap $event
            $eventType = switch ([int]$event.Id) {
                2010 { 'FIREWALL_PROFILE_CHANGE' }
                2011 { 'FIREWALL_BLOCK_NOTIFICATION' }
                2052 { 'FIREWALL_RULE_DELETED' }
                2059 { 'FIREWALL_RULE_MODIFIED' }
                2097 { 'FIREWALL_RULE_ADDED' }
                2099 { 'FIREWALL_RULE_MODIFIED' }
                default { 'FIREWALL_EVENT' }
            }

            $protocol = Get-FirstValue $data @('Protocol')
            if ([string]::IsNullOrWhiteSpace($protocol)) {
                $protocol = if ($event.Id -eq 2010) { 'N/A' } else { '' }
            }

            $sourceIp = Get-FirstValue $data @('SourceAddress', 'LocalAddress', 'RemoteAddress')
            $destinationIp = Get-FirstValue $data @('DestinationAddress', 'LocalAddress', 'RemoteAddress')
            $sourcePort = Get-IntValue $data @('SourcePort', 'LocalPort', 'Port')
            $destinationPort = Get-IntValue $data @('DestinationPort', 'Port', 'LocalPort')
            $action = Get-FirstValue $data @('Action', 'Direction')
            $service = Normalize-Text $event.ProviderName
            $logLevel = Get-LogLevel -EventId ([int]$event.Id) -DefaultLevel 'INFORMATION'

            $rows += New-EventRow `
                -Timestamp $event.TimeCreated.ToString('o') `
                -LogType 'firewall' `
                -EventType $eventType `
                -EventId ([int]$event.Id) `
                -EventMessage (Normalize-Text $event.Message) `
                -SourceIp $sourceIp `
                -DestinationIp $destinationIp `
                -SourcePort $sourcePort `
                -DestinationPort $destinationPort `
                -Protocol $protocol `
                -Service $service `
                -LogLevel $logLevel `
                -Action $action
        }
    }
    catch {
        Write-Warning "Firewall log query returned no accessible events: $($_.Exception.Message)"
        return @()
    }

    return Group-EventRows $rows
}

function Collect-DnsLogs {
    param(
        [int]$Minutes,
        [int]$MaxEvents
    )

    $startTime = (Get-Date).AddMinutes(-$Minutes)
    $rows = @()

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop
        foreach ($event in $events) {
            $data = Get-EventDataMap $event
            $queryName = Get-FirstValue $data @('QueryName', 'Name', 'HostName')
            $queryType = Get-FirstValue $data @('QueryType', 'Type')
            $sourceIp = Get-FirstValue $data @('InterfaceIpAddress', 'Address', 'ClientAddress')
            $destinationIp = Get-FirstValue $data @('ServerAddress', 'DnsServerAddress', 'DestinationAddress')
            $eventType = 'DNS_EVENT'
            $logLevel = Get-LogLevel -EventId ([int]$event.Id) -DefaultLevel 'INFORMATION'

            $rows += New-EventRow `
                -Timestamp $event.TimeCreated.ToString('o') `
                -LogType 'dns' `
                -EventType $eventType `
                -EventId ([int]$event.Id) `
                -EventMessage (Normalize-Text $event.Message) `
                -SourceIp $sourceIp `
                -DestinationIp $destinationIp `
                -Protocol 'DNS' `
                -LogLevel $logLevel `
                -QueryName $queryName `
                -QueryType $queryType
        }
    }
    catch {
        Write-Warning "DNS log query returned no accessible events: $($_.Exception.Message)"
        return @()
    }

    return Group-EventRows $rows
}

$SystemOutPath = Resolve-OutputPath -Path $SystemOutPath -DefaultName 'data\system_logs.csv'
$NetworkOutPath = Resolve-OutputPath -Path $NetworkOutPath -DefaultName 'data\network_logs.csv'

Ensure-ParentDirectory -FilePath $SystemOutPath
Ensure-ParentDirectory -FilePath $NetworkOutPath

$systemRows = Collect-SecurityLogs -Minutes $Minutes -MaxEvents $MaxEvents
$firewallRows = Collect-FirewallLogs -Minutes $Minutes -MaxEvents $MaxEvents
$dnsRows = Collect-DnsLogs -Minutes $Minutes -MaxEvents $MaxEvents

$networkRows = @()
if ($firewallRows) { $networkRows += $firewallRows }
if ($dnsRows) { $networkRows += $dnsRows }

$systemCount = @($systemRows).Count
$networkCount = @($networkRows).Count

if ($systemCount -eq 0) {
    '"timestamp","source_ip","user","service","event","event_id","failed_count","log_level"' |
        Set-Content -Path $SystemOutPath -Encoding UTF8
}
else {
    $systemRows | Select-Object timestamp, source_ip, user, service, event_type, event_id, failed_count, log_level |
        ForEach-Object {
            [PSCustomObject]@{
                timestamp = $_.timestamp
                source_ip = $_.source_ip
                user = $_.user
                service = $_.service
                event = $_.event_type
                event_id = $_.event_id
                failed_count = $_.failed_count
                log_level = $_.log_level
            }
        } | Export-Csv -Path $SystemOutPath -NoTypeInformation -Encoding UTF8
}

if ($networkCount -eq 0) {
    '"timestamp","log_type","event_type","event_id","event_message","source_ip","destination_ip","source_port","destination_port","protocol","user","service","failed_count","log_level","query_name","query_type","action","connection_observation_count","duration_sec"' |
        Set-Content -Path $NetworkOutPath -Encoding UTF8
}
else {
    $networkRows | Select-Object timestamp, log_type, event_type, event_id, event_message, source_ip, destination_ip, source_port, destination_port, protocol, user, service, failed_count, log_level, query_name, query_type, action, connection_observation_count, duration_sec |
        Export-Csv -Path $NetworkOutPath -NoTypeInformation -Encoding UTF8
}

Write-Output "Security logs written: $SystemOutPath ($systemCount rows)"
Write-Output "Event logs written: $NetworkOutPath ($networkCount rows)"