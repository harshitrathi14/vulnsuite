# Read-only Windows Event Log adapter. No raw messages, command lines or credentials.
[CmdletBinding()]
param(
    [string]$CursorJson = '{}',
    [ValidateRange(1,500)][int]$MaxEvents = 200
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$cursors = @{}
$old = ConvertFrom-Json $CursorJson
foreach ($prop in $old.PSObject.Properties) { $cursors[$prop.Name] = [long]$prop.Value }
$records = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[string]]::new()
$reset = $false
$more = $false
$channels = @(
    @{Name='Security'; Filter='(EventID=4624 or EventID=4625 or EventID=5140)'},
    @{Name='Microsoft-Windows-Sysmon/Operational'; Filter='EventID=1'}
)
# Separate budgets prevent a busy Security channel starving process telemetry.
$perChannel = [Math]::Max(1, [Math]::Floor($MaxEvents / $channels.Count))
$allowed = @('IpAddress','LogonType','TargetUserName','TargetDomainName',
    'SubjectUserName','SubjectDomainName','ProcessId','ParentProcessId','Image',
    'ParentImage','User','Hashes')
foreach ($channel in $channels) {
    $name = $channel.Name
    if ($records.Count -ge $MaxEvents) { $more = $true; break }
    try {
        $latest = Get-WinEvent -LogName $name -MaxEvents 1 -ErrorAction Stop
        if (-not $cursors.ContainsKey($name)) {
            # Enrollment starts at the latest record. Subsequent runs resume durably.
            $cursors[$name] = [long]$latest.RecordId
            continue
        }
        if ([long]$latest.RecordId -lt [long]$cursors[$name]) {
            $reset = $true
            $cursors[$name] = 0
        }
        $after = [long]$cursors[$name]
        $query = "*[System[($($channel.Filter)) and EventRecordID > $after]]"
        $take = [Math]::Min($perChannel, $MaxEvents - $records.Count)
        try {
            $events = @(Get-WinEvent -LogName $name -FilterXPath $query -Oldest -MaxEvents ($take + 1) -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
            else { throw }
        }
        if ($events.Count -gt $take) { $more = $true }
        foreach ($entry in ($events | Select-Object -First $take)) {
            [xml]$xml = $entry.ToXml()
            $data = @{}
            foreach ($field in $xml.Event.EventData.Data) {
                $key = [string]$field.Name
                if ($allowed -contains $key) {
                    $value = [string]$field.'#text'
                    if ($value.Length -le 4096) { $data[$key] = $value }
                }
            }
            $records.Add(@{
                Provider = [string]$entry.ProviderName
                EventId = [int]$entry.Id
                RecordId = [string]$entry.RecordId
                TimeCreated = $entry.TimeCreated.ToUniversalTime().ToString('o')
                Keywords = [string]$xml.Event.System.Keywords
                EventData = $data
            })
            $cursors[$name] = [long]$entry.RecordId
        }
    } catch {
        # Return only channel names; exception text may contain host details.
        $errors.Add($name)
    }
}
@{records=@($records.ToArray()); cursors=$cursors; errors=@($errors.ToArray());
  reset=$reset; has_more=$more} | ConvertTo-Json -Depth 6 -Compress
