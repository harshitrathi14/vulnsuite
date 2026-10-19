# Fixed local executor. Plans are data on stdin; no server-supplied code is run.
# Requires an administrator-protected installation and pre-created NTFS state folder.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Apply','Release','Watchdog','Cleanup')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$StateDirectory,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$JobId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:HelperPath = $PSCommandPath
$script:TrustedSids = @('S-1-5-18', 'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Get-Now { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Get-Group([string]$Id) { return 'VulnSuite-Isolation-' + $Id }
function Get-RecordPath([string]$Id) { return Join-Path $StateDirectory ($Id + '.json') }
function Get-ReadyPath([string]$Id) { return Join-Path $StateDirectory ($Id + '.watchdog') }

function Assert-ProtectedPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $first = $true
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'unsafe_installation' }
        $acl = Get-Acl -LiteralPath $item.FullName
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $script:TrustedSids) { throw 'unsafe_installation' }
        $danger = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                  [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                  [Security.AccessControl.FileSystemRights]::Delete -bor
                  [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                  [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                  [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
        if ($first) {
            $danger = $danger -bor [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::AppendData -bor
                [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
        }
        foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                $ace.IdentityReference.Value -notin $script:TrustedSids -and
                ($ace.FileSystemRights -band $danger) -ne 0) { throw 'unsafe_installation' }
        }
        $first = $false
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent } else { $item = $item.Directory }
    }
}

function Initialize-Executor {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'policy_denied' }
    if ($StateDirectory -notmatch '^[A-Za-z]:\\' -or $StateDirectory -match '["\r\n]' -or
        $script:HelperPath -match '["\r\n]') { throw 'unsafe_installation' }
    Assert-ProtectedPath $StateDirectory
    Assert-ProtectedPath $script:HelperPath
    if (-not (Get-Item -LiteralPath $StateDirectory).PSIsContainer) { throw 'unsafe_installation' }
    $volume = Get-Volume -DriveLetter $StateDirectory.Substring(0,1)
    if ($volume.FileSystem -ne 'NTFS') { throw 'unsafe_installation' }
    Import-Module NetSecurity -ErrorAction Stop
    Import-Module ScheduledTasks -ErrorAction Stop
}

function New-ExecutorMutex {
    $security = New-Object Security.AccessControl.MutexSecurity
    $security.SetAccessRuleProtection($true, $false)
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $security.SetOwner($administrators)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.MutexAccessRule($identity,
            [Security.AccessControl.MutexRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    $created = $false
    $mutex = [Threading.Mutex]::new($false, 'Global\VulnSuite-Isolation-Executor', [ref]$created, $security)
    $acl = $mutex.GetAccessControl()
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        $mutex.Dispose(); throw 'unsafe_installation'
    }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            $mutex.Dispose(); throw 'unsafe_installation'
        }
    }
    return $mutex
}

function Write-Record($Record, [bool]$New=$false) {
    $id = ([Guid]$Record.plan.request_id).ToString('N')
    $target = Get-RecordPath $id
    $temporary = Join-Path $StateDirectory ('.record-' + [Guid]::NewGuid().ToString('N'))
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Depth 12 -Compress))
    $file = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    try {
        if ($New) { [IO.File]::Move($temporary, $target) }
        else { [IO.File]::Replace($temporary, $target, $null) }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Read-Record([string]$Id) {
    $path = Get-RecordPath $Id
    Assert-ProtectedPath $path
    if ((Get-Item -LiteralPath $path).Length -gt 1048576) { throw 'invalid_plan' }
    $record = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if (([Guid]$record.plan.request_id).ToString('N') -ne $Id -or $record.plan.platform -ne 'windows') { throw 'invalid_plan' }
    return $record
}

function Assert-Plan($Plan, $Rules) {
    if ($Plan.platform -ne 'windows' -or ([Guid]$Plan.request_id).ToString('D') -ne $Plan.request_id) { throw 'invalid_plan' }
    $duration = [long]$Plan.expires_at - [long]$Plan.created_at
    if ($duration -lt 60 -or $duration -gt 3600 -or [long]$Plan.created_at -gt (Get-Now) + 30) { throw 'invalid_plan' }
    if ([long]$Plan.expires_at -le (Get-Now)) { throw 'plan_expired' }
    if (@($Plan.management_networks).Count -lt 1 -or @($Plan.management_networks).Count -gt 32 -or
        @($Plan.management_ports).Count -lt 1 -or @($Plan.management_ports).Count -gt 32) { throw 'invalid_plan' }
    foreach ($value in $Plan.management_networks) {
        $parts = ([string]$value).Split('/')
        if ($parts.Count -ne 2) { throw 'invalid_plan' }
        $ip = [Net.IPAddress]::Parse($parts[0])
        $prefix = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { '32' } else { '128' }
        if ($parts[1] -ne $prefix) { throw 'invalid_plan' }
    }
    foreach ($port in $Plan.management_ports) { if ([int]$port -lt 1 -or [int]$port -gt 65535) { throw 'invalid_plan' } }
    if (@($Rules).Count -ne 526) { throw 'invalid_plan' }
    $group = Get-Group (([Guid]$Plan.request_id).ToString('N'))
    for ($i=0; $i -lt $Rules.Count; $i++) {
        $rule = $Rules[$i]
        if ($rule.name -ne ('{0}-{1:D3}' -f $group, $i) -or [int]$rule.direction -notin @(1,2) -or
            [int]$rule.action -notin @(0,1) -or [int]$rule.protocol -lt 0 -or [int]$rule.protocol -gt 255) { throw 'invalid_plan' }
        foreach ($address in $rule.remote_addresses) {
            if ([string]$address -notmatch '^[0-9a-fA-F:.\-/]+$') { throw 'invalid_plan' }
        }
    }
}

function Assert-Environment([string]$Group) {
    foreach ($name in @('MpsSvc','BFE','Schedule')) {
        if ((Get-Service -Name $name).Status -ne 'Running') { throw 'helper_not_ready' }
    }
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    if ([int]$policy.LocalPolicyModifyState -ne 0) { throw 'unsupported_policy' }
    foreach ($mask in @(1,2,4)) {
        if (-not $policy.FirewallEnabled($mask) -or $policy.BlockAllInboundTraffic($mask)) { throw 'unsupported_policy' }
        if (@($policy.ExcludedInterfaces($mask) | Where-Object { $null -ne $_ -and [string]$_ -ne '' }).Count -gt 0) { throw 'unsupported_policy' }
    }
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore) {
        if ([string]$profile.Enabled -ne 'True' -or [string]$profile.AllowLocalFirewallRules -eq 'False' -or
            [string]$profile.AllowInboundRules -eq 'False' -or @($profile.DisabledInterfaceAliases |
                Where-Object { $null -ne $_ -and [string]$_ -notin @('','NotConfigured') }).Count -gt 0) { throw 'unsupported_policy' }
    }
    # Existing explicit block rules could override a management exception. Reject
    # the configuration conservatively instead of silently weakening those rules.
    $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True)
    if (@($existing | Where-Object { [string]$_.Action -eq 'Block' -and $_.Group -ne $Group }).Count -gt 0) { throw 'unsupported_policy' }
    $security = @($existing | Get-NetFirewallSecurityFilter)
    if (@($security | Where-Object { [string]$_.OverrideBlockRules -eq 'True' }).Count -gt 0) { throw 'unsupported_policy' }
    return $policy
}

function Remove-OwnedRules([string]$Id) {
    $group = Get-Group $Id
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $names = @($policy.Rules | Where-Object { $_.Grouping -eq $group -and $_.Name -match ('^' + $group + '-[0-9]{3}$') } | ForEach-Object { $_.Name })
    foreach ($name in $names) { $policy.Rules.Remove($name) }
    if (@($policy.Rules | Where-Object { $_.Grouping -eq $group }).Count -ne 0) { throw 'rollback_failed' }
    # Query the effective store separately: a local deletion alone is not proof
    # that the provider removed the active filtering policy.
    $remaining = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Group -eq $group })
    if ($remaining.Count -ne 0) { throw 'rollback_failed' }
}

function Invoke-Release([string]$Id) {
    $record = Read-Record $Id
    Remove-OwnedRules $Id
    $record.state = 'released'
    Write-Record $record
    $task = Get-ScheduledTask -TaskName (Get-Group $Id) -ErrorAction SilentlyContinue
    if ($null -ne $task) { Unregister-ScheduledTask -TaskName (Get-Group $Id) -Confirm:$false }
    $ready = Get-ReadyPath $Id
    if ([IO.File]::Exists($ready)) { [IO.File]::Delete($ready) }
    return @{ status='rolled_back'; detail='isolation_released'; platform='windows'; request_id=$record.plan.request_id }
}

function Assert-Task([string]$Id, $Plan) {
    $task = Get-ScheduledTask -TaskName (Get-Group $Id)
    if ([string]$task.State -eq 'Disabled' -or [string]$task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
        [string]$task.Principal.RunLevel -ne 'Highest' -or -not $task.Settings.StartWhenAvailable) { throw 'watchdog_unavailable' }
    $expected = '-NoProfile -NonInteractive -File "' + $script:HelperPath + '" -Mode Watchdog -StateDirectory "' + $StateDirectory + '" -JobId ' + $Id
    $exe = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $exe -or $task.Actions[0].Arguments -ne $expected) { throw 'watchdog_unavailable' }
    $timed = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' })
    $startup = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' })
    if ($timed.Count -ne 1 -or $startup.Count -ne 1) { throw 'watchdog_unavailable' }
    $deadline = [DateTimeOffset]::Parse($timed[0].StartBoundary).ToUnixTimeSeconds()
    if ([Math]::Abs($deadline - [long]$Plan.expires_at) -gt 1) { throw 'watchdog_unavailable' }
}

function Register-Expiry([string]$Id, $Plan) {
    $name = Get-Group $Id
    if ($null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) { throw 'job_conflict' }
    $exe = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -File "' + $script:HelperPath + '" -Mode Watchdog -StateDirectory "' + $StateDirectory + '" -JobId ' + $Id
    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $at = [DateTimeOffset]::FromUnixTimeSeconds([long]$Plan.expires_at).LocalDateTime
    $triggers = @((New-ScheduledTaskTrigger -Once -At $at), (New-ScheduledTaskTrigger -AtStartup))
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $triggers -Settings $settings -Principal $principal | Out-Null
    Assert-Task $Id $Plan
    Start-ScheduledTask -TaskName $name
    # A SYSTEM watchdog must actually start and publish a fresh heartbeat before
    # any block rule can be written. Mere task registration is insufficient.
    $until = (Get-Now) + 15
    $ready = Get-ReadyPath $Id
    while (-not [IO.File]::Exists($ready) -and (Get-Now) -lt $until) { Start-Sleep -Milliseconds 200 }
    if (-not [IO.File]::Exists($ready) -or [long]([IO.File]::ReadAllText($ready)) -lt (Get-Now) - 5) { throw 'watchdog_unavailable' }
}

function Normalize-Addresses([string[]]$Values) {
    $result = @()
    foreach ($value in ($Values -join ',').Split(',')) {
        $value = $value.Trim()
        if ($value -in @('*','Any','')) { $result += '*'; continue }
        $parts = $value.Split('/')
        if ($parts.Count -eq 2) {
            $start = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
            $end = [byte[]]$start.Clone()
            $prefix = [int]$parts[1]
            if ($prefix -lt 0 -or $prefix -gt $start.Length*8) { throw 'effective_rules_unconfirmed' }
            for ($i=0; $i -lt $start.Length; $i++) {
                $bits = [Math]::Min(8,[Math]::Max(0,$prefix - $i*8))
                $mask = if ($bits -eq 0) { 0 } else { 256 - [int][Math]::Pow(2,8-$bits) }
                $start[$i] = [byte]($start[$i] -band $mask)
                $end[$i] = [byte]($start[$i] -bor (255-$mask))
            }
        } else {
            $bounds = $value.Split('-')
            $start = [Net.IPAddress]::Parse($bounds[0]).GetAddressBytes()
            $end = if ($bounds.Count -eq 2) { [Net.IPAddress]::Parse($bounds[1]).GetAddressBytes() } else { $start }
            if ($start.Length -ne $end.Length) { throw 'effective_rules_unconfirmed' }
        }
        $result += ([BitConverter]::ToString($start) + '/' + [BitConverter]::ToString($end))
    }
    return (($result | Sort-Object -Unique) -join ',')
}

function Normalize-Filter([string[]]$Values) {
    $items = @(($Values -join ',').Split(',') | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    if ($items.Count -eq 0 -or ($items.Count -eq 1 -and $items[0] -in @('','*','Any'))) { return '*' }
    return ($items -join ',')
}

function Normalize-Icmp([string[]]$Values) {
    $items = @(($Values -join ',').Split(',') | ForEach-Object {
        $value = $_.Trim()
        if ($value -match '^[0-9]+$') { $value + ':*' }
        else { $value.Replace(':Any',':*') }
    })
    return (Normalize-Filter $items)
}

function Assert-EffectiveRules($Record) {
    $id = ([Guid]$Record.plan.request_id).ToString('N')
    $group = Get-Group $id
    $native = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $group)
    if ($native.Count -ne $Record.rules.Count) { throw 'effective_rules_unconfirmed' }
    $expectedNames = @($Record.rules | ForEach-Object { $_.name })
    foreach ($rule in $native) {
        if ([long]$Record.plan.expires_at -le (Get-Now)) { throw 'plan_expired' }
        $enforcement = @($rule.EnforcementStatus | ForEach-Object { [int]$_ })
        # COM Name is the display name; NetSecurity's internal Name may be a GUID.
        if ($rule.DisplayName -notin $expectedNames -or [string]$rule.Enabled -ne 'True' -or [int]$rule.PrimaryStatus -ne 1 -or
            $enforcement -notcontains 1 -or @($enforcement | Where-Object { $_ -notin @(1,5) }).Count -gt 0) { throw 'effective_rules_unconfirmed' }
        $spec = @($Record.rules | Where-Object name -eq $rule.DisplayName)[0]
        $address = $rule | Get-NetFirewallAddressFilter
        $ports = $rule | Get-NetFirewallPortFilter
        $interfaces = $rule | Get-NetFirewallInterfaceFilter
        $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
        $application = $rule | Get-NetFirewallApplicationFilter
        $service = $rule | Get-NetFirewallServiceFilter
        $expectedAction = if ([int]$spec.action -eq 0) { 'Block' } else { 'Allow' }
        $expectedDirection = if ([int]$spec.direction -eq 1) { 'Inbound' } else { 'Outbound' }
        $protocol = switch ([string]$ports.Protocol) {
            'TCP' { 6 }; 'UDP' { 17 }; 'ICMPv4' { 1 }; 'ICMPv6' { 58 }; default { [int]$ports.Protocol }
        }
        if ([string]$rule.Action -ne $expectedAction -or [string]$rule.Direction -ne $expectedDirection -or
            [int]$rule.Profile -ne 0 -or [int]$rule.EdgeTraversalPolicy -ne 0 -or $protocol -ne [int]$spec.protocol -or
            (Normalize-Addresses $address.RemoteAddress) -ne (Normalize-Addresses $spec.remote_addresses) -or
            (Normalize-Addresses $address.LocalAddress) -ne '*' -or
            (Normalize-Filter $interfaces.InterfaceAlias) -ne '*' -or [string]$interfaceType.InterfaceType -ne 'Any' -or
            (Normalize-Filter @($application.Program)) -ne '*' -or (Normalize-Filter @($service.Service)) -ne '*') { throw 'effective_rules_unconfirmed' }
        if ([int]$spec.protocol -in @(6,17)) {
            $expectedLocal = if ($null -ne $spec.PSObject.Properties['local_ports']) { $spec.local_ports } else { @('*') }
            $expectedRemote = if ($null -ne $spec.PSObject.Properties['remote_ports']) { $spec.remote_ports } else { @('*') }
            if ((Normalize-Filter $ports.LocalPort) -ne (Normalize-Filter $expectedLocal) -or
                (Normalize-Filter $ports.RemotePort) -ne (Normalize-Filter $expectedRemote)) { throw 'effective_rules_unconfirmed' }
        }
        if ([int]$spec.protocol -in @(1,58) -and
            (Normalize-Icmp $ports.IcmpType) -ne (Normalize-Icmp $spec.icmp_types)) { throw 'effective_rules_unconfirmed' }
    }
    # Verify persisted condition values, not only existence of names.
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($spec in $Record.rules) {
        $rule = $policy.Rules.Item($spec.name)
        if ($rule.Grouping -ne $group -or [int]$rule.Protocol -ne [int]$spec.protocol -or
            [int]$rule.Action -ne [int]$spec.action -or [int]$rule.Direction -ne [int]$spec.direction -or -not $rule.Enabled -or
            [int]$rule.Profiles -ne 2147483647 -or [string]$rule.InterfaceTypes -ne 'All' -or $rule.EdgeTraversal -or
            -not [string]::IsNullOrEmpty($rule.ApplicationName) -or -not [string]::IsNullOrEmpty($rule.ServiceName) -or
            @($rule.Interfaces | Where-Object { $null -ne $_ -and [string]$_ -ne '' }).Count -gt 0 -or
            (Normalize-Addresses @($rule.LocalAddresses)) -ne '*' -or
            (Normalize-Addresses @($rule.RemoteAddresses)) -ne (Normalize-Addresses $spec.remote_addresses)) { throw 'effective_rules_unconfirmed' }
        if ([int]$spec.protocol -in @(6,17)) {
            $local = if ($null -ne $spec.PSObject.Properties['local_ports']) { $spec.local_ports } else { @('*') }
            $remote = if ($null -ne $spec.PSObject.Properties['remote_ports']) { $spec.remote_ports } else { @('*') }
            if ((Normalize-Filter @($rule.LocalPorts)) -ne (Normalize-Filter $local) -or
                (Normalize-Filter @($rule.RemotePorts)) -ne (Normalize-Filter $remote)) { throw 'effective_rules_unconfirmed' }
        }
        if ([int]$spec.protocol -in @(1,58) -and
            (Normalize-Filter @($rule.IcmpTypesAndCodes)) -ne (Normalize-Filter $spec.icmp_types)) { throw 'effective_rules_unconfirmed' }
    }
}

function Invoke-Apply($InputData) {
    $plan, $rules = $InputData.plan, @($InputData.rules)
    Assert-Plan $plan $rules
    $id = ([Guid]$plan.request_id).ToString('N')
    $group = Get-Group $id
    $path = Get-RecordPath $id
    if ([IO.File]::Exists($path)) {
        $old = Read-Record $id
        if (($old.plan | ConvertTo-Json -Depth 6 -Compress) -ne ($plan | ConvertTo-Json -Depth 6 -Compress)) { throw 'job_conflict' }
        if ($old.state -eq 'released') { throw 'job_already_released' }
        if ($old.state -ne 'applied') { Invoke-Release $id | Out-Null; throw 'interrupted_application' }
        Assert-Environment $group | Out-Null
        Assert-Task $id $plan
        Assert-EffectiveRules $old
        return @{ status='applied'; detail='isolated'; platform='windows'; request_id=$plan.request_id; expires_at=$plan.expires_at }
    }
    if ([long]$plan.expires_at - (Get-Now) -lt 30) { throw 'plan_expired' }
    $policy = Assert-Environment $group
    if (@($policy.Rules | Where-Object { $_.Grouping -eq $group }).Count -gt 0) { throw 'job_conflict' }
    $record = [pscustomobject]@{ plan=$plan; rules=$rules; state='prepared' }
    Write-Record $record $true
    try {
        Register-Expiry $id $plan
        foreach ($spec in $rules) {
            if ([long]$plan.expires_at -le (Get-Now)) { throw 'plan_expired' }
            $rule = New-Object -ComObject HNetCfg.FWRule
            $rule.Name = $spec.name
            $rule.Description = 'VulnSuite reviewed temporary host isolation'
            $rule.Grouping = $group
            $rule.Protocol = [int]$spec.protocol
            $rule.RemoteAddresses = [string]::Join(',', [string[]]$spec.remote_addresses)
            if ($null -ne $spec.PSObject.Properties['local_ports']) { $rule.LocalPorts = [string]::Join(',', [string[]]$spec.local_ports) }
            if ($null -ne $spec.PSObject.Properties['remote_ports']) { $rule.RemotePorts = [string]::Join(',', [string[]]$spec.remote_ports) }
            if ($null -ne $spec.PSObject.Properties['icmp_types']) { $rule.IcmpTypesAndCodes = [string]::Join(',', [string[]]$spec.icmp_types) }
            $rule.Direction = [int]$spec.direction
            $rule.Action = [int]$spec.action
            $rule.Profiles = 2147483647
            $rule.InterfaceTypes = 'All'
            $rule.Enabled = $true
            $policy.Rules.Add($rule)
        }
        Assert-Environment $group | Out-Null
        Assert-Task $id $plan
        Assert-EffectiveRules $record
        if ([long]$plan.expires_at -le (Get-Now)) { throw 'plan_expired' }
        $record.state = 'applied'
        Write-Record $record
    } catch {
        $originalError = $_.Exception.Message
        try { Invoke-Release $id | Out-Null } catch { throw 'rollback_failed' }
        throw $originalError
    }
    return @{ status='applied'; detail='isolated'; platform='windows'; request_id=$plan.request_id; expires_at=$plan.expires_at }
}

function Invoke-Watchdog([string]$Id) {
    # Runs as SYSTEM independently of the polling agent and control connection.
    $record = Read-Record $Id
    $ready = Get-ReadyPath $Id
    while ((Get-Now) -lt [long]$record.plan.expires_at) {
        if ((Read-Record $Id).state -eq 'released') { return }
        [IO.File]::WriteAllText($ready, [string](Get-Now))
        Start-Sleep -Seconds 1
    }
    # The apply process owns this lock while adding rules and checks the deadline
    # on every iteration, preventing rule creation after a concurrent release.
    $mutex = New-ExecutorMutex
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'rollback_failed' }
        Invoke-Release $Id | Out-Null
    } finally { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}

try {
    Initialize-Executor
    if ($Mode -eq 'Watchdog') { Invoke-Watchdog $JobId; exit 0 }
    $mutex = New-ExecutorMutex
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'job_conflict' }
        if ($Mode -eq 'Apply') {
            $inputJson = [Console]::In.ReadToEnd()
            if ($inputJson.Length -gt 1048576) { throw 'invalid_plan' }
            $result = Invoke-Apply ($inputJson | ConvertFrom-Json)
        } elseif ($Mode -eq 'Release') {
            $result = Invoke-Release $JobId
        } else {
            $released = 0
            foreach ($file in Get-ChildItem -LiteralPath $StateDirectory -Filter '*.json' -File) {
                if ($file.BaseName -notmatch '^[a-f0-9]{32}$') { continue }
                $record = Read-Record $file.BaseName
                if ($record.state -ne 'released' -and [long]$record.plan.expires_at -le (Get-Now)) {
                    Invoke-Release $file.BaseName | Out-Null
                    $released++
                }
            }
            $result = @{ status='cleaned'; released=$released }
        }
        $result | ConvertTo-Json -Depth 5 -Compress
    } finally { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
    exit 0
} catch {
    $known = @('policy_denied','unsupported_policy','unsafe_installation','invalid_plan','plan_expired',
        'helper_not_ready','job_conflict','job_already_released','execution_failed','rollback_failed',
        'watchdog_unavailable','effective_rules_unconfirmed','interrupted_application')
    $code = $_.Exception.Message
    if ($code -notin $known) { $code = 'execution_failed' }
    @{ status='failed'; error=$code } | ConvertTo-Json -Compress
    exit 1
}
