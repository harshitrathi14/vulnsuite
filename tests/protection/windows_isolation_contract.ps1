# Test only: execute orchestration functions with an in-memory firewall fixture.
# No production entry point or native Windows security command is invoked.
param([string]$HelperPath, [string]$PayloadPath, [string]$Scenario, [string]$WorkDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:events=[Collections.Generic.List[string]]::new()
$script:clock=1000
$script:scenario=$Scenario
$script:saved=$null
class FixtureRule {
    [string]$Name; [string]$Description; [string]$Grouping; [int]$Protocol
    [string]$RemoteAddresses; [string]$LocalPorts; [string]$RemotePorts
    [string]$IcmpTypesAndCodes; [int]$Direction; [int]$Action
    [int]$Profiles; [string]$InterfaceTypes; [bool]$Enabled
}
class FixtureRules : Collections.IEnumerable {
    [Collections.Generic.List[object]]$Items=[Collections.Generic.List[object]]::new()
    [int]$Attempts=0
    [void]Add([object]$Rule) {
        $this.Attempts++
        $script:events.Add('add')
        if ($script:scenario -eq 'partial_failure' -and $this.Attempts -eq 3) { throw 'execution_failed' }
        $this.Items.Add($Rule)
        if ($script:scenario -eq 'expired_during_apply') { $script:clock=1300 }
    }
    [Collections.IEnumerator]GetEnumerator() { return $this.Items.GetEnumerator() }
}
$script:policy=[pscustomobject]@{Rules=[FixtureRules]::new()}
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($HelperPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'helper parse error' }
foreach ($name in @('Assert-Plan','Invoke-Apply','Normalize-Addresses','Normalize-Filter')) {
    $node=$ast.FindAll({param($part) $part -is [Management.Automation.Language.FunctionDefinitionAst]},$false) |
        Where-Object Name -eq $name
    # Repo-owned test function definitions only; never execute the helper entrypoint.
    . ([scriptblock]::Create($node.Extent.Text))
}
function Get-Now { return $script:clock }
function Get-Group([string]$Id) { return 'VulnSuite-Isolation-'+$Id }
function Get-RecordPath([string]$Id) { return Join-Path $WorkDirectory ($Id+'.json') }
function Write-Record($Record,[bool]$New=$false) {
    $script:events.Add('manifest_'+$Record.state)
    $script:saved=$Record
    [IO.File]::WriteAllText((Get-RecordPath (([Guid]$Record.plan.request_id).ToString('N'))),'fixture')
}
function Read-Record([string]$Id) { return $script:saved }
function Assert-Environment([string]$Group) { $script:events.Add('preflight'); return ,$script:policy }
function Register-Expiry([string]$Id,$Plan) {
    $script:events.Add('watchdog')
    if ($script:scenario -eq 'watchdog_failure') { throw 'watchdog_unavailable' }
}
function Assert-Task([string]$Id,$Plan) { $script:events.Add('task_verified') }
function Assert-EffectiveRules($Record) { $script:events.Add('effective_verified') }
function Invoke-Release([string]$Id) {
    $script:events.Add('release')
    $script:policy.Rules.Items.Clear()
    $script:saved.state='released'
    return @{status='rolled_back'}
}
function New-Object([string]$ComObject) {
    if ($ComObject -ne 'HNetCfg.FWRule') { throw 'unexpected native object request' }
    return [FixtureRule]::new()
}
$payload=[IO.File]::ReadAllText($PayloadPath) | ConvertFrom-Json
if ($Scenario -in @('retry_applied','retry_partial')) {
    $script:saved=[pscustomobject]@{plan=$payload.plan;rules=$payload.rules;state='applied'}
    if ($Scenario -eq 'retry_partial') { $script:saved.state='prepared' }
    [IO.File]::WriteAllText((Get-RecordPath (([Guid]$payload.plan.request_id).ToString('N'))),'fixture')
}
$failure=$null; $receipt=$null
try { $receipt=Invoke-Apply $payload } catch { $failure=$_.Exception.Message }
@{ scenario=$Scenario; events=@($script:events); error=$failure; receipt=$receipt;
   remaining=$script:policy.Rules.Items.Count; state=$script:saved.state } | ConvertTo-Json -Depth 6 -Compress
