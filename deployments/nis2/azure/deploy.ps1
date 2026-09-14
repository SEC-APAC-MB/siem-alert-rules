<#
.SYNOPSIS
  Deploy Microsoft Sentinel SIEM alert rules (PowerShell version).

.DESCRIPTION
  Creates Sentinel Scheduled analytics rules for every rule bundled in
  rules.json using the Azure CLI (az) or Az PowerShell modules.

.EXAMPLE
  .\deploy.ps1
  .\deploy.ps1 -Config ..\deployment-config.yaml
  .\deploy.ps1 -DryRun
  .\deploy.ps1 -Compliance NIS2
#>
[CmdletBinding()]
param(
    [string]$Config,
    [switch]$DryRun,
    [string]$Compliance
)

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RulesFile  = "$ScriptDir\rules.json"

# ─── config file (simple YAML-ish parsing) ───────────────────
function Get-CfgValue([string]$Key, [string]$File) {
    if (-not (Test-Path $File)) { return "" }
    $line = Get-Content $File | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*:" } | Select-Object -First 1
    if (-not $line) { return "" }
    return ($line -split ":", 2)[1].Trim().Trim('"')
}

if ($Config) {
    if (-not (Test-Path $Config)) { throw "Config file not found: $Config" }
    if (-not $env:AZ_SUBSCRIPTION_ID) { $env:AZ_SUBSCRIPTION_ID = Get-CfgValue "subscription_id" $Config }
    if (-not $env:AZ_RESOURCE_GROUP)  { $env:AZ_RESOURCE_GROUP  = Get-CfgValue "resource_group"  $Config }
    if (-not $env:AZ_WORKSPACE_NAME)  { $env:AZ_WORKSPACE_NAME  = Get-CfgValue "workspace_name"  $Config }
}

$SubscriptionId = $env:AZ_SUBSCRIPTION_ID
$ResourceGroup  = $env:AZ_RESOURCE_GROUP
$WorkspaceName  = $env:AZ_WORKSPACE_NAME

Write-Host "== Azure deployment prerequisites =="
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI is not installed. See https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
}
az extension add --name sentinel --only-show-errors *> $null

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { throw "AZ_SUBSCRIPTION_ID is empty. Set env var or provide 'subscription_id' in --config." }
if ([string]::IsNullOrWhiteSpace($ResourceGroup))  { throw "AZ_RESOURCE_GROUP is empty. Set env var or provide 'resource_group' in --config." }
if ([string]::IsNullOrWhiteSpace($WorkspaceName))  { throw "AZ_WORKSPACE_NAME is empty. Set env var or provide 'workspace_name' in --config." }
Write-Host "  subscription: $SubscriptionId"
Write-Host "  resource group: $ResourceGroup"
Write-Host "  workspace: $WorkspaceName"

az account show --subscription $SubscriptionId *> $null
if ($LASTEXITCODE -ne 0) { throw "Cannot authenticate / access subscription $SubscriptionId. Run 'az login' first." }
az account set --subscription $SubscriptionId *> $null
Write-Host "  authentication: OK"

# ─── load package ────────────────────────────────────────────
if (-not (Test-Path $RulesFile)) { throw "Rules file not found: $RulesFile" }
$pkg = Get-Content $RulesFile -Raw | ConvertFrom-Json
Write-Host ""
Write-Host "== Package: $RulesFile =="
Write-Host "  regulation: $($pkg.regulation)"
Write-Host "  rules: $($pkg.rules.Count)"

if ($Compliance) { Write-Host "  compliance filter: $Compliance" }
if ($DryRun) { Write-Host ""; Write-Host "== DRY RUN — validating without deploying ==" }

function Normalize-Freq([string]$v) {
    if ($v -like "PT*") { return $v }
    if ($v -match "^(\d+)h$") { return "PT$($Matches[1])H" }
    if ($v -match "^(\d+)m$") { return "PT$($Matches[1])M" }
    if ($v -match "^(\d+)d$") { return "P$($Matches[1])D" }
    if ($v -match "^\d+$") { return "PT${v}M" }
    return "PT5M"
}
function Convert-Severity([int]$s) {
    switch ($s) { 0 {"High"} 1 {"Medium"} 2 {"Low"} 3 {"Informational"} default {"Low"} }
}

Write-Host ""
Write-Host "== Deploying rules =="
$success = 0; $failed = 0; $skipped = 0

foreach ($rule in $pkg.rules) {
    if ($Compliance -and $Compliance -ne "ALL") {
        $refs = @($rule.regulation_refs) -join ","
        if ($refs -notmatch $Compliance) {
            Write-Host "  SKIP     $($rule.rule_id)  (not tagged $Compliance)"
            $skipped++
            continue
        }
    }
    $id      = $rule.rule_id
    $display = $rule.name
    $desc    = $rule.description
    $sev     = Convert-Severity ([int]$rule.severity)
    $query   = $rule.query -replace '"', '\"'
    $freq    = Normalize-Freq $rule.queryFrequency
    $period  = Normalize-Freq $rule.queryPeriod
    $op      = $rule.triggerOperator
    $thr     = [string]$rule.triggerThreshold
    $tactics = @($rule.tactics) -join ","

    $args = @(
        "--resource-group", $ResourceGroup,
        "--workspace-name", $WorkspaceName,
        "--name", $id,
        "--kind", "Scheduled",
        "--display-name", $display,
        "--description", $desc,
        "--severity", $sev,
        "--query", $query,
        "--query-frequency", $freq,
        "--query-period", $period,
        "--trigger-operator", $op,
        "--trigger-threshold", $thr,
        "--enabled", "true"
    )
    if ($tactics) { $args += @("--tactics", $tactics) }

    if ($DryRun) {
        Write-Host "  OK       $id  (would run: az sentinel alert-rule create ...)"
        $success++
        continue
    }
    az sentinel alert-rule create @args *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK       $id  ($display)"
        $success++
    } else {
        Write-Host "  FAIL     $id  ($display)"
        $failed++
    }
}

Write-Host ""
Write-Host "== Summary =="
Write-Host "  success: $success"
Write-Host "  failed:  $failed"
Write-Host "  skipped: $skipped"
if ($DryRun) { Write-Host "  DRY RUN — no resources were created or modified." }

if ($failed -gt 0) {
    throw "$failed rule(s) failed to deploy"
}
Write-Host "✅ Azure deployment complete"