# Wazuh Active Response - Disable a compromised AD account
# Triggered by rule 100010 (successful brute force). Runs on DC01 as the agent (SYSTEM).
#
# Wazuh passes the alert as JSON on stdin (Active Response v2). We read it, pull the
# targeted user from the alert, refuse to touch protected accounts, disable the rest,
# and log every decision to the standard Active Response log.

$ErrorActionPreference = "Stop"
# Use our OWN log file. Wazuh keeps active-responses.log locked (wazuh-execd),
# so writing there fails with a sharing violation.
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\disable-account-ar.log"

# Accounts this response must NEVER disable, no matter what fires the rule.
# (break-glass admin, KRBTGT, guest, and any machine account handled separately)
$Protected = @("administrator", "krbtgt", "guest", "defaultaccount", "bf.service")

function Write-ARLog($msg) {
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    Add-Content -Path $LogFile -Value "$stamp disable-account: $msg"
}

try {
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { Write-ARLog "no input received on stdin"; exit 0 }

    $msg = $raw | ConvertFrom-Json
    $command = $msg.command

    # Only act on the 'add' phase (the trigger). 'delete' is the rollback phase.
    if ($command -ne "add") { Write-ARLog "ignoring command '$command'"; exit 0 }

    $user = $msg.parameters.alert.data.win.eventdata.targetUserName
    if (-not $user) { Write-ARLog "no targetUserName in alert - no action"; exit 0 }

    $u = $user.Trim()
    $lower = $u.ToLower()

    # Safety: never disable protected or machine accounts (machine accounts end with $)
    if ($lower -in $Protected -or $u.EndsWith('$')) {
        Write-ARLog "REFUSED to disable protected/machine account '$u'"
        exit 0
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    $acct = Get-ADUser -Identity $u -ErrorAction Stop
    if (-not $acct.Enabled) {
        Write-ARLog "account '$u' already disabled - no action"
        exit 0
    }

    Disable-ADAccount -Identity $u -ErrorAction Stop
    Write-ARLog "DISABLED account '$u' in response to rule 100010 (successful brute force)"
}
catch {
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    Add-Content -Path $LogFile -Value "$stamp disable-account: ERROR $($_.Exception.Message)"
    exit 1
}
