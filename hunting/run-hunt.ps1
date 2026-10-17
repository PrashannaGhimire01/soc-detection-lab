# Threat hunt: run Chainsaw with this repo's Sigma rules + Chainsaw's built-in
# rules over exported Windows event logs.
#
# Prereqs:
#   - Chainsaw extracted to C:\chainsaw  (the "all_platforms+rules" release)
#   - Logs exported from the target host to C:\hunt-logs (Security/Sysmon/Defender .evtx)
#       wevtutil epl Security "C:\hunt-logs\Security.evtx" /ow:true
#       wevtutil epl "Microsoft-Windows-Sysmon/Operational" "C:\hunt-logs\Sysmon.evtx" /ow:true
#       wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "C:\hunt-logs\Defender.evtx" /ow:true
#
# Run from the repo so $PSScriptRoot finds the Sigma rules:  .\hunting\run-hunt.ps1

$cs    = (Get-ChildItem C:\chainsaw -Recurse -Filter "chainsaw*msvc.exe" | Select-Object -First 1).FullName
$map   = (Get-ChildItem C:\chainsaw -Recurse -Filter "sigma-event-logs-all.yml" | Select-Object -First 1).FullName
$rules = (Get-ChildItem C:\chainsaw -Recurse -Directory | Where-Object Name -eq 'rules' | Select-Object -First 1).FullName
$sigma = Resolve-Path (Join-Path $PSScriptRoot "..\detections\sigma")
$logs  = "C:\hunt-logs"

if (-not $cs)  { throw "chainsaw.exe not found under C:\chainsaw" }
if (-not $map) { throw "sigma mapping not found under C:\chainsaw" }

& $cs hunt $logs -s $sigma --mapping $map -r $rules --csv --output "C:\hunt-results"

Write-Host "`n=== hits per category ==="
Get-ChildItem C:\hunt-results\*.csv | ForEach-Object {
    "{0,-26} {1,5} hits" -f $_.Name, ((Import-Csv $_.FullName).Count)
}
