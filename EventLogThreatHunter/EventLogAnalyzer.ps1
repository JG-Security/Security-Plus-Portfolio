param (
    [int]$Hours = 24,          # This directs the command to look back 24 hours.
    [int]$Threshold = 10       # Flags if more failed logons than indicated threshold amount. Arbitrary amount that be set to any number desired
)

Write-Host "Event Log Threat Hunter" -ForegroundColor Cyan
Write-Host "Analyzing last $Hours hours for failed logons (Event ID 4625)..." -ForegroundColor Yellow

# Calculate the start time based on user input
$StartTime = (Get-Date).AddHours(-$Hours)

# Query the Security Event Log for failed logons (Event ID 4625)
$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

if ($FailedLogons) {
    Write-Host "Found $(FailedLogons.Count) failed logon events." -ForegroundColor Green
} else {
    Write-Host "No Failed logon events found in the last $Hours hours." -ForegroundColor Magenta
    exit
}
