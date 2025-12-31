param (
    [int]$Hours = 24,          # This directs the command to look back 24 hours.
    [int]$Threshold = 10       # Flags if more failed logons than indicated threshold amount. Arbitrary amount that be set to any number desired
)

Write-Host "Event Log Threat Hunter" -ForegroundColor Cyan
Write-Host "Analyzing last $Hours hours for failed logons (Event ID 4625)..." -ForegroundColor Yellow
