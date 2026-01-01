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
    Write-Host "Found $($FailedLogons.Count) failed logon events." -ForegroundColor Green
} else {
    Write-Host "No Failed logon events found in the last $Hours hours." -ForegroundColor Magenta
    exit
}

# Extract key fields from each event
$Report = $FailedLogons | ForEach-Object {
    [pscustomobject]@{
        TimeCreated       = $_.TimeCreated
        TargetUsername    = $_.Properties[5].Value      # Index 5 = Target account name
        SourceWorkstation = $_.Properties[18].Value     # Index 18 = Originating Workstation
        SourceIP          = $_.Properties[19].Value     # Index 19 = source IP (or '-' if local)
    }
}

# Group by attacker. Prefer real IP, otherwise uses workstation name
$Summary = $Report | Group-Object -Property {
    if ($_.SourceIP -and $_.SourceIP -ne '-' -and $_.SourceIP -ne '127.0.0.1') { $_.SourceIP } else { $_.SourceWorkstation }
} | Select-Object @{
    Name       = 'Attacker'
    Expression = { $_.Name }
},
Count,
@{
    Name       = 'TargetUsername'
    Expression = { ($_.Group.TargetUsername | Sort-Object -Unique) -join ', ' }
},
@{
    Name       = 'Flagged'
    Expression = { $_.Count -ge $Threshold }
} | Sort-Object Count -Descending

#Display Results
Write-Host "`nBrute-Force Attempt Summary:" -ForegroundColor Cyan
$Summary | Format-Table -AutoSize

#Export to CSV
$Timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$CsvPath = "BruteForceReport_$Timestamp.csv"
$Summary | Export-Csv -Path $CsvPath -NoTypeInformation

# Final alert
if ($Summary | Where-Object Flagged) {
    Write-Host " SUSPICIOUS ACTIVITY DETECTED (>= $Threshold failed attempts)!" -ForegroundColor Red
    } else {
    Write-Host " No sources exceeded the threshold of $Threshold attempts." -ForegroundColor Green
}
