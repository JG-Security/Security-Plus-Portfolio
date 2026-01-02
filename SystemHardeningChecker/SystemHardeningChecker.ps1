# Windows System Hardening Checker Project
# Please run as Administrator for best accuracy

Write-Host "Windows System Hardening Checker" -ForegroundColor Cyan
Write-Host "Auditing common security settings..." -ForegroundColor Yellow

# Array to hold all check results
$Results = @()

# Reusable function to add a result
function Add-CheckResult {
    param (
        [string]$CheckName,         # Name of the secuirty check
        [string]$Status,            # "Secure", "Warning", or "Insecure"
        [string]$CurrentValue,      # What the system currently has
        [string]$Recommended,       # What it should be
        [string]$Notes = ""        # Optional/Extra info
    )


    # Add a customer object to the $Results array
    $Results += [pscustomobject]@{
        CheckName       = $CheckName
        Status          = $Status
        CurrentValue    = $CurrentValue
        Recommended     = $Recommended
        Notes           = $Notes
    }
}

# Placeholder message until we add real checks
Write-Host "`nNo checks added yet - script framework ready!" -ForegroundColor Magenta
Write-Host "Results array has $($Results.Count) items." -ForegroundColor Gray