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


    # Add a custom object to the $Results array
    $script:Results += [pscustomobject]@{
        CheckName       = $CheckName
        Status          = $Status
        CurrentValue    = $CurrentValue
        Recommended     = $Recommended
        Notes           = $Notes
    }
}

# ============ HARDENING CHECKS START HERE ============

# Check 1: If User Account Control (UAC) Enabled
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacValue = Get-ItemProperty -Path $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue
if ($uacValue.EnableLUA -eq 1) {
    Add-CheckResult -CheckName "User Account Control (UAC)" -Status "Secure" -CurrentValue "Enabled" -Recommended "Enabled" -Notes "Prevents unauthorized elevation"
} else {
    Add-CheckResult -CheckName "User Account Control (UAC)" -Status "Insecure" -CurrentValue "Disabled" -Recommended "Enabled" -Notes "Critical hardening feature"
}

# Check 2: If Guest Account is Disabled
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest.Enabled -eq $false) {
    Add-CheckResult -CheckName "Guest Account Status" -Status "Secure" -CurrentValue "Disabled" -Recommended "Disabled" -Notes "Prevents anonymous logon"
} else {
    Add-CheckResult -CheckName "Guest Account Status" -Status "Insecure" -CurrentValue "Enabled" -Recommended "Disabled" -Notes "High-risk legacy account"
}

# Check 3: Windows Firewall Enabled for ALL Profiles
$fwProfiles = Get-NetFirewallProfile
$allEnabled = $true
foreach ($fwProfile in $fwProfiles) {
    if ($fwProfile.Enabled -eq $false) { $allEnabled = $false }
}
if ($allEnabled) {
    Add-CheckResult -CheckName "Windows Firewall" -Status "Secure" -CurrentValue "Enable (All Profiles)" -Recommended "Enabled" -Notes "Blocks unauthorized inbound traffic"
} else {
    Add-CheckResult -CheckName "Windows Firewall" -Status "Warning" -CurrentValue "Disabled on one or more profiles" -Recommended "Enabled" -Notes "Check Domain/Private/Public"

}

# ============ HARDENING CHECKS END (more coming) ============

# Final output
Write-Host "`nHardening Audit Complete - $($Results.Count) checks performed`n" -ForegroundColor Cyan
$Results | Format-Table -AutoSize
