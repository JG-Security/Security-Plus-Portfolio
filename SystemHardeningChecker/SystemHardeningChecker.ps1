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

# Check 4: Password Complexity (with Windows Hello/PIN detection)
$user = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue

if (-not $user) {
    Add-CheckResult -CheckName "Password Complexity" -Status "Warning" -CurrentValue "Unable to detect user" -Recommended "Enabled" -Notes "User query failed"
} elseif (-not $user.PasswordRequired) {
    Add-CheckResult -CheckName "Password Complexity" -Status "Secure" -CurrentValue "N/A (Windows Hello/PIN only)" -Recommended "N/A" -Notes "Hello is more secure than passwords; ensure strong PIN and device protection"
} else {
    $complexityKey = Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account" -Name "F" -ErrorAction SilentlyContinue
    if ($complexityKey) {
        $complexityEnabled = ($complexityKey.F[0] -band 0x20000) -ne 0
        if ($complexityEnabled) {
            Add-CheckResult -CheckName "Password Complexity" -Status "Secure" -CurrentValue "Enabled" -Recommended "Enabled" -Notes "Requires mixed case, numbers, symbols"
        } else {
            Add-CheckResult -CheckName "Password Complexity" -Status "Insecure" -CurrentValue "Disabled" -Recommended "Enabled" -Notes "Allows weak passwords - high risk"
        }
    } else {
        Add-CheckResult -CheckName "Password Complexity" -Status "Warning" -CurrentValue "Unable to read policy" -Recommended "Enabled" -Notes "Common on Hello-only accounts or GPO-managed systems"
    }
}

# Check 5 & 6: Minimum Password Length and Lockout Threshold (using secedit for reliability)
$tempFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $tempFile /quiet
$secConfig = Get-Content $tempFile | Where-Object { $_ -match "MinimumPasswordLength|LockoutBadCount" }
Remove-Item $tempFile -Force

$minLength = ($secConfig | Select-String "MinimumPasswordLength").Line.Split('=')[1].Trim()
$lockoutThreshold = ($secConfig | Select-String "LockoutBadCount").Line.Split('=')[1].Trim()

if ([int]$minLength -ge 12) {
    Add-CheckResult -CheckName "Minimum Password Length" -Status "Secure" -CurrentValue "$minLength characters" -Recommended "≥12" -Notes "Strong resistance to brute-force"
} elseif ([int]$minLength -ge 8) {
    Add-CheckResult -CheckName "Minimum Password Length" -Status "Warning" -CurrentValue "$minLength characters" -Recommended "≥12" -Notes "Acceptable but 12+ preferred"
} else {
    Add-CheckResult -CheckName "Minimum Password Length" -Status "Insecure" -CurrentValue "$minLength characters" -Recommended "≥12" -Notes "Too short - vulnerable"
}

if ($lockoutThreshold -eq "0") {
    Add-CheckResult -CheckName "Account Lockout Threshold" -Status "Insecure" -CurrentValue "Never" -Recommended "5-10 attempts" -Notes "No protection against brute-force"
} elseif ([int]$lockoutThreshold -le 10 -and [int]$lockoutThreshold -gt 0) {
    Add-CheckResult -CheckName "Account Lockout Threshold" -Status "Secure" -CurrentValue "$lockoutThreshold attempts" -Recommended "5-10 attempts" -Notes "Good brute-force mitigation"
} else {
    Add-CheckResult -CheckName "Account Lockout Threshold" -Status "Warning" -CurrentValue "$lockoutThreshold attempts" -Recommended "5-10 attempts" -Notes "Too high - reduces effectiveness"
}

# Check 7: AutoPlay/AutoRun Disabled (keeping your working version)
$autoPlayKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
if ($autoPlayKey -and $autoPlayKey.NoDriveTypeAutoRun -ge 255) {
    Add-CheckResult -CheckName "AutoPlay/AutoRun" -Status "Secure" -CurrentValue "Disabled" -Recommended "Disabled" -Notes "Prevents malware from removable media"
} else {
    Add-CheckResult -CheckName "AutoPlay/AutoRun" -Status "Warning" -CurrentValue "Partially/fully enabled" -Recommended "Disabled" -Notes "Common infection vector"
}

# Check 8: SMBv1 Protocol Disabled
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($smbv1 -and $smbv1.State -eq "Disabled") {
    Add-CheckResult -CheckName "SMBv1 Protocol" -Status "Secure" -CurrentValue "Disabled" -Recommended "Disabled" -Notes "Prevents EternalBlue/WannaCry exploitation"
} elseif ($smbv1) {
    Add-CheckResult -CheckName "SMBv1 Protocol" -Status "Insecure" -CurrentValue "$($smbv1.State)" -Recommended "Disabled" -Notes "Critical vulnerability - disable immediately"
} else {
    Add-CheckResult -CheckName "SMBv1 Protocol" -Status "Warning" -CurrentValue "Not found" -Recommended "Disabled" -Notes "Feature not detected"
}

# ============ HARDENING CHECKS END (more coming) ============

# Final output
Write-Host "`nHardening Audit Complete - $($Results.Count) checks performed`n" -ForegroundColor Cyan
$Results | Format-Table -AutoSize