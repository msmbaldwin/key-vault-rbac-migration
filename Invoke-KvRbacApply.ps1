[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$InputJson = ""
)

# Import common functionality
. (Join-Path $PSScriptRoot "Common.ps1")

# Import analysis functions to reuse Get-RoleMapping and Test-ScopeParameters
. (Join-Path $PSScriptRoot "Invoke-KvRbacAnalysis.ps1")

function Invoke-RoleAssignment {
    <#
    .SYNOPSIS
    Creates a role assignment with error handling and WhatIf support
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [string]$ObjectId,
        [string]$RoleDefinitionName,
        [string]$RoleDefinitionId,
        [string]$Scope
    )
    
    try {
        # Check if assignment already exists
        $existingAssignment = if ($RoleDefinitionId) {
            Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionId $RoleDefinitionId -Scope $Scope -ErrorAction SilentlyContinue
        } else {
            Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction SilentlyContinue
        }
        
        if ($existingAssignment) {
            Write-Host "  Role assignment already exists for $ObjectId" -ForegroundColor Yellow
            return @{ Success = $true; Message = "Already exists"; Skipped = $true }
        }
        
        # Check if we should proceed with the assignment
        if (-not $PSCmdlet -or $PSCmdlet.ShouldProcess("principal '$ObjectId' with role '$RoleDefinitionName'", "Create Role Assignment on scope '$Scope'")) {
            $assignment = if ($RoleDefinitionId) {
                New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionId $RoleDefinitionId -Scope $Scope -ErrorAction Stop
            } else {
                New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop
            }
            
            Write-Host "  ✓ Successfully assigned '$RoleDefinitionName' to $ObjectId" -ForegroundColor Green
            return @{ Success = $true; Message = "Successfully assigned"; Assignment = $assignment }
        }
        else {
            # This block runs when -WhatIf is used
            return @{ Success = $true; Message = "WhatIf: Assignment skipped"; Skipped = $true }
        }
    }
    catch {
        $errorMsg = "Failed to assign '$RoleDefinitionName' to $ObjectId : $($_.Exception.Message)"
        Write-Host "  ✗ $errorMsg" -ForegroundColor Red
        return @{ Success = $false; Message = $errorMsg; Error = $_.Exception }
    }
}

function Invoke-KvRbacApply {
    Write-LogInfo "Key Vault RBAC Role Assignment Application"
    Write-LogInfo "Log file: $(Get-LogFilePath)"
    
    # Validate InputJson parameter is provided
    if ([string]::IsNullOrEmpty($InputJson)) {
        Write-Error "InputJson parameter is required"
        return
    }
    
    # Validate input file
    if (-not (Test-Path $InputJson)) {
        Write-Error "Input JSON file not found: $InputJson"
        return
    }
    
    # Load analysis results
    try {
        $analysisData = Get-Content -Path $InputJson -Raw | ConvertFrom-Json
        Write-Host "Loaded analysis data for $($analysisData.Count) vaults" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to parse input JSON: $($_.Exception.Message)"
        return
    }
    
    # Load role mappings
    try {
        $roleMapping = Get-RoleMapping
        Write-LogInfo "Role mapping loaded successfully"
    }
    catch {
        Write-LogError "Failed to load role mapping: $_"
        return
    }
    
    # Summary counters
    $totalVaults = 0
    $processedVaults = 0
    $skippedVaults = 0
    $failedVaults = 0
    $totalAssignments = 0
    $successfulAssignments = 0
    $failedAssignments = 0
    $skippedAssignments = 0
    $subscriptionAssignmentCounts = @{}

    # Subscription-level RBAC assignment summary
    $subscriptions = $analysisData | Select-Object -ExpandProperty SubscriptionId -Unique
    foreach ($sub in $subscriptions) {
        $subScope = "/subscriptions/$sub"
        $currentCount = (Get-AzRoleAssignment -Scope $subScope -ErrorAction SilentlyContinue).Count
        $subscriptionAssignmentCounts[$sub] = $currentCount
        $subVaults = $analysisData | Where-Object { $_.SubscriptionId -eq $sub }
        $neededCount = 0
        foreach ($subVault in $subVaults) {
            foreach ($principal in $subVault.Principals) {
                if ($principal.RequiredRBACRoles) {
                    $neededCount += ($principal.RequiredRBACRoles | Where-Object { -not $_.AlreadyAssigned }).Count
                }
            }
        }
        $projectedTotal = $currentCount + $neededCount
        Write-Host ""
        Write-Host "Subscription: $sub" -ForegroundColor Cyan
        Write-Host "  Current RBAC assignments in subscription: $currentCount" -ForegroundColor Cyan
        Write-Host "  Projected total after assignments: $projectedTotal" -ForegroundColor Cyan
    }
    
    foreach ($vault in $analysisData) {
        $totalVaults++

        if ($vault.Status -ne "Analyzed") {
            Write-Host "Skipping vault '$($vault.VaultName)' - Status: $($vault.Status)" -ForegroundColor Yellow
            $skippedVaults++
            continue
        }
        
        # Count needed assignments
        $neededAssignments = @()
        foreach ($principal in $vault.Principals) {
            if ($principal.RequiredRBACRoles) {
                foreach ($role in $principal.RequiredRBACRoles) {
                    if (-not $role.AlreadyAssigned) {
                        $neededAssignments += @{
                            PrincipalId = $principal.PrincipalId
                            RoleName    = $role.name
                            RoleId      = $role.id
                        }
                    }
                }
            }
        }

        # Use precomputed subscription-level assignment count
        $assignmentCount = $subscriptionAssignmentCounts[$vault.SubscriptionId]
        $potentialTotal = $assignmentCount + $neededAssignments.Count
        if ($potentialTotal -gt 4000) {
            Write-Host "WARNING: Assigning all needed RBAC roles ($($neededAssignments.Count)) would put subscription $($vault.SubscriptionId) over the 4,000 assignment limit ($potentialTotal total). Some assignments may fail!" -ForegroundColor Red
        }
        
        if ($neededAssignments.Count -eq 0) {
            Write-Host "Skipping vault '$($vault.VaultName)' - No role assignments needed" -ForegroundColor Yellow
            $skippedVaults++
            continue
        }
        
        # Display vault information
        Write-Host "`nVault: $($vault.VaultName)" -ForegroundColor Cyan
        Write-Host "Resource Group: $($vault.ResourceGroup)" -ForegroundColor Cyan
        Write-Host "Needed Assignments: $($neededAssignments.Count)" -ForegroundColor Cyan
        
        foreach ($assignment in $neededAssignments) {
            Write-Host "  - $($assignment.RoleName) for $($assignment.PrincipalId)" -ForegroundColor White
        }
        
        # Process assignments if user confirms or -WhatIf is not used
        if ($PSCmdlet -and -not $PSCmdlet.ShouldProcess($vault.VaultName, "Apply $($neededAssignments.Count) Role Assignment(s)")) {
            $skippedVaults++
            # Add the number of assignments that would have been created to the skipped count for the final summary
            $skippedAssignments += $neededAssignments.Count
            $totalAssignments += $neededAssignments.Count
            continue
        }

        $processedVaults++
        $vaultScope = "/subscriptions/$($vault.SubscriptionId)/resourceGroups/$($vault.ResourceGroup)/providers/Microsoft.KeyVault/vaults/$($vault.VaultName)"
        $vaultSuccessful = 0
        $vaultFailed = 0
        $vaultSkipped = 0
        
        foreach ($assignment in $neededAssignments) {
            $totalAssignments++
            
            # Pass the -WhatIf parameter down to the helper function
            $whatIfPreference = if ($PSBoundParameters.ContainsKey('WhatIf')) { $PSBoundParameters['WhatIf'] } else { $false }
            $result = Invoke-RoleAssignment -ObjectId $assignment.PrincipalId -RoleDefinitionName $assignment.RoleName -RoleDefinitionId $assignment.RoleId -Scope $vaultScope -WhatIf:$whatIfPreference
            
            if ($result.Success) {
                if ($result.Skipped) {
                    $skippedAssignments++
                    $vaultSkipped++
                }
                else {
                    $successfulAssignments++
                    $vaultSuccessful++
                }
            }
            else {
                $failedAssignments++
                $vaultFailed++
            }
        }
        
        Write-Host "  Vault Summary: $vaultSuccessful successful, $vaultSkipped skipped, $vaultFailed failed" -ForegroundColor $(if ($vaultFailed -gt 0) { 'Red' } else { 'Green' })
        
        if ($vaultFailed -gt 0) {
            $failedVaults++
        }
    }
    
    # Final summary
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Vaults processed: $processedVaults/$totalVaults (skipped: $skippedVaults, failed: $failedVaults)" -ForegroundColor White
    Write-Host "Role assignments: $successfulAssignments created, $skippedAssignments skipped, $failedAssignments failed (total: $totalAssignments)" -ForegroundColor White
    
    if ($failedVaults -gt 0 -or $failedAssignments -gt 0) {
        Write-Host "Some operations failed. Review the output above for details." -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host "All operations completed successfully!" -ForegroundColor Green
    }
}

# Main execution - only run if not dot-sourced
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-KvRbacApply
}

# SIG # Begin signature block
# MIIo2gYJKoZIhvcNAQcCoIIoyzCCKMcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA+97twtRF/jM4O
# aSME9/bIttDWazomfHgn6bK6hV9yV6CCDcMwggatMIIElaADAgECAhMzAAAArn9k
# 1tYsMf4JAAAAAACuMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMzAxBgNVBAMTKkF6dXJlIFJTQSBQ
# dWJsaWMgU2VydmljZXMgQ29kZSBTaWduaW5nIFBDQTAeFw0yNTA2MTkxODU1NTha
# Fw0yNjA2MTcxODU1NThaMIGCMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSwwKgYDVQQDEyNBenVyZSBQdWJsaWMgU2VydmljZXMgUlNBIENvZGUg
# U2lnbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAIRy9Jav+qjrsKKb
# Vcy2KamcS2PmseebRp/jyYNO0toLB0s0QN8Q99LDDItAglhi0pF/IH1dpgqJQ2vm
# 6A+h4n0sC2AjCQkVF+ScgVMXmf59ZgyMFXrI2hOTih/5dPOCbhW/u55g8cxbKA4R
# oC8EnAvARzfOhptPTF3y2Psavn8wn2zwPOXNzhZl2cNMZkMJguNzoH0mzUKMlUbO
# 8a2pBEj/4Z/vGKGGjlioVX6ci6++K+mYalr+HVECbU9+MFL+iuiX/HE/gMBl0vJf
# M9MMOWVJsb2JX1FYf4gBUINrTfcJEoXPtwCiKE4Ocy28Y4qOel5ulP5mnvt0ndpu
# WHCNNo05gec0BJHWMfK2QimrtAd7Vi2jAkG80DgNtRvuNtunvb79oYo/EGKmvD5U
# Q5JAZoRTGYuuZG5JiyUj8XKhG/4z05iG8UaqnICVdhuOGq9Af1JtubOsY5Pf5seE
# jtpjiPn69FiESN/VwiaFz3hnqaUfzbqzEFPKdDqm6tCcmFXfBwIDAQABo4IBuTCC
# AbUwDgYDVR0PAQH/BAQDAgeAMB8GA1UdJQQYMBYGCCsGAQUFBwMDBgorBgEEAYI3
# WwEBMB0GA1UdDgQWBBS9m3ktbtjEjFmjMaYZvOm3b/H+5DBFBgNVHREEPjA8pDow
# ODEeMBwGA1UECxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMRYwFAYDVQQFEw00Njk5
# ODErNTA1MjkyMB8GA1UdIwQYMBaAFPEvupEWfN59Uicx9Xr71VhZaTo9MG8GA1Ud
# HwRoMGYwZKBioGCGXmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3Js
# L0F6dXJlJTIwUlNBJTIwUHVibGljJTIwU2VydmljZXMlMjBDb2RlJTIwU2lnbmlu
# ZyUyMFBDQS5jcmwwfAYIKwYBBQUHAQEEcDBuMGwGCCsGAQUFBzAChmBodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL0F6dXJlJTIwUlNBJTIwUHVi
# bGljJTIwU2VydmljZXMlMjBDb2RlJTIwU2lnbmluZyUyMFBDQS5jcnQwDAYDVR0T
# AQH/BAIwADANBgkqhkiG9w0BAQwFAAOCAgEAHqIN6Re5DdV7TxZBAy69e8RGQDSr
# gSl/XnxV9m2FB5nl56PUW/QBZN/Ge47ynj1KWSDzXVTlS6u6jdoy2F18yqC/pjaV
# l9ffmatw5Q27dS+IKpjSlRCYV3PfSGkdxre4B6fq9XNdW6I1rnI0nmsbyiYXHmaN
# YcfKwgg7IK4FzbWxxqywk3TGOibaVfqwwcaHtdb9pqHQJt5zJqjCjFFZg9AWsUNS
# rlymWKM2DKKs9eUKslcE1NmQgU+2IFIkkyheW+RT7UfTFVwnqRTD2o6gB3E24jmE
# C8sYh+3W298veaWNbjMVaO+GCROzOlA1uCoQkSzpb1z/LcJnWGgY4YVy4yAtKSvP
# P0WNHqvxAPC+7mCYALh5plC/lWYQXQMrnqHxSIgh8x0RAK44BRVlkG4sYTkBFfxq
# dWJMDIBatvKql4bBC2ArAkY/CsFf5xIQV4cm841s38TKGBB0Ur4LxvRIL+J2qG6s
# EkKKkeA14LpKkfLEUF3u85iyPZLdTHlpV/jIovLLcu2cDNb86CW6s9OUpjflQ16n
# xydFfOK4iPzYr0PGZAja18Kls2s/qB/nz3e1nfP/OiMwjLQ9yaAZKC164IlqMDaw
# rKb0VpF53lQZcUrNRU0ENt3lgsvitz3ZT5WhSE4nlnA+kiWE0JKERFP+NFGDRwaN
# RD6JgXWZ0huICuowggcOMIIE9qADAgECAhMzAAAAArLEk4h4WezTAAAAAAACMA0G
# CSqGSIb3DQEBDAUAMFsxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLDAqBgNVBAMTI01pY3Jvc29mdCBSU0EgU2VydmljZXMgUm9v
# dCBDQSAyMDIxMB4XDTIxMDkwMjE3NDExOVoXDTM2MDkwMjE3NTExOVowYjELMAkG
# A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEzMDEGA1UE
# AxMqQXp1cmUgUlNBIFB1YmxpYyBTZXJ2aWNlcyBDb2RlIFNpZ25pbmcgUENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApd39LL3WcWCx5Uk4WB5GFXGt
# xqHKnVgZI3QWk4SARERVvc0P9CAjsjTJ3tcbo4TxWiavkUzG8rxO8ngtzos/0EPP
# YZJrUzQuXMcpfvnv/bgLRmd3NxwDWpCLTT4GaY6vimWbFHNMW/g+F3DzIE8X0YO8
# KWpXwBK+9uK1+NoPt1U84Utvs3t++3+paiAY3l6KzQVcKpUl2Y9llpfaHiIbSi2w
# CF+rzK9KUnRjA7iLkYN4tDBOww3VF/ZQAdAoJRiQWwtJDSaptpFsNmEH7akUv+r9
# zZrqGUcudqljJ/CU0VeQOHAAVYTN/AUcRHahHjZRrJ8322w7+na1aTfcKucd2d0k
# OshnqhDcP42CiX9NHwECBcIgzqx7piUsNOzFHCH1BQOrspWErLnwcYolSrCAhbQT
# ty+XNSXQd+395uEAtnIUOSGh/0LkKrhz/jzpcuNCrSdu4qwU2FBTTK8AFHd6iHDr
# cqmzrpSZrjygTQmao7GbOs++shNhyycHIqV6Ief7jKr5Oz8qu2qRDBBy6KQw+tnB
# cK2xiTExTJSfyCvyh7DbZYN4hAQIAzULP1Nx0lp2ytOgqpdBrZsCf8AAEBjKiA88
# 418a+iNMjcOVgPjZ60xr+A95klq9f7PvHx3/h5gGcn1YVKL2rS/68s4Zzd/IzYpC
# 2rl5VsdfmtXJZzpsnfkCAwEAAaOCAcIwggG+MBAGCSsGAQQBgjcVAQQDAgEAMB0G
# A1UdDgQWBBTxL7qRFnzefVInMfV6+9VYWWk6PTBUBgNVHSAETTBLMEkGBFUdIAAw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsG
# A1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFA4MsWRpvS2x
# 1WsmpkfqVk6Aw+2KMGYGA1UdHwRfMF0wW6BZoFeGVWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFJTQSUyMFNlcnZpY2VzJTIw
# Um9vdCUyMENBJTIwMjAyMS5jcmwwcwYIKwYBBQUHAQEEZzBlMGMGCCsGAQUFBzAC
# hldodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
# dCUyMFJTQSUyMFNlcnZpY2VzJTIwUm9vdCUyMENBJTIwMjAyMS5jcnQwDQYJKoZI
# hvcNAQEMBQADggIBAGKfs8wGdeOcgnTH74ue50sNZadnx1mYnXgO5l9Syz92hROE
# sAzhyusdpNsmi6VRQQs13YCc6lf9ni16dQxPeyNgh09jIl8hhY9Gp8jo1vP4lUrt
# FG+faeXkQQwi5ETpQpL1kYFt/TZruxvTgT/sE382GGua1L+1UWN9GutWH3NeS7jm
# upa4LBRPODcSrEpDw4Zu2MFC2r9LJv9yWbkEeyiHdeEydv1Uu/cbV241/3QUvn+j
# zxdngvXyfHWV+TLaeWVjgcgDw8rwBquoBbiIpJMDcQaqfyz/jta1ApP6oQPZhtld
# U5gv4vu9AMKcVvCGADHq5y4zPsB7WuqJuDcCOwLtTkzegD++oAcMoMDeZ0zkPov9
# kR1CBobbQeFQ5JD4KJAPdPIdKJUJ9Uy5O/zciIoKeLctb/be0cLa1s3nuuWExyjK
# MiL4hV3uPuzjUwUFoPAmuZ9ef9gz6VH/lCq87vNYBtuv9dTnfW/eOv+MGKWauq3p
# T9vvLxNfID2djFX2JIwWZxvIiLbGB1wAeHGeldy9y/IVYRPpiImLJ5IlnDAm/yDB
# eIEX5mHQgcCuXopWxsB2wBO4/VMIQGk/KddmaS+IgRY+2e/fXlmNMLuc+g6lKc5V
# o7vBnO2s559m6cjl8HHDuYbWjKhGcANlrCIWxWj0n9wO7XkStEJ8NBGHBKIFMYIa
# bTCCGmkCAQEweTBiMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTMwMQYDVQQDEypBenVyZSBSU0EgUHVibGljIFNlcnZpY2VzIENv
# ZGUgU2lnbmluZyBQQ0ECEzMAAACuf2TW1iwx/gkAAAAAAK4wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII77HE8ZX1y1Zu2LaUkSDHZ9
# MzeJ/qXBPdOH/yA6yZdjMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAJ6su/TYoowKdN9ObgX4aoshRd+BASJCrFxfPjKsrX+ZPPz8OPLPNXi3e
# vKSSPiLGsk/IvCB41gvhnbwgNN4ROL/4mdF1USZHlqye65PBp2DxwpCT+ewAseU1
# y8J3AY5j3w5yIJJa/PvdlZuxeUBEfe/6wPAxF0TLGynm83IWc2ChWWFGuUCEhgxo
# vaPXmGY+u+bIHLLmaN01QPLfTfj3f7qkEt3OZkD54sWgigN1vSnBqsaLeb+tRsGs
# FXbFwSjV5eYcZ2RUMquotc2cDQu95vzbCpxZU4tlis/EU3RzBWj+tDnZBSK5u2yd
# 91kCYzCrP0iGbTlZYAi7AY6uAe4wORPlaibI+2OWd/5885PrLU+eu1dHFSLgaueP
# pWhkHAeVbzn5fQv4PM0g5NnCBqYfbKbJCTpm1Ogn01+zwDSv9oHC258YpJTHOoA+
# s9Z1/1CYb8pnaeo2HC5djJC27X2A9VVgtnHMEXVPo5dete3JRcS4PFJEs6f+rQH6
# Rhpiwk9goYIXlDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIX
# bTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIAkBW6e7HlDg
# rNMrl1EjWhcdrh9ai9ZphXeHDKwOsmzeAgZplJxQeCMYEzIwMjYwMzA1MTg0MjU5
# LjIyOVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo4NjAzLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgEC
# AhMzAAACBywROYnNhfvFAAEAAAIHMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI1MloXDTI2MDQyMjE5NDI1
# MlowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjo4NjAzLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AMU//3p0+Zx+A4N7f+e4W964Gy38mZLFKQ6fz1kXK0dCbfjiIug+qRXCz4KJR6NB
# psp/79zspTWerACaa2I+cbzObhKX35EllpDgPHeq0D2Z1B1LsKF/phRs/hn77yVo
# 1tNCKAmhcKbOVXfi+YLjOkWsRPgoABONdI8rSxC4WEqvuW01owUZyVdKciFydJyP
# 1BQNUtCkCwm2wofIc3tw3vhoRcukUZzUj5ZgVHFpOCpI+oZF8R+5DbIasBtaMlg5
# e555MDUxUqFbzPNISl+Mp4r+3Ze4rKSkJRoqfmzyyo1sjdse3+sT+k3PBacArP48
# 4FFsnEiSYv6f8QxWKvm7y7JY+XW3zwwrnnUAZWH7YfjOJHXhgPHPIIb3biBqicqO
# JxidZQE61euc8roBL8s3pj7wrGHbprq8psVvNqpZcCPMSJDwRj0r2lgj8oLKCLGM
# PAd9SBVJYLJPwrDuYYHJRmZE8/Fc42W4x78/wK0Ekym6HwIFbKO8V8WY5I1ErwRO
# RSaVNQBHUIg5p4GosbCxxKEV/K8NCtsKGaFeJvidExflT1iv13tVxgefp5kmyDLO
# HlAqUhsJAL9i+EUrjZx4IEMxtz463lHpP8zBx7mNXJUKapdXFY5pBzisDadXuicw
# 5kLpS8IbwsYVJkGePWWgMMtaj8j5G5GiTaP9DjNwyfCRAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUcrVSYsK9etAK9H3wkGrXz/jOjR4wHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAOO7Sq49ueLHSyUSMPuPbbbilg48ZOZ0O87T5s1EI2RmpS/Ts/Tid/Uh
# /dj+IkSZRpTvDXYWbnzYiakP8rDYKVes0os9ME7qd/G848a1qWkCXjCqgaBnG+nF
# vbIS6cbjJlDoRA6mDV0T245ejN7eAPgeO1xzvmRxrzKK+jAQj6uFe5VRYHu+iDhM
# ZTEp2cO+mTkZIZec6E8OF0h36DqFHJd1mLCARr6r0z1dy3PhMaEOA4oWxjEWFc0l
# mj0pG4arp6+G3I125iuTOMO1ZLqBbxqRHn1SG4saxWr7gCCoRjxaVeNAYzY5OTIG
# eVAukHyoPvH2NGljYKrQ5ZaUrTB8f/XN5+tY3n5t7ztLDZM9wi50gmff1tsMbtrA
# oxVgMd+w8nxm/GBaRm5/plkCSmHR5gaHchXzjm1ouR0s4K/Dj1bGqFrkOaLY6OHw
# aNrm/2TJjcpMXJfdPgLaxzF+Cn/rFF34MY6E1U+9U9r/fJFSpjmzlRinLwOdumlX
# udA7ax7ce8JJutv7I/J6hvWRR8xhr18TZsSygxs5odGAaOLxk+38l3Zs991CgEdx
# Q6o/CMcFQhxJzvF0lliNFvibzWrGOZrcMuO44WWMxlNii9GIa8Qwv3FmPakdFTK/
# 6zm/tUbBwzquM1gzirNlAzoDZEZgkZTvzQZAbRA73zD6y5y5NWt9MIIHcTCCBVmg
# AwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
# b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgy
# MjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ck
# eb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+
# uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4
# bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhi
# JdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD
# 4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKN
# iOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXf
# tnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8
# P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMY
# ctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9
# stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUe
# h17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQID
# AQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4E
# FgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9
# AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38
# Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTlt
# uw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99q
# b74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQ
# JL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1
# ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP
# 9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkk
# vnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFH
# qfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g7
# 5LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr
# 4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghi
# f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA00wggI1AgEBMIH5oYHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVANO9VT9iP2VRLJ4MJqInYNrm
# FSJLoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtVDAzMCIYDzIwMjYwMzA1MTYzOTE1WhgPMjAyNjAzMDYxNjM5
# MTVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAO1UMDMCAQAwBwIBAAICE44wBwIB
# AAICEjQwCgIFAO1VgbMCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoD
# AqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAfvdF
# kLcbeEm4YGQB+/UsPFiaFXC033s8lNJG3m0Z4Vxhd/H1vJFI6JguVAJzSOiWrHKX
# 7xgifFYkCviCsUJxaewfNxORKKOKk6VOUYIIHyRCMc/GGRr7G7NTmK7ZeQavT9hK
# BBQxew5vutoXPVUvLDnMVqt8E3adZ6lKg+mvrhfwOZfqv+I4p9khxBhwY6wg62Xi
# xrtAQRWCLyKX7XZIw9hx3VHSg0p4IvptOTNziA27ymKhBsIouH7d949l51BDNG2K
# z4sQDmudDi/QxnBFDUl2gZnaBtPROBAMpGIVwf/oaawi6pOgMnJJ8o8XU39OBWbx
# s9WDjzMAo65FfGgOtTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAACBywROYnNhfvFAAEAAAIHMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIHIy
# 6JSkhiMpAJQCDL/voZ9vGCY1Bvt24j4BM2kT0MIDMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgL/fU0dB2zUhnmw+e/n2n6/oGMEOCgM8jCICafQ8ep7MwgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgcsETmJzYX7
# xQABAAACBzAiBCC+jMGLsi6MTP9ax83nz2iq3LNzzI4Bd8tHDJ4yNfOh0DANBgkq
# hkiG9w0BAQsFAASCAgClUltstheTaVjLzoELxTk7yT+Fg9nDmisQMPc10xBXEr8J
# vLfKtfhNO8tHn65y+/iaQxp7tnM43ykMRLHgIgWqcW0p+3kB2UpllrXCk7uV1PFQ
# zuQfIrIXFAujfRA0469ZgfPiLI9UuAL7ZZMeSrKJGYFm+iYW8t4ZjIFwcv8ZcgGQ
# XFZ5xP5caPvIcj/B3vuOBMoCiMCID0+Bggi9fmf5aUYgu+E7qxOH4bMCzoR2nAk8
# DHW42iefBb+IPAmPamicxk5ElVdFaBdV+nifjdepwe0UyiA5/B+HXR1iS/DRbwHd
# UaY8pqBBDoZr60432WyKWCJExpFXdk1tjOK/CZAgfwO+x6PW7+O/Q1h5cFaEFyWm
# MHtEHjERktylk+0jISA8Dvz7zxmsr2UxopNuVNsMVs6rxUXmUDSUtEk2XYwHpQew
# t695FAoyQloYJ9R4XFYPyECOBnePLo/3mmZfF3T3RJwzKjyGWXe8iL2TNp9/ZOk6
# CqDcnIPtn36fRMQNMXAhOofUcYzePq/RVZveefKYHJS1GvNNPWh8q1vjk9/ZSivb
# 3PqgJ04T2tKLc4XQbg5L04gA/z2K32zFNKVuOxdhSPvxMNVLHaJaiwy9GgUw/Saf
# 9YtiOSiMoM3899rzjI4zCYFvNyF3uthcuDt1J4PouHGL29a8XheSoJsWcDBVRw==
# SIG # End signature block
