#Requires -Modules Pester

<#
.SYNOPSIS
Comprehensive test suite for KvRbacMigrator - RoleMapping.json validation

.DESCRIPTION
This test suite validates the critical RoleMapping.json configuration file to ensure
all required Azure RBAC roles and permission mappings are correctly defined.

.EXAMPLE
# Run all tests
.\Tests.ps1

# Run only RoleMapping tests with Pester directly
Invoke-Pester -Path .\Tests.ps1 -Tag "RoleMapping"
#>

Write-Host "Starting KvRbacMigrator Test Suite" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Test categories with tags for selective execution
Describe "RoleMapping.json Validation" -Tag "RoleMapping", "Critical" {
    
    BeforeAll {
        # Reference RoleMapping.json in the parent directory
        $script:roleMappingPath = Join-Path (Split-Path $PSScriptRoot -Parent) "RoleMapping.json"
        
        # Ensure the file exists before we start testing
        if (-not (Test-Path $script:roleMappingPath)) {
            throw [System.IO.FileNotFoundException] "RoleMapping.json not found at $script:roleMappingPath"
        }
        
        $script:roleMapping = Get-Content -Path $script:roleMappingPath -Raw | ConvertFrom-Json
    }
    
    Context "Schema and Structure Validation" {
        
        It "Should exist and be readable" {
            $script:roleMappingPath | Should -Exist
            { Get-Content -Path $script:roleMappingPath -Raw } | Should -Not -Throw
        }
        
        It "Should contain required top-level sections" {
            $script:roleMapping.roleDefinitions | Should -Not -BeNullOrEmpty
            $script:roleMapping.secrets | Should -Not -BeNullOrEmpty
            $script:roleMapping.keys | Should -Not -BeNullOrEmpty
            $script:roleMapping.certificates | Should -Not -BeNullOrEmpty
            $script:roleMapping.rolePermissions | Should -Not -BeNullOrEmpty
        }
        
        It "Should have administrator mode configuration" {
            $script:roleMapping.administratorModeMapping | Should -Not -BeNullOrEmpty
            $script:roleMapping.administratorModeMapping.requiredObjectTypes | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Role Definitions Validation" {
        
        It "Should contain all expected Azure RBAC roles" {
            $expectedRoles = @(
                "Key Vault Reader",
                "Key Vault Secrets User", 
                "Key Vault Secrets Officer",
                "Key Vault Crypto User",
                "Key Vault Crypto Officer", 
                "Key Vault Certificate User",
                "Key Vault Certificates Officer",
                "Key Vault Administrator",
                "Key Vault Crypto Service Encryption User"
            )
            
            foreach ($role in $expectedRoles) {
                $script:roleMapping.roleDefinitions.$role | Should -Not -BeNullOrEmpty -Because "Role '$role' should be defined"
                $script:roleMapping.roleDefinitions.$role.id | Should -Not -BeNullOrEmpty -Because "Role '$role' should have an ID"
                [int]$script:roleMapping.roleDefinitions.$role.weight | Should -BeOfType [int] -Because "Role '$role' should have numeric weight"
            }
        }
        
        It "Should have valid Azure role definition GUIDs" {
            foreach ($roleName in $script:roleMapping.roleDefinitions.PSObject.Properties.Name) {
                $roleId = $script:roleMapping.roleDefinitions.$roleName.id
                $roleId | Should -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -Because "Role '$roleName' should have valid GUID"
            }
        }
        
        It "Should have logical weight hierarchy" {
            $adminWeight = $script:roleMapping.roleDefinitions."Key Vault Administrator".weight
            $officerWeight = $script:roleMapping.roleDefinitions."Key Vault Secrets Officer".weight
            $userWeight = $script:roleMapping.roleDefinitions."Key Vault Secrets User".weight
            $readerWeight = $script:roleMapping.roleDefinitions."Key Vault Reader".weight
            
            $adminWeight | Should -BeGreaterThan $officerWeight -Because "Administrator should have higher weight than Officer"
            $officerWeight | Should -BeGreaterThan $userWeight -Because "Officer should have higher weight than User"
            $userWeight | Should -BeGreaterThan $readerWeight -Because "User should have higher weight than Reader"
        }
    }
    
    Context "Permission Mapping Completeness" {
        
        It "Should map all Key Vault secret permissions" {
            $expectedSecretPermissions = @("get", "list", "set", "delete", "backup", "restore", "recover", "purge")
            
            foreach ($permission in $expectedSecretPermissions) {
                $script:roleMapping.secrets.$permission | Should -Not -BeNullOrEmpty -Because "Secret permission '$permission' should be mapped"
            }
        }
        
        It "Should map all Key Vault key permissions" {
            $expectedKeyPermissions = @("get", "list", "create", "update", "import", "delete", "backup", "restore", "recover", "purge", "decrypt", "encrypt", "unwrapKey", "wrapKey", "verify", "sign")
            
            foreach ($permission in $expectedKeyPermissions) {
                $script:roleMapping.keys.$permission | Should -Not -BeNullOrEmpty -Because "Key permission '$permission' should be mapped"
            }
        }
        
        It "Should map all Key Vault certificate permissions" {
            $expectedCertPermissions = @("get", "list", "create", "update", "import", "delete", "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers", "deleteissuers")
            
            foreach ($permission in $expectedCertPermissions) {
                $script:roleMapping.certificates.$permission | Should -Not -BeNullOrEmpty -Because "Certificate permission '$permission' should be mapped"
            }
        }
        
        It "Should ensure role permissions match individual mappings" {
            # Verify that rolePermissions section aligns with individual permission mappings
            $secretsOfficerPerms = $script:roleMapping.rolePermissions."Key Vault Secrets Officer".secrets
            $secretsUserPerms = $script:roleMapping.rolePermissions."Key Vault Secrets User".secrets
            
            $secretsOfficerPerms | Should -Contain "set" -Because "Secrets Officer should have 'set' permission"
            $secretsUserPerms | Should -Contain "get" -Because "Secrets User should have 'get' permission"
            $secretsUserPerms | Should -Not -Contain "set" -Because "Secrets User should not have 'set' permission"
        }
    }
    
    Context "Administrator Mode Security Logic" {
        
        It "Should require all object types for administrator mode" {
            $requiredTypes = $script:roleMapping.administratorModeMapping.requiredObjectTypes
            $requiredTypes | Should -Contain "secrets"
            $requiredTypes | Should -Contain "keys"
            $requiredTypes | Should -Contain "certificates"
        }
        
        It "Should have privilege escalation prevention logic defined" {
            $script:roleMapping.administratorModeMapping.useAdministratorFor | Should -Not -BeNullOrEmpty
            $script:roleMapping.administratorModeMapping.useAdministratorFor.exactPermissionMatch | Should -Be $true
            $script:roleMapping.administratorModeMapping.useAdministratorFor.preventPrivilegeEscalation | Should -Be $true
            $script:roleMapping.administratorModeMapping.useAdministratorFor.noAdditionalPermissions | Should -Be $true
        }
    }
    
    Context "Data Integrity Checks" {
        
        It "Should not have duplicate role mappings" {
            $allMappedRoles = $script:roleMapping.secrets.PSObject.Properties.Value +
                              $script:roleMapping.keys.PSObject.Properties.Value +
                              $script:roleMapping.certificates.PSObject.Properties.Value
            
            # Ensure all mapped roles exist in roleDefinitions
            foreach ($role in ($allMappedRoles | Sort-Object -Unique)) {
                $script:roleMapping.roleDefinitions.$role | Should -Not -BeNullOrEmpty -Because "Mapped role '$role' should exist in roleDefinitions"
            }
        }
        
        It "Should have consistent role names across sections" {
            $definedRoles = $script:roleMapping.roleDefinitions.PSObject.Properties.Name
            $permissionRoles = $script:roleMapping.rolePermissions.PSObject.Properties.Name
            
            foreach ($role in $permissionRoles) {
                $definedRoles | Should -Contain $role -Because "Role '$role' in rolePermissions should be defined in roleDefinitions"
            }
        }
    }
}


# SIG # Begin signature block
# MIIo2gYJKoZIhvcNAQcCoIIoyzCCKMcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8P2voYM+sSJte
# lUbQLrT23WlF+AfssXgVXzO3u8oL/qCCDcMwggatMIIElaADAgECAhMzAAAArn9k
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAJ5f88M6UQvZSD+xR7nR/Ha
# huAF8thaBtxzQ7LXVSKqMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAaMNcZ6P1jy3xCcndfYeb/X2O6jGDsirzDoBBGH1tENozrHtGMcn6qYRd
# hvyDNQCCzDhp6pqw+RH+weeyXW5m7vUWSuWSTAb3n1az8WxnKvicyz9pnzxPTFDu
# h7UpKldsDfzU119wSVtd6yeZD+TiGBtGItu+2YtwkcAoqsvjrVMICX1Ox2TYYSv/
# pWnSd2Fhhfqmie5CyBvFZ87bZiBCJUqfUvtGqbXu7IPENcSPPqkpGuiydLqN53kJ
# 4XB/lOSb2BuaiwjT3oeLVaHndO1nngjnLsJ84MhCq1Aq9YwpZxSTGme6Uc2L4/k4
# TJUwDeAhgPL6MQvblhJtxSWzx2r4kwqwMDjBmr0jIVK9Xt6XlShaUa4WKJ3fIOR6
# Clwck2DbwHMHgb6A2DHEZqZ703OHS9rj17NvU4+mRh92pZKmDc1loJOeyxG7X33T
# FL+UjWFojlBDN6FNIr9KNdf0NmAKznf0igjDkod0rPZNkvgidFo7xNLHwAxCrBBt
# Ugq7sdPIoYIXlDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIX
# bTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIMju6cqo1tvn
# Wzavdl1l3nJEaFa8e1GanWzQivFTsRCLAgZppyysUckYEzIwMjYwMzA1MTg0MjU3
# LjUyMVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5MjAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgEC
# AhMzAAACCQgH4PlcjOZVAAEAAAIJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI1NVoXDTI2MDQyMjE5NDI1
# NVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjo5MjAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AMKUSjD3Lgzd/VL3PXG00QRPBYvW8SKLDSgPtJcR2/ix0/TGxXKJ2/ojauYSXw9i
# z0txmPOxY4cjt1CREvbwY/cJdy9jRmrqdawdjZBqYJkUsXYiVEfoEfHZGQ3tlEMq
# azsE6jggYFGUIyRS/033+3A7MCSlY2wzdv8FDFzCFWCxCq1Dw0Q9S6JH4ZXmt1Ad
# RPimOKFlOQnCtqWLPRltilRMfk6SLd3cGnH2qI+uIHqGE18Y+OXQ8inbcPnv2ulb
# pmY+o9PyPXYpfvJJnA27Gzc9i8X/DXcaxFeTMhsjIsoQ/OP2XOaasXbCO+9SvH0B
# nDsYtJeTbwOfVdJ/raFuQW5QbA8UuncRtGohWYFnjbBzPmZIggLLdCz+HCERiFSd
# 2cAGA2kPlq8As5XuxR8mscNldfp/2CBuMgDqPaeFIBIiqXwXkuwoHDRE+0O7LePY
# I/G1OZmjNssrxMy3EOIwKDFOl+DmJhS/KFXhqpoMvBEGygFGE7/6HDJsqdjBfEp5
# 46uw7BAudo4TkGYUlhYE4XPd3zwsEr1BEGB0QfkItWHvCSAwh6H3pwfn4fTES+aD
# q3u7O2VdfZJXvF1Rg/EDe+ONXcSRXtptIcPkcdBlOt3cWqwP9U5gAJRUE+vEX6RS
# tkZfFgidlOmtgxgSrpQgbUNPikJU/0NxoIsYg5gQnWDTAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUSYvo0cRdOOW98C9AzbV3MxaTytIwHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAFxefG84PCTiH+NtQGycWUW2tK4EFlvvBJl9rmUpExM182WZoALht3ta
# jQjmEzGwQlTK6kfCHiQPmqRFlzMhzSMgAFBDXENQFr5ZPGun9QCoLXuKMUJ49kph
# WM2sd/8GaPPsVo4jjWTG55GHAs0hxDaCYGoNHlbhNLaG1EljJkCzuN8mZsO1NxQ4
# yESXU5aXH8We9xBui3lU/NpTCJPo2J7yXo9mOhCy7GJqy5ICbEohB2wecnlCiSrB
# 3KpeLUVkO0RNW9td8Oyh/NO1rh6fap/jyHMRnBS9uTPmya3z3SdUAruTPZyuvM3e
# Gmd8W5+2n+tctZO/E9Bx9ZeIS4hR3YaDt5HxC3Iq0kNTz48PAQKTOhomNsYIqrH0
# RKAUnPOtc3CGFfpFzyDYRT/7reaapZ4IX+Qk4WDZ4nDtq79psRKCrcRrPIPVWUv4
# dpf4wEcbNCYe286bdCXjBVM3darxfxsJHryqIXmsVqybhHEXrNqNl5IcL+pLnffr
# /howOqxXo7zpGU88JgYk4+1/Yxso7tckl4v9RA3Rze6LHlExOjrp1sBPE9QUQbk+
# Hg8fMaNRsQ7sPfku4QGKIbxiuUxE6QaXd8FCX1tZuDD0IhRBvCrlxNoTGV8Skx1K
# jJ0miVRNAPkQsobPVMlqFOJ13bTCXCLkGTfpcibOwfhizXmJdF8CMIIHcTCCBVmg
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
# IFRTUyBFU046OTIwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHzvras9NB3sicMJB1vWSAUp
# CQJEoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtU6UUMCIYDzIwMjYwMzA1MDY0NTQwWhgPMjAyNjAzMDYwNjQ1
# NDBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAO1TpRQCAQAwBwIBAAICBX0wBwIB
# AAICE7cwCgIFAO1U9pQCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoD
# AqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAJ3jb
# 3432vS+wN/18pKR0pfL74Pj7lwx4TJ9g8AkeNRkzkzSRAFdJLwvn/YPYmbO/WUhc
# aPl6r6Jq9TlUnOBAAkNWqlOSWZ8vGU3MW8tV9xLev+gMtWAPieS5IA+8hNvI7Lv9
# r3jVM+H89hKQtXw7xzf6oRFx5Ke5/rLwdzspVgfcr7WQBmfRb4NkZlDM47Qx5ay1
# 8H8MExCZQL9qPzLbRVyecL+RFvRULDLhvp3U28YFQu0QXd4c7/GwaPlCknAbOQ41
# jKelRxfMU0QUHwIU1ZOjizts1ux1TaxCLS+hc8121H5F7oZ5cgB1a17P6Oc8CQuk
# zdB5DhKWgPm5IfjtWTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAACCQgH4PlcjOZVAAEAAAIJMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIOHg
# WI2HtFSSC36p/lYd0nX+5HuS9oaNHnHqeCfZSfKXMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgaBssHsi99AIuZQ5RmGN1SorxuKR8HplVV2hOM3CFEz4wgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgkIB+D5XIzm
# VQABAAACCTAiBCB+DP2RXRmhE/K5c4aHTG0DZiwoS5StmD4hy890FoOUszANBgkq
# hkiG9w0BAQsFAASCAgCRnzw5Nbj8tyBtjwX7ra1B7PlWSQikOec5ZwkyGnRMnVgR
# BHcG6uyvUigw0q80Rs/Rj0hRbDbSOWSZdTYpPVNnDpnKmSQXTbeIh9i6gxhPPe93
# Six3bSQ3EazWU47sM5hCzWQ7M2jlksiAOY7UcYsZpkjcMEfopvs6CCiXsQDcUYjx
# ZFq8S3/0nH/e4PDc+eK1xiz2yHrAF/ivxzk07m8RSwbyv+rjbZKoGTq7tqAbgwQF
# lR7siiailjy7H5wYS+gjFUPA2Gr9+KoAsotoKlPCgCeVsdhc9NqIL+ijRfUvMKYb
# 6yyvntwSVMirqTBVPBlOHmp1RDXNkHdJtpaOXhb5MdOX+s990wrpgLNDSDEqUa0I
# Y4HP1hxZlCtRQaIlzXD4th5LC6TN0fA1CXe9zXD0PK30JnC+mowPUswo9qCleRGY
# lzzmTjk09zrjcG/SiYzg7Oluee5JuN+GgGTfMQiNBaCGusiIqRGbS4wb9HNJArFy
# gUf+Y/hK/yYaa0Ke2G63FNBN+luHumnE9mem2qdEz+K/Bi6l3NPupg3bZXtyb3oD
# tsDrBoxEVjHcVbAlwnzuVWQakKyv9dc0nKgBWgwKnvV0eYcBbWGdtXQL2BSw3dzU
# GoXXHC+z1HCW6Yhy2BKxeSlHBqnlPCUydaRi4W4yONWOodvUxgsj4KszCGQOnQ==
# SIG # End signature block
