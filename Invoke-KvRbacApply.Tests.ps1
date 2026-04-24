#Requires -Modules Pester

Describe "Invoke-KvRbacAnalysis.ps1 Integration Test" {

    # This BeforeAll block runs once. It sources the scripts and sets up a comprehensive,
    # shared mock role mapping that is valid for the test.
    BeforeAll {
        . "$PSScriptRoot/../Common.ps1"
        . "$PSScriptRoot/../Invoke-KvRbacAnalysis.ps1"
        Initialize-AuditLogging

        $script:mockRoleMapping = @{
            roleDefinitions = @{
                "Key Vault Reader"                 = @{ id = "21090545-7ca7-4776-b22c-e363652d74d2"; name = "Key Vault Reader"; weight = 10 }
                "Key Vault Secrets User"           = @{ id = "4633458b-17de-408a-b874-0445c86b69e6"; name = "Key Vault Secrets User"; weight = 20 }
                "Key Vault Secrets Officer"        = @{ id = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"; name = "Key Vault Secrets Officer"; weight = 30 }
                "Key Vault Crypto User"            = @{ id = "12338af0-0e69-4776-bea7-57ae8d297424"; name = "Key Vault Crypto User"; weight = 20 }
                "Key Vault Crypto Officer"         = @{ id = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603"; name = "Key Vault Crypto Officer"; weight = 30 }
                "Key Vault Certificates Officer"   = @{ id = "a4417e6f-fecd-4de8-b567-7b0420556985"; name = "Key Vault Certificates Officer"; weight = 30 }
                "Key Vault Administrator"          = @{ id = "00482a5a-887f-4fb3-b363-3b7fe8e74483"; name = "Key Vault Administrator"; weight = 40 }
            }
            administratorModeMapping = @{
                requiredObjectTypes = @("secrets", "keys", "certificates")
            }
            rolePermissions = @{
                "Key Vault Administrator" = @{
                    secrets      = @("get", "list", "set", "delete")
                    keys         = @("get", "list", "create", "import", "update", "delete", "sign")
                    certificates = @("get", "list", "create", "import", "update", "delete")
                }
                "Key Vault Secrets Officer" = @{ secrets = @("get", "list", "set", "delete") }
                "Key Vault Crypto Officer" = @{ keys = @("get", "list", "create", "import", "update", "delete", "sign") }
                "Key Vault Certificates Officer" = @{ certificates = @("get", "list", "create", "import", "update", "delete") }
            }
            secrets = @{ "get" = "Key Vault Secrets User"; "list" = "Key Vault Secrets User"; "set" = "Key Vault Secrets Officer"; "delete" = "Key Vault Secrets Officer" }
            keys = @{ "get" = "Key Vault Crypto User"; "list" = "Key Vault Crypto User"; "create" = "Key Vault Crypto Officer"; "import" = "Key Vault Crypto Officer"; "update" = "Key Vault Crypto Officer"; "delete" = "Key Vault Crypto Officer"; "sign" = "Key Vault Crypto Officer" }
            certificates = @{ "get" = "Key Vault Certificates Officer"; "list" = "Key Vault Certificates Officer"; "create" = "Key Vault Certificates Officer"; "import" = "Key Vault Certificates Officer"; "update" = "Key Vault Certificates Officer"; "delete" = "Key Vault Certificates Officer" }
        }
    }

    It "Should correctly analyze policies and export the 'AlreadyAssigned' status" {
        # This single, isolated test verifies the end-to-end flow for the user's specific scenario.
        
        # 1. SETUP: Reset metrics and define all mocks and test data inside the 'It' block for perfect isolation.
        $script:MigrationContext.Metrics = @{ StartTime = Get-Date; VaultsProcessed = 0; VaultsSkipped = 0; VaultsFailed = 0; PrincipalsAnalyzed = 0; RoleAssignmentsGenerated = 0; WarningsGenerated = 0; ErrorsEncountered = 0; PermissionMappingDecisions = @(); UnmappedPermissions = @() }
        $outputFolder = "./test-output-integration"
        if (Test-Path $outputFolder) { Remove-Item -Recurse -Force $outputFolder }

        $mockVault = [PSCustomObject]@{ name = 'test-vault'; resourceGroup = 'test-rg'; subscriptionId = 'test-sub'; id = '/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/test-vault' }
        
        $mockPolicies = @(
            [PSCustomObject]@{
                ObjectId                  = 'principal-01'
                PermissionsToSecrets      = @("get", "list") # -> Needs "Key Vault Secrets User"
                PermissionsToKeys         = @("get", "list") # -> Has "Key Vault Crypto User"
                PermissionsToCertificates = @()
            }
        )

        # Mock all external dependencies. These mocks only exist for the duration of this 'It' block.
        Mock Get-VaultAccessPolicies { return $mockPolicies }
        Mock Get-ExistingRoleAssignments { return @( @{ RoleDefinitionName = "Key Vault Crypto User" } ) }
        Mock Get-ResolvedPrincipal { return [PSCustomObject]@{ PrincipalId = $PrincipalId; DisplayName = 'TestPrincipal'; PrincipalType = 'ServicePrincipal'; AppId = $null; UserPrincipalName = $null } }
        Mock Get-AzADServicePrincipal { return $null }
        Mock Get-AzADUser { return $null }

        # 2. EXECUTION (Phase 1): Run the analysis.
        $analysisResults = @(Invoke-VaultAnalysis -Vaults @($mockVault) -RoleMapping $script:mockRoleMapping)
        
        # 3. VERIFICATION (Phase 1): Check the in-memory analysis object.
        $analysisResults.Count | Should -Be 1
        $principals = $analysisResults[0].Principals
        $principals.Count | Should -Be 1

        # Verify the consolidated principal object
        $principal = $principals[0]
        $principal.RecommendedRoles | Should -Be @("Key Vault Crypto User", "Key Vault Secrets User")
        
        # Verify the 'AlreadyAssigned' status for each role
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Secrets User" }).AlreadyAssigned | Should -Be $false
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Crypto User" }).AlreadyAssigned | Should -Be $true

        # 4. EXECUTION (Phase 2): Run the report export.
        $reportPaths = Export-AnalysisReport -AnalysisResults $analysisResults -OutputFolder $outputFolder -RoleMapping $script:mockRoleMapping
        
        # 5. VERIFICATION (Phase 2): Check the final JSON report on disk.
        $jsonContent = Get-Content -Path $reportPaths.JsonPath | ConvertFrom-Json
        $reportedRoles = $jsonContent[0].Principals[0].RequiredRBACRoles
        
        ($reportedRoles | Where-Object { $_.name -eq "Key Vault Secrets User" }).AlreadyAssigned | Should -Be $false
        ($reportedRoles | Where-Object { $_.name -eq "Key Vault Crypto User" }).AlreadyAssigned | Should -Be $true

        # 6. TEARDOWN
        Remove-Item -Recurse -Force $outputFolder
    }

    It "Should detect role assignments inherited through group membership" {
        # SETUP: user-01 has no direct role assignment but belongs to group-A which has 'Key Vault Crypto User'
        $script:MigrationContext.Metrics = @{ StartTime = Get-Date; VaultsProcessed = 0; VaultsSkipped = 0; VaultsFailed = 0; PrincipalsAnalyzed = 0; RoleAssignmentsGenerated = 0; WarningsGenerated = 0; ErrorsEncountered = 0; PermissionMappingDecisions = @(); UnmappedPermissions = @() }
        $script:MigrationContext.GroupMembershipCache = @{ 'principal-01' = @('group-A') }
        $outputFolder = "./test-output-group"
        if (Test-Path $outputFolder) { Remove-Item -Recurse -Force $outputFolder }

        $mockVault = [PSCustomObject]@{ name = 'group-test-vault'; resourceGroup = 'test-rg'; subscriptionId = 'test-sub'; id = '/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/group-test-vault' }

        $mockPolicies = @(
            [PSCustomObject]@{
                ObjectId                  = 'principal-01'
                PermissionsToSecrets      = @("get", "list") # -> Needs "Key Vault Secrets User"
                PermissionsToKeys         = @("get", "list") # -> Needs "Key Vault Crypto User" (has via group)
                PermissionsToCertificates = @()
            }
        )

        Mock Get-VaultAccessPolicies { return $mockPolicies }
        # Return group-inherited assignment for Crypto User, no direct assignment for Secrets User
        Mock Get-ExistingRoleAssignments {
            return @(
                @{
                    RoleDefinitionName = "Key Vault Crypto User"
                    AssignmentType     = "GroupInherited"
                    Source             = "group-A"
                }
            )
        }
        Mock Get-ResolvedPrincipal { return [PSCustomObject]@{ PrincipalId = $PrincipalId; DisplayName = 'TestUser'; PrincipalType = 'User'; AppId = $null; UserPrincipalName = 'testuser@test.com' } }
        Mock Get-AzADServicePrincipal { return $null }
        Mock Get-AzADUser { return $null }

        # EXECUTION
        $analysisResults = @(Invoke-VaultAnalysis -Vaults @($mockVault) -RoleMapping $script:mockRoleMapping)

        # VERIFICATION
        $analysisResults.Count | Should -Be 1
        $principal = $analysisResults[0].Principals[0]
        $principal.RecommendedRoles | Should -Be @("Key Vault Crypto User", "Key Vault Secrets User")

        # Crypto User should be marked as already assigned (via group)
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Crypto User" }).AlreadyAssigned | Should -Be $true
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Crypto User" }).AssignmentSource | Should -BeLike 'GroupInherited*'
        # Secrets User should NOT be assigned
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Secrets User" }).AlreadyAssigned | Should -Be $false
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Secrets User" }).AssignmentSource | Should -BeNullOrEmpty
        # Not all assignments exist since Secrets User is missing
        $principal.AllAssignmentsExist | Should -Be $false
    }

    It "Should show AlreadyAssigned=false when user has no direct or group assignment" {
        $script:MigrationContext.Metrics = @{ StartTime = Get-Date; VaultsProcessed = 0; VaultsSkipped = 0; VaultsFailed = 0; PrincipalsAnalyzed = 0; RoleAssignmentsGenerated = 0; WarningsGenerated = 0; ErrorsEncountered = 0; PermissionMappingDecisions = @(); UnmappedPermissions = @() }
        $script:MigrationContext.GroupMembershipCache = @{ 'user-02' = @('group-B') }

        $mockVault = [PSCustomObject]@{ name = 'no-assign-vault'; resourceGroup = 'test-rg'; subscriptionId = 'test-sub'; id = '/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/no-assign-vault' }

        $mockPolicies = @(
            [PSCustomObject]@{
                ObjectId                  = 'user-02'
                PermissionsToSecrets      = @("get", "list")
                PermissionsToKeys         = @()
                PermissionsToCertificates = @()
            }
        )

        Mock Get-VaultAccessPolicies { return $mockPolicies }
        Mock Get-ExistingRoleAssignments { return @() }
        Mock Get-ResolvedPrincipal { return [PSCustomObject]@{ PrincipalId = $PrincipalId; DisplayName = 'TestUser2'; PrincipalType = 'User'; AppId = $null; UserPrincipalName = 'testuser2@test.com' } }
        Mock Get-AzADServicePrincipal { return $null }
        Mock Get-AzADUser { return $null }

        $analysisResults = @(Invoke-VaultAnalysis -Vaults @($mockVault) -RoleMapping $script:mockRoleMapping)

        $principal = $analysisResults[0].Principals[0]
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Secrets User" }).AlreadyAssigned | Should -Be $false
        $principal.AllAssignmentsExist | Should -Be $false
    }

    It "Should show AllAssignmentsExist=true when all roles covered by group" {
        $script:MigrationContext.Metrics = @{ StartTime = Get-Date; VaultsProcessed = 0; VaultsSkipped = 0; VaultsFailed = 0; PrincipalsAnalyzed = 0; RoleAssignmentsGenerated = 0; WarningsGenerated = 0; ErrorsEncountered = 0; PermissionMappingDecisions = @(); UnmappedPermissions = @() }
        $script:MigrationContext.GroupMembershipCache = @{ 'user-03' = @('group-C') }

        $mockVault = [PSCustomObject]@{ name = 'all-group-vault'; resourceGroup = 'test-rg'; subscriptionId = 'test-sub'; id = '/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/all-group-vault' }

        $mockPolicies = @(
            [PSCustomObject]@{
                ObjectId                  = 'user-03'
                PermissionsToSecrets      = @("get", "list")
                PermissionsToKeys         = @()
                PermissionsToCertificates = @()
            }
        )

        Mock Get-VaultAccessPolicies { return $mockPolicies }
        Mock Get-ExistingRoleAssignments {
            return @(
                @{
                    RoleDefinitionName = "Key Vault Secrets User"
                    AssignmentType     = "GroupInherited"
                    Source             = "group-C"
                }
            )
        }
        Mock Get-ResolvedPrincipal { return [PSCustomObject]@{ PrincipalId = $PrincipalId; DisplayName = 'TestUser3'; PrincipalType = 'User'; AppId = $null; UserPrincipalName = 'testuser3@test.com' } }
        Mock Get-AzADServicePrincipal { return $null }
        Mock Get-AzADUser { return $null }

        $analysisResults = @(Invoke-VaultAnalysis -Vaults @($mockVault) -RoleMapping $script:mockRoleMapping)

        $principal = $analysisResults[0].Principals[0]
        ($principal.RolesWithStatus | Where-Object { $_.RoleName -eq "Key Vault Secrets User" }).AlreadyAssigned | Should -Be $true
        $principal.AllAssignmentsExist | Should -Be $true
    }
}
# SIG # Begin signature block
# MIIpAgYJKoZIhvcNAQcCoIIo8zCCKO8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBaFaVmQ3l/Tst2
# VfJe43pBKOjmL2PfEEPMZVzW05mut6CCDdIwgga8MIIEpKADAgECAhMzAAAArfwg
# b4sisLFgAAAAAACtMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMzAxBgNVBAMTKkF6dXJlIFJTQSBQ
# dWJsaWMgU2VydmljZXMgQ29kZSBTaWduaW5nIFBDQTAeFw0yNTA2MTkxODU1NTZa
# Fw0yNjA2MTcxODU1NTZaMIGCMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSwwKgYDVQQDEyNBenVyZSBQdWJsaWMgU2VydmljZXMgUlNBIENvZGUg
# U2lnbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAImX7ktXR4nHu/z+
# Qlmg6WqeAX2lXZwwA27jX6s4Fwe/ut783uedwijPYIysN9s36cNmShOC25McggS7
# +uadZMzf1Y5cu2ZBcDv/x3MS+1T1/092YcKanWut0hb+us0w0Y8AL1H3nUDTCqKt
# RHmNrhE8QoV8S09xCwK3C8z1GyIzJEpzYcIQResT6XkUI/JanHIX18z4b+UCSm6K
# bDlWkg92Bmc+UwMPOUJq7BBsZFV6Es4Q5DLjy2JVb2/6Q1ukhovBlUkC7D/DCEvN
# yyDPqHa8CBu5G94+IO3WBde5jT5hBoXKy8BfSy+XvqiutsBQgqVuFc0lMpk2IUlq
# afKVlbG2mNpUT69DTIUpdxajN8cPvwRwOWjqq4QinSXNAC2UdbmVuJ2EsmD1Uvzy
# 1dJPwXJzoD8IuMVT6e31LFcdfaY6fEUlIKrUvh9ow80zMAtlUBHCG0ayShRAz1dK
# W0ttY11wT2uFcZpzyFK2kOKn2uFOeAfGPEYCZx69kiDxXhSGuQIDAQABo4IByDCC
# AcQwDgYDVR0PAQH/BAQDAgeAMB8GA1UdJQQYMBYGCCsGAQUFBwMDBgorBgEEAYI3
# WwEBMB0GA1UdDgQWBBRAhLEl/+uJfjQyWgp+AsIrZk2UTDBUBgNVHREETTBLpEkw
# RzEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MRYwFAYDVQQFEw00Njk5ODErNTA1MzAyMB8GA1UdIwQYMBaAFPEvupEWfN59Uicx
# 9Xr71VhZaTo9MG8GA1UdHwRoMGYwZKBioGCGXmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL0F6dXJlJTIwUlNBJTIwUHVibGljJTIwU2VydmljZXMl
# MjBDb2RlJTIwU2lnbmluZyUyMFBDQS5jcmwwfAYIKwYBBQUHAQEEcDBuMGwGCCsG
# AQUFBzAChmBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL0F6
# dXJlJTIwUlNBJTIwUHVibGljJTIwU2VydmljZXMlMjBDb2RlJTIwU2lnbmluZyUy
# MFBDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOCAgEAIpoW76rb
# za/ZUlt5vS0Ppx28/SGUHHkCWxqUIf2n6QEiGh3seVfQzvC3X82AO7bJTa4dC3ub
# jmYsoDm87TO5mkLQsJtBYaQOf8F52fEzGTRAZEO3h8IOKFsTrqPAL2hK576/Y2y0
# rYu5guye+z8M+gVtKjjW7J9qmqUpPvmScJoV8H+Lqa3YSWnvvcBcgtW44IU6sSKn
# iD6xVCXXPeUvb5wlXjAdexPCmbizHR2KVDpw9G6w/bNuXZeRXfNgKq6v/vqtdvR4
# CqC0DOyT1IiTY4oeY1FcTgo3a0Cgl2iCHVxDqo+JZJ6el5q/PMvv9fDKs10/z/zi
# eziKqpVA8DJzwxmMfcSoX7L8olU5dvMYGhCO7s+1qPjgHfxyDgoIW4VTVCSmKN3c
# IwzLplGIyh6FZEqxeycsMyJ3saWhuQmmy8X/k9YkALkyS3AGtkACjPltlxlSaGRJ
# Nq78YrhZ1VrH4aYNgBj8tqckBcrhLkKh14omG2nsHYTqp5V3xC2BUSkp1nbhazhw
# H/ErmJOQM71n6xXRjwZLHeRU4mUdaq0LXwzQcRmRsnAp4iVuT/yyBwQc0ZuWCqwI
# OwInfiX0HxxE75ZWw7ALhMgvoll3UkZBNDceuSlYiLVWDQeSq2SPzpex1SKtSAyJ
# JKVMTQwymL3WdXqJUREKCA8DVD16Ara2kFcwggcOMIIE9qADAgECAhMzAAAAArLE
# k4h4WezTAAAAAAACMA0GCSqGSIb3DQEBDAUAMFsxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLDAqBgNVBAMTI01pY3Jvc29mdCBS
# U0EgU2VydmljZXMgUm9vdCBDQSAyMDIxMB4XDTIxMDkwMjE3NDExOVoXDTM2MDkw
# MjE3NTExOVowYjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEzMDEGA1UEAxMqQXp1cmUgUlNBIFB1YmxpYyBTZXJ2aWNlcyBDb2Rl
# IFNpZ25pbmcgUENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApd39
# LL3WcWCx5Uk4WB5GFXGtxqHKnVgZI3QWk4SARERVvc0P9CAjsjTJ3tcbo4TxWiav
# kUzG8rxO8ngtzos/0EPPYZJrUzQuXMcpfvnv/bgLRmd3NxwDWpCLTT4GaY6vimWb
# FHNMW/g+F3DzIE8X0YO8KWpXwBK+9uK1+NoPt1U84Utvs3t++3+paiAY3l6KzQVc
# KpUl2Y9llpfaHiIbSi2wCF+rzK9KUnRjA7iLkYN4tDBOww3VF/ZQAdAoJRiQWwtJ
# DSaptpFsNmEH7akUv+r9zZrqGUcudqljJ/CU0VeQOHAAVYTN/AUcRHahHjZRrJ83
# 22w7+na1aTfcKucd2d0kOshnqhDcP42CiX9NHwECBcIgzqx7piUsNOzFHCH1BQOr
# spWErLnwcYolSrCAhbQTty+XNSXQd+395uEAtnIUOSGh/0LkKrhz/jzpcuNCrSdu
# 4qwU2FBTTK8AFHd6iHDrcqmzrpSZrjygTQmao7GbOs++shNhyycHIqV6Ief7jKr5
# Oz8qu2qRDBBy6KQw+tnBcK2xiTExTJSfyCvyh7DbZYN4hAQIAzULP1Nx0lp2ytOg
# qpdBrZsCf8AAEBjKiA88418a+iNMjcOVgPjZ60xr+A95klq9f7PvHx3/h5gGcn1Y
# VKL2rS/68s4Zzd/IzYpC2rl5VsdfmtXJZzpsnfkCAwEAAaOCAcIwggG+MBAGCSsG
# AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTxL7qRFnzefVInMfV6+9VYWWk6PTBUBgNV
# HSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQM
# HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
# IwQYMBaAFA4MsWRpvS2x1WsmpkfqVk6Aw+2KMGYGA1UdHwRfMF0wW6BZoFeGVWh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFJT
# QSUyMFNlcnZpY2VzJTIwUm9vdCUyMENBJTIwMjAyMS5jcmwwcwYIKwYBBQUHAQEE
# ZzBlMGMGCCsGAQUFBzAChldodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NlcnRzL01pY3Jvc29mdCUyMFJTQSUyMFNlcnZpY2VzJTIwUm9vdCUyMENBJTIw
# MjAyMS5jcnQwDQYJKoZIhvcNAQEMBQADggIBAGKfs8wGdeOcgnTH74ue50sNZadn
# x1mYnXgO5l9Syz92hROEsAzhyusdpNsmi6VRQQs13YCc6lf9ni16dQxPeyNgh09j
# Il8hhY9Gp8jo1vP4lUrtFG+faeXkQQwi5ETpQpL1kYFt/TZruxvTgT/sE382GGua
# 1L+1UWN9GutWH3NeS7jmupa4LBRPODcSrEpDw4Zu2MFC2r9LJv9yWbkEeyiHdeEy
# dv1Uu/cbV241/3QUvn+jzxdngvXyfHWV+TLaeWVjgcgDw8rwBquoBbiIpJMDcQaq
# fyz/jta1ApP6oQPZhtldU5gv4vu9AMKcVvCGADHq5y4zPsB7WuqJuDcCOwLtTkze
# gD++oAcMoMDeZ0zkPov9kR1CBobbQeFQ5JD4KJAPdPIdKJUJ9Uy5O/zciIoKeLct
# b/be0cLa1s3nuuWExyjKMiL4hV3uPuzjUwUFoPAmuZ9ef9gz6VH/lCq87vNYBtuv
# 9dTnfW/eOv+MGKWauq3pT9vvLxNfID2djFX2JIwWZxvIiLbGB1wAeHGeldy9y/IV
# YRPpiImLJ5IlnDAm/yDBeIEX5mHQgcCuXopWxsB2wBO4/VMIQGk/KddmaS+IgRY+
# 2e/fXlmNMLuc+g6lKc5Vo7vBnO2s559m6cjl8HHDuYbWjKhGcANlrCIWxWj0n9wO
# 7XkStEJ8NBGHBKIFMYIahjCCGoICAQEweTBiMQswCQYDVQQGEwJVUzEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTMwMQYDVQQDEypBenVyZSBSU0EgUHVi
# bGljIFNlcnZpY2VzIENvZGUgU2lnbmluZyBQQ0ECEzMAAACt/CBviyKwsWAAAAAA
# AK0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIN4X
# TB0K0dPKLeQ+Nww5YGxENbkSMi+86OasmuK3ANVzMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggGAH7CpIBYSj0QvpyiSZNRaqAvtfvHo0vODW/NF
# zuk+guRUwG6daA24ACWtZzz7TZZVsKxY0DDUs/fj3AFwuCrhpfkgWcvBw7muxFIX
# ficWU4ytYFyneFGxg+zA5Rdco+4kdKfbVi+SAqKNUr7K049sDzkJ7LO59Ro1jV6Q
# 3ZEdqCCmdci548XblaHsM0k2isbUrHcuom5HaRbAYKs6O62eRL9vhX1wiVKdSXUW
# tezbHbms9omFRba4+6qKiGUNQ2aK0wdSTWxtAdUGH55n33Qx8OXKLgHaGnWmoShB
# encadKH26MFKXu+F4/20+6Ua0kuIPrFA6TvgBOgFBgY2xSGg4jtxhMRAGbzb3k8h
# B54zchHYTdHqNuB0IMhXP9IPDUg8vztxisLAhLTZbqDyn/tu2NAdihrpf4MVlEkf
# Q6AXVK7JBMgf1+71zTegugeUXESiWcy8xztYnoA+sgaTqM7miNvOha0TOdbMcISm
# f2mTPVP53Q8u6MqAmsWCKjmcISLooYIXrTCCF6kGCisGAQQBgjcDAwExgheZMIIX
# lQYJKoZIhvcNAQcCoIIXhjCCF4ICAQMxDzANBglghkgBZQMEAgEFADCCAVoGCyqG
# SIb3DQEJEAEEoIIBSQSCAUUwggFBAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUD
# BAIBBQAEIGLCnJd0ijGrRvW7oQ4e2RSBkupsvLrFFneXwRMZKd/OAgZpmKpv7QoY
# EzIwMjYwMzA1MTg0MjU4LjQzMlowBIACAfSggdmkgdYwgdMxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OjZGMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIR+zCCBygwggUQoAMCAQICEzMAAAIcCVUV18NZB9EAAQAAAhwwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjUw
# ODE0MTg0ODMxWhcNMjYxMTEzMTg0ODMxWjCB0zELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046NkYxQS0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjDTEQBRoUjLIshd4XN4jw
# grIE43a7QOvTYhITmn0bkJRd+cW7ZLQTWBYIy8NamilfqVHGOaCepovcG2daUFVO
# jzFQ1Fm7beJ7hgEwAkHtS3qaeqcdXC8MnEY7hMPdKesJ37KDfkH1AV6Orejj44HK
# 9ePKdrKlnK6RxBouwpC+jETwSUcfvNw5cQlaZTeudfNpb9LhIfc4+GhRtNNzLqdS
# ArHmlFaJDbhQQ8tjNzEYmOqOTP4aIJYY8UcMx1bzqVpa+YKyWi5A+w3Z4GTx3Elw
# RmZbiXqnhO2Ghdx97EQD1h1hozPXRoyFk2l2w1oO0NBQwMQLeTUPUzLr0xdI+VSY
# P3EXIOWReJVrsEISnddxW2pODMcbCvbwkPqgTvMQ9h65k6K4IFdNlKj/CTe1sOWw
# RJsg9XqKdiqvPGIxiqXF8J3MLcKKaH381P8uT39pT4jLJz1vc5pPR1nzCAtpUMIY
# QtEyurIiZ0Ue/Qy51y3Nb+Q+xXclr25+kpa6MSI3cJb/9fyEVr2PkiY15DNwyK3c
# yhJqgbCduJklfUjKJsimGWpxxcWTihNNI5AGwBTDxTSDA6czlQkPyYFQF3rk2no0
# GTHZy+IngjfgbJcUJbLLkW3VCwFjJV8Abco6EJ88dB/yVDMm8uvnthbRsP/FWzgC
# DiBNLopk3IUR9f2MV1GWvQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFFreY4LMHy7v
# Om8OHwwYpVgsKTtkMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCSVvrD915qJ3cG
# 6NAK1YUF7Sf2mTJHL7LJYSDvSIPCgnm7R7Q77gZ6s3N1lvXNM+wcnwQYzKjUrvK0
# vbX6mZ0UxOXX08Lw4nljan5cpRDLZ0P6GCBEyYmANCyBs4LEdh476ODi36+DrXBS
# ui/PMuQffPQ8lde+g24GP0t1r0KI0x3rTjnUq5t730CtJ/pkyPe3SnisVuBJrMOz
# 7xMn7woDkZVpiM8eP2uUy4jdaOiERz1qmdDqEyMxyTeOUdkjCW5Vh5RATSqOYCl8
# y1MATNsxR1jywtO6cvUaRsNJ4qf07uWUEac23IzW4z0x2/VXJaHTP8iuJAoiOe2q
# obKgXQe8Mc4VkLJQME8t+XKK7tjXND+w+i6exv3poF9B2reHcs6fq36b0Sc3P8bo
# zPNa+kmTpiBMdMip5A38X9emI+9t96Teer89hsvdq76QF9FQeIIVdK+3qWivQcLr
# bq9SbP1k087HARYu5xyibGzLcnBYfv2+wz/sBGqgbmHp3o1qF9o65E/hcj3G10fc
# 9r80IvJCPEpfIvHPBDON12RfYSlMmeXKm6E+YR15rn1TPYTfTcvHJdKcoG8awCfJ
# ZgB+d6OvdgCIv1is3aXZ2fX3xGkDgMKb1C1liLALSrZ+5S+6Lfg988hRkHJ/vAe6
# 5a7nSFj1YvHWQ4wjzHKjsAjpNo2ucjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKb
# SZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIy
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXI
# yjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjo
# YH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1y
# aa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v
# 3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pG
# ve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viS
# kR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYr
# bqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlM
# jgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSL
# W6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AF
# emzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIu
# rQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIE
# FgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
# 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
# MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2
# LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv
# 6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZn
# OlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1
# bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4
# rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU
# 6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDF
# NLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/
# HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdU
# CbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKi
# excdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTm
# dHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZq
# ELQdVTNYs6FwZvKhggNWMIICPgIBATCCAQGhgdmkgdYwgdMxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OjZGMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBaZOIDTW7mbGr+dXGJEksw6yRUZ6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUA
# AgUA7VRLhzAiGA8yMDI2MDMwNTE4MzU1MVoYDzIwMjYwMzA2MTgzNTUxWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDtVEuHAgEAMAcCAQACAh1oMAcCAQACAhSXMAoC
# BQDtVZ0HAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAAo64yRdQOhyVP/m
# EuncK99qpbBR6M4PdVYme5bqa1UYCzUD5TWmiyB/HxQNGzlD/vlMcoeUx8G12eQs
# WtPYFa0OyRtkEuxgdST8rm3L34YwLdYHMIOI4cgYr5F8WtXtFuQOg+6S/DZDFBEh
# WzvCSjZMF/73nJpNl9LVBTYL0tCNkZ5oh5C9tHPaQU8BmEt25+392vgS2haYqyH2
# xUITB3LTIFXyF36b+9u30HGRQS+swhl3Hx6j1P3f1D6MDoz/4IkQEUipubOVtwRR
# 3BF8vICCFbMBNBOzU17eHn0lwpu1dJoJoKWs94x0mTIq9SwQ8XfqiKkE6bF8c8SA
# R76wkmwxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAhwJVRXXw1kH0QABAAACHDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBrltdbTMKEVY4X
# eVyX7DUhKOm5bNIPXkO7EUVVa3vONDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIKAgaSY2F2jv4oTt1aEj4TYK3HZEtahi+8mh0IhyIcdoMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIcCVUV18NZB9EAAQAAAhww
# IgQgM5GGKP649yhA7So2l5vdcELHB9st8kPLpQ6HT+nVJwYwDQYJKoZIhvcNAQEL
# BQAEggIAawrAuO9+MyWmHTcB1KnfAIrXkttx6tjux8+n3yn8/NggiqKrYYFCuq0g
# Zz85N4pD+WRCsb0HJtopkP+MWP8eWC/0FL5Y3JuY6kWdX10VKbCLCYBvi39bbjaH
# bRT64XtDo9CDAxK4979bwzh2YXQrdEbzyNdO7HQV5p3w4c7+2h2LPYPf28YqeizL
# mzqw4RztAtjbRoGjB3q0TdSWGlfMFpdTkBpcekJhEwa1jIKmyllINR2meRPD/4bE
# nWopegx9cX38ekYH8OWxLjZiGZtL0ZAvWQFA6RiI8hDxoP+VXPxJreeRZJDAapvd
# O5jLa//1/a1N61ir9gYQiMJrf2V5xz+urqneCF36XuI1636nJBtY4oMPTmlOoTuh
# 1YN3s1tOgNUHp4PdudmRQjxMnvwFdvUJnUZ5Pn0D7KRTzhSiANAAJqHYYuHag8tz
# YHiC8IbH8xxbQI88xK97AV1JKe/HnG/srnYJiygwRfxrAFj+N2Nve86/ACwPmLRG
# O5W1sfcnWkcsL8qHBuUXw35Lbc5+p69p8QL2i5VpSVmmvIjv/DteuBTo2TBOdcDz
# Hd88zdw3v3x0iNReVRTuPOh2C7LqDeVn6DxujIfPUrRH0ILaNSDh4DirqPH3lHts
# D7qEYpodigL/n5xSB/VWHuYCNywPX9kSC53yBhw0wohfug0KOUg=
# SIG # End signature block
