#Requires -Modules Pester

Describe "Invoke-KvRbacApply.ps1" {

    BeforeAll {
        # Dot-source the necessary scripts
        . "$PSScriptRoot/../Common.ps1"
        . "$PSScriptRoot/../Invoke-KvRbacAnalysis.ps1"
        . "$PSScriptRoot/../Invoke-KvRbacApply.ps1"

        # Initialize logging to ensure the output directory exists
        Initialize-AuditLogging

        # Create a mock role mapping to avoid file I/O
        $script:mockRoleMapping = @{
            roleDefinitions = @{
                "Key Vault Secrets User" = @{
                    id = "4633458b-17de-408a-b874-0445c86b69e6"
                }
            }
        }
    }

    Context "Execution Modes" {
        BeforeEach {
            # Create a temporary analysis file for each test
            $mockAnalysis = @(
                @{
                    VaultName        = "test-vault-1"
                    ResourceGroup    = "rg-test"
                    SubscriptionId   = "sub-id-test"
                    Status           = "Analyzed"
                    Principals       = @(
                        @{
                            PrincipalId      = "user-guid-1"
                            AssignmentStatus = "Needed"
                            RequiredRBACRoles = @(
                                @{
                                    name = "Key Vault Secrets User"
                                    id   = "4633458b-17de-408a-b874-0445c86b69e6"
                                    AlreadyAssigned = $false
                                }
                            )
                        }
                    )
                }
            ) | ConvertTo-Json -Depth 5
            $script:tempJsonPath = (New-TemporaryFile).FullName
            Set-Content -Path $script:tempJsonPath -Value $mockAnalysis
        }

        AfterEach {
            # Clean up the temporary file
            Remove-Item -Path $script:tempJsonPath -ErrorAction SilentlyContinue
        }

        It "Should run in DRY RUN mode and not apply changes" {
            # Mock dependencies for this specific test case
            Mock Get-RoleMapping { return $script:mockRoleMapping } -Verifiable
            Mock New-AzRoleAssignment { throw "New-AzRoleAssignment should not be called in dry run mode" } -Verifiable

            # Set the parameters as variables in the current scope and then call the function
            $InputJson = $script:tempJsonPath
            $Apply = $false
            Invoke-KvRbacApply

            Should -Not -Invoke -Command 'New-AzRoleAssignment'
        }

        It "Should run in APPLY mode and call New-AzRoleAssignment" {
            # Mock dependencies for this specific test case
            Mock Get-RoleMapping { return $script:mockRoleMapping } -Verifiable
            Mock Get-AzRoleAssignment { return $null } -Verifiable
            Mock New-AzRoleAssignment { } -Verifiable
            Mock Get-UserChoice { return 'Yes' } -Verifiable

            # Set the parameters as variables in the current scope and then call the function
            $InputJson = $script:tempJsonPath
            $Apply = $true
            Invoke-KvRbacApply

            Should -Invoke -Command 'New-AzRoleAssignment' -Exactly 1 -ParameterFilter {
                $ObjectId -eq 'user-guid-1' -and
                $RoleDefinitionId -eq '4633458b-17de-408a-b874-0445c86b69e6' -and
                $Scope -eq '/subscriptions/sub-id-test/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/test-vault-1'
            }
        }
        It "Should display subscription-level RBAC summary in dry-run mode" {
            Mock Write-Host {} -Verifiable
            $InputJson = $script:tempJsonPath
            $Apply = $false
            Invoke-KvRbacApply
            Should -Invoke -Command 'Write-Host' -ParameterFilter { $Object -eq "Subscription: sub-id-test" -and $ForegroundColor -eq 'Cyan' }
            Should -Invoke -Command 'Write-Host' -ParameterFilter { $Object -match "Current RBAC assignments in subscription: \d+" }
            Should -Invoke -Command 'Write-Host' -ParameterFilter { $Object -match "Projected total after assignments: \d+" }
        }
    }
}
# SIG # Begin signature block
# MIIpAQYJKoZIhvcNAQcCoIIo8jCCKO4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWForK3XrBapxs
# 9bCAgtGW405dgEyw/f2gj8AOnbvEMaCCDdIwgga8MIIEpKADAgECAhMzAAAArfwg
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
# 7XkStEJ8NBGHBKIFMYIahTCCGoECAQEweTBiMQswCQYDVQQGEwJVUzEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTMwMQYDVQQDEypBenVyZSBSU0EgUHVi
# bGljIFNlcnZpY2VzIENvZGUgU2lnbmluZyBQQ0ECEzMAAACt/CBviyKwsWAAAAAA
# AK0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGr1
# zKwK8CTJc6/yzIcFsp85Si/APa37sZj713K/sO+7MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggGAe3K8Wbvr6Ez5+npj95Px+Fp5aLTivSgMGeF7
# NTBxLa00Nq/3Y+e/5YfLJmQ1uBgoD63a0snVNiRLREmv2GSy5pUajx++O5X7uvou
# dX3p/Cw7ZVDbpxEiRXWrgj7eRx7s8N5GF1LbsHEjj4GIxTcruUINR4q+WsZceYKC
# /V7tfr/J2zDfLqEZMaBBpaw3P+h4gheNuJFsedP5+Qci4DiL3MwivZAsEZORvGiC
# 1no/I3KNj4/qmVdDYmVmdpYtG8ys7F+uzcWkp4ryuIQvttrdqpKt7RzyDpYZ2BEd
# RPJh1PuKaXX6RCfc19TmABkFMww3ZCLbIvj7yEsvuFDjEDBhoMrjAKqEIHDvnDT8
# VRvYdeC34Rp8spdejPwlPVrqpXdyZfKtqUZl//YqBSPocrOVXRHXrjEawVZ0pjSN
# GcsV8qx3vEAFgKBxxtii10Y/cCfvRNDArOaN+WURp1xSmJZ6lReWLhw3or5JcYVj
# 9uh5yHka/nGXwWnYrVml4XI2dpdaoYIXrDCCF6gGCisGAQQBgjcDAwExgheYMIIX
# lAYJKoZIhvcNAQcCoIIXhTCCF4ECAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqG
# SIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUD
# BAIBBQAEIHNNskqj1gt6Xt942cj5UfALQBUbBnyqYKsj4j4P+bMXAgZpc9F+0ycY
# EjIwMjYwMzA1MTg0MjU3LjgyWjAEgAIB9KCB2aSB1jCB0zELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# NEMxQS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WgghH7MIIHKDCCBRCgAwIBAgITMwAAAhgl2ZIF4ufl5AABAAACGDANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTA4
# MTQxODQ4MjVaFw0yNjExMTMxODQ4MjVaMIHTMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo0QzFBLTA1
# RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALHc6OrrkCagH8S57xAXyL4+
# pJyvqem5zFxBWf0IzzhcsJXIw38yPA4NZ8w5cZu/6am741ocr2syphcjuqmz8ApX
# 0ZyOe4eTgosYKTjghiSUCGUk4jILotwfAz4hbST3H80bdxbJ8Yy18ASIxoJ4xn5k
# Je83owNVqGC/6gZkIcPxQxU1nm8X6OJtEQgjsX9qsI99Wjo3NmmFHj7SzFx7Fyjx
# R9LaeUiiBf/bScUUoNDWBL0KlYpY3vGkJD3d6swLsdjHORzEiuDTE7VVQmAFg1Ge
# KfuogyPbeQTQgSLH+aKBTVFrcQqp6RWIi2JB3xX8YVVAWfCxhsWLAN+rJw+ubNh3
# +LfOpNHvFnpR/7rH4WKjjN89smiPK4NPOt9SJMKlM8kKBD6jLB4AXptcaZjhkiFJ
# 1b07AL/pZhAi9kaq3DmZWWsfCtGooo/IelJFgTdiAP4pGnJE0hlUQUJllmbixVlf
# 0+Mbjc7HAtF+8aOH3rYKbKmhANI2P0Hr5E7y7+DpTTfXji/CzYe1ZtEeuT+6Gmzk
# A6rVBQMAoI4DydIlf40AmjAHDt0mKRucEgGIiZJOFy4zUpTcVNiHY7NbDkYZe7Oy
# wuoTm+21QB1cDje+BsXxTYhCAOgX7nQDY6UCdJ1HP6aRF6U+KYAwR7GLVfDsikoy
# rCMTnRUe3yCSIw3PA71JAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUJC6hxFw6G2O3
# R7qEAgWuLF+2i9EwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAJ5I0YY8D4HaCKb7
# eGIqE/49C1rgcRdwEQSlwxDYIK2irwtKET8G4wJrF5zxJrbqOTA/LifV8PXmK8aq
# pCuAxfbJ2TKxzH6KMQmvvtYqy8/GKKMwuLXIvmuDd+0m5HtabdcbPambb5D4GRlp
# +QXMFX5gMEmSx4tgrmdOmNP1/renzQZ62zFaLzWg1+Fj3ciPRhM8XyIIA7HJNiKa
# OFVy/wK3M+6dhe2xGRkbssY4DAvsKApAyWh/8pP8HGaQLIsXuDznTdA1umW9+Ttw
# 4N/muqawDTHN1iHb3yg5e+T9GqnEG0AEe29H+IB+DTJFHLdFpuBjeSobBNWCu1f8
# AKgypiuI8d8y892vB7MWvRwdxsorZZgubA4TpeEExjeZEYuqAqFeISvpCBYJ5Fox
# 4UkTaJs9+kJ2wkhvwRyxJthkVPbt/yOM1HfRNQAveyCRBn8G/tDVm90BHK5MqXRn
# VsJdCxDm4a0EfQdVe/nnXMjZrF9KdgV9KxaXdT5FyUm8X/CHBIsP25DYGoGRPlZQ
# 7cV3q7i3aOZN5Rjr+6z2LjhGqGWMQ72baRz/T9+sJluCDY0ejSJ59lDPpKz/8Xi5
# 0WwwZJvUbJZ6A4Va2pYigx+tgcYXIC/bYkYDh5XCNMKr1Vi3b/MlvK8ZGsDpYQka
# k9xChAlvJLVAD8DWwVC5E/qFnLwXMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCA1YwggI+AgEBMIIBAaGB2aSB1jCB0zELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# NEMxQS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WiIwoBATAHBgUrDgMCGgMVAJ1rRq11orjRPEKyn5uArRq+e8/poIGDMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQAC
# BQDtU7H0MCIYDzIwMjYwMzA1MDc0MDM2WhgPMjAyNjAzMDYwNzQwMzZaMHQwOgYK
# KwYBBAGEWQoEATEsMCowCgIFAO1TsfQCAQAwBwIBAAICFe0wBwIBAAICEr0wCgIF
# AO1VA3QCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEArZkAly2EGC/t3LMK
# QQN7c1sjWR8BtZRIBAjflcE1iZmkdwIBgo3WBjIBaiq8ILnXzM1YYzVmeF1n21Le
# s9/PtlCkZfX9n27ejRDe70ebfMZ9OXNhpP3MpWzsOLrBQgMePNPXwXQ4Je3Gw4Vv
# C/NFp4y8CMcIi7zlTLNEXHKAMZNRxCj06QAgds/xB4xi18UzrSMmQ5dgltltTdUq
# c8FEo2+k5Yxp+VqBnpBGF7a2FYzcBv5P3Exp2+9MDzNMcB6TM2etumSewW9iGEy9
# JwPO+GYMAbuZyrYCbkQpAhabWOOdRUVFRijJ8YciAQkBDIIGoyDh8VU+RbxN/30i
# ao1cSDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAACGCXZkgXi5+XkAAEAAAIYMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIFsGffA28dWLmxT6
# EvmiSNfxgtQlMlsIDLvBmtoIKuCYMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgmRPcibjkyLSMFmhEupcxiitV3EqM9cp0c2jlc8fXhWowgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAhgl2ZIF4ufl5AABAAACGDAi
# BCBQxOmM2A+Lbm3IercQXxRlBucbYAG7sMdtc4fp/i6jITANBgkqhkiG9w0BAQsF
# AASCAgCayBFjWj1m30RSsCH8yyH9fKBKcMFFGRNZn3xOeW+5TLCYKgUamAKi4nAM
# 6dMWMa3rsJhTB/wJEM5CDGsZKl+4okFZkk/LePKtkcnhDEkQmiES6UyQKYgcfp8s
# m7V3QKyTiC92peU/eU1i7E9kgQzCmAfjM0GPGSsuDUMB2E2FJMMikiXY0FPfJROE
# rApXV/2X0bLd+Dop05puXdbJo1MOYybjnDVZVkHrS3UM7KOmWuwMh2cQ5Iv9QX0B
# lDa+ATpA7FCMrQ3JsXFhmCOAn44RRgX+fPIvDikRSF1tMAC/BSJzn3K92oXp/AJ/
# ghzAUx3CMewvumY6zs9mIFk2DWDJuEf2XQaqRg1GixKc663HeDMqefi/jtsqNDHt
# dOET8/G+KGANafw92Yd2bbNQ1e1n1Tyy+hmFAHDLBRyVgF7Z5Lk10bF/egqK/o3S
# ud9gVwKzNYn/IzHMXPVW3NCJ+PaSIPX2Ft0IbavqVCZt9IJmtjtd/CeZuasN92oP
# 8nwE1aqVMKTfamJAlS8HXvHvQitmwrQrjpn9Ms5MR5Eguk8S9mhUtEdjNmlkyjK/
# rkBFOOB1dvdIR/FfTuuMF8maYdQwqTUBjH5w7iMcYZW5ewFPM9YeF71ZDI9L8TTn
# xbNm2o8/g4XveoclvN+MTAwUHsGTvXCUD7DiBRqGhD0+xw0yvA==
# SIG # End signature block
