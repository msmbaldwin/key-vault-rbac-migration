#Requires -Modules Pester

Describe "Switch-KeyVaultAuthModeToRBAC.ps1" {

    BeforeAll {
        # Dot-source the necessary scripts
        . "$PSScriptRoot/../Common.ps1"
        . "$PSScriptRoot/../Invoke-KvRbacAnalysis.ps1" # Contains Get-UserChoice
        . "$PSScriptRoot/../Switch-KeyVaultAuthModeToRBAC.ps1"

        # Initialize logging to ensure the output directory exists
        Initialize-AuditLogging
    }

    Context "Execution Modes" {
        $mockVault = $null
        BeforeEach {
            # Define a fresh mock vault for each test to ensure isolation
            $mockVault = [pscustomobject]@{
                VaultName             = "test-vault-1"
                ResourceGroupName     = "rg-test"
                Location              = "eastus"
                EnableRbacAuthorization = $false
                AccessPolicies        = @("policy1", "policy2")
            }
        }

        It "Should run in DRY RUN mode and not apply changes" {
            # Mock the necessary cmdlets to simulate a dry run
            Mock Get-KeyVaultsForAuthSwitch { return @($mockVault) } -Verifiable
            Mock Test-VaultAuthMode {
                return @{
                    VaultName           = "test-vault-1"
                    ResourceGroup       = "rg-test"
                    Location            = "eastus"
                    CurrentAuthMode     = "Access Policy"
                    IsRbacEnabled       = $false
                    AccessPolicyCount   = 2
                }
            } -Verifiable
            # CRITICAL: Ensure the cmdlet that makes changes is NOT called
            Mock Update-AzKeyVault { throw "Update-AzKeyVault should not be called in dry run mode" } -Verifiable

            # Set parameters and call the function
            $VaultName = "test-vault-1"
            $Apply = $false
            Switch-KeyVaultAuthModeToRBAC

            # Verify that the change-making cmdlet was not invoked
            Should -Not -Invoke -Command 'Update-AzKeyVault'
        }

        It "Should run in APPLY mode and call Update-AzKeyVault when approved" {
            # Mock the necessary cmdlets to simulate an apply run
            Mock Get-KeyVaultsForAuthSwitch { return @($mockVault) } -Verifiable
            Mock Test-VaultAuthMode {
                return @{
                    VaultName           = "test-vault-1"
                    ResourceGroup       = "rg-test"
                    Location            = "eastus"
                    CurrentAuthMode     = "Access Policy"
                    IsRbacEnabled       = $false
                    AccessPolicyCount   = 2
                }
            } -Verifiable
            # Mock user approving the change
            Mock Get-UserChoice { return 'Yes' } -Verifiable
            # Mock the update cmdlet to verify it's called
            Mock Update-AzKeyVault { } -Verifiable
            # Mock Get-AzKeyVault for verification after the update
            Mock Get-AzKeyVault {
                # Simulate the vault being updated
                $mockVault.EnableRbacAuthorization = $true
                return $mockVault
            } -Verifiable

            # Set parameters and call the function
            $VaultName = "test-vault-1"
            $Apply = $true
            Switch-KeyVaultAuthModeToRBAC

            # Verify that the change-making cmdlet was invoked with the correct parameters
            Should -Invoke -Command 'Update-AzKeyVault' -Exactly 1 -ParameterFilter {
                $VaultName -eq 'test-vault-1' -and
                $ResourceGroupName -eq 'rg-test' -and
                $EnableRbacAuthorization -eq $true
            }
        }

        It "Should SKIP vaults that are already in RBAC mode" {
            # Mock a vault that is already configured for RBAC
            $rbacVault = [pscustomobject]@{
                VaultName             = "rbac-vault"
                ResourceGroupName     = "rg-test"
                Location              = "eastus"
                EnableRbacAuthorization = $true
                AccessPolicies        = @()
            }

            Mock Get-KeyVaultsForAuthSwitch { return @($rbacVault) }
            Mock Test-VaultAuthMode {
                return @{
                    VaultName           = "rbac-vault"
                    ResourceGroup       = "rg-test"
                    Location            = "eastus"
                    CurrentAuthMode     = "RBAC"
                    IsRbacEnabled       = $true
                    AccessPolicyCount   = 0
                }
            }
            Mock Update-AzKeyVault { throw "Update-AzKeyVault should not be called for an RBAC-enabled vault" }

            # Set parameters and call the function
            $VaultName = "rbac-vault"
            $Apply = $true
            Switch-KeyVaultAuthModeToRBAC

            # Verify that no attempt was made to switch the vault
            Should -Not -Invoke -Command 'Update-AzKeyVault'
        }
    }
}
# SIG # Begin signature block
# MIIo2gYJKoZIhvcNAQcCoIIoyzCCKMcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDNDioAZvoUrw0
# g7uDCTIYHPiAHqvLa/X7rUxt4a9BhKCCDcMwggatMIIElaADAgECAhMzAAAArn9k
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHNu0dorAjLzrXCpRAc4ZM4D
# X9/Q1/CVztWQIul2VYrEMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAhGz8xNrarjKrX3iqq6tFfrEEL4IbekYwfr5tegl1xMm/YBMhPLa21TyF
# 1c3sDVjV7C///aFvpQlxupa0fNzSgdCwk/HZhdhHvGsVhzRhHpecDg6RIWN3gijt
# PmAN9p1Gfl4Gr+LCg+FD2sqWeVFd1JgAeBvkyvcm8TigilR5SAWIlfhR0eDcz2Pg
# NUTTVknzwKVGsU+Kp4J+n6PL5q4tO81+ZHpTftdFS1FLm6lUAEQsmfAk7d4lXrDI
# gfcCZqAu1uc3+8YtyxInQP7iW9iqqgWBHwCA+nLoFces8q1EcQF3/t6ruRsqukSs
# wBhMCnL2TtuZxjnOjffPuAPbwnn/AUi5tY62YGrX9DH6gHTEmy7htgXZ7yXAKzkl
# ONPp/dxEplNotjks1aUIFbmSj8Gu1iCFdMMjoSeKDlfjVsAOOlEeDlKFoW4YUWiy
# 31QSide/tQC7nNaBQnBbAYmImX3hAB2ufrvYzRKaVMA8J0PM5e0U1N+yOxETr7Qd
# 5wXNydZhoYIXlDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIX
# bTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIBvYdIaqGIAh
# Jl8j4F/PeODozTeLz3wAH3xzai7nLo+xAgZplMyDTAwYEzIwMjYwMzA1MTg0MjU5
# LjkwM1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo4OTAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgEC
# AhMzAAACDizLKH2VIHVjAAEAAAIOMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDMwM1oXDTI2MDQyMjE5NDMw
# M1owgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjo4OTAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKzm3uJG1e3SFt6j0wTvxliMijexpC5YwEVDtfiz2+ihhEAFM5/amhMdq3H4TCcF
# QYHVXa38TozCxA2Zjlekz/vloKtl3ECetX2jhO7mwF6ltt96Gys5ZEEgagkTo+1a
# h3UKsV6GbV2LPeNjcfyIWuHuep5+eJnVKdtxY8zI0jG4YXOlCIMD4TlhLfeZ4ypp
# fCF1vTUKW7KaH/cQq+SePh0ilBkRY48zePFtFUBg3kna06tiQlx0PHSXTZX81h3W
# qS9QGA/Gsq+KrmTPsToBs6J8INIwGByf9ftFDDrfRCTOqGnSQNTap6L9qj0gea65
# F5cSOeOmBOyvgBvfcgIAoxjE5B76fnCoRVwT05PKGZZklLkCdZROeKiTiaDA40FZ
# DUMs4YWRnBdPffgg8Kp3j/f8t38i2LOKy3JRliyaX8LhmF0Atu99jDO/fU7F/w1O
# ZXkgbFZ0eeTYeGHhufNMqiwRoOsm9AyJD6WiiMzt/luB3IEGdhAGbn7+ImzHDyTb
# bvMXaNs0j47Czwct5ka3y3q4nZ5WM0PUHRi2CwE/RywGWecj7j528thG3RwCrDo+
# JhLPkVJlxumLTF0Af+N3d3PIYCtvIu6jr0e6B8YQRv+wzTutyg/Wjdxnx5Yxvj4w
# gHx645vkNU8OcRwWLg0O6Rgz3WDUO3+oh6T6u0TzxVLxAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUhXFEaVIRkT7URIrpQYjtg1wQiNswHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAHXgvZMv4vw5cvGcZJqXaHfSZnsWwEWiiJiRRU5jTkX2mfA9NW58QMZY
# Sk03LY59pQdYg6hD/3+uPA7SFLZKkHQHMwCTaDLP3Y0ZY6lZukF0y+utEOmJZmL+
# 4tLhkZ1Gfc/YNxxiaWQ0/69pEBe+e/6anbsqAjv2Yn2EbIJBu+0wiORtiguoruwX
# tZqGf2suNfXLlAkviW8TLdCYD0pEGPnpwS/+UC/MOrt5KKpGr+kLKrJzy7OZDxJ4
# pbJa7oONQD2+LzhCyYuOo8YKcfhw/KD633lGlb7veyeF7DWIJX7Be7ZHEydaDsSw
# Pl4uQkcuzNQg935cKUP4VO9XTcZ+sMN+T7jl+Uf94pFlzcxRm2eEsmM/C/cqgoNJ
# xbiJXpJsJHJxg+SqhYGsd/tK8MDsasfZQ63PVZrWTbux1mCkbr9z0KoojwJfm+Bp
# r4DuhgdvhkGPtLy7yyDHBYrseBYNEHI4fcKIm7gsnyHdOJGRECuYdGnSVs1/WIAq
# 4vzzogoT3Xa/TKrnm3yMzGMFTu6guythUigqTOH6wCSCSkY6hkvXj52XFUz3UFq/
# NriQ4NNSXDNv5KlexKpXHye4HqqFTLumqmDDDWrhI2EDEWcXGzGJOVqgvvkY3E9H
# rTmUnZZd6G0SLv/5h8mq8f6+epymoKPJD2E1pXO44QdfgzK6pyPCMIIHcTCCBVmg
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
# IFRTUyBFU046ODkwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAErodj9lYuc5wwRCyOQMCgH8
# llYIoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtU7ezMCIYDzIwMjYwMzA1MDgwNTA3WhgPMjAyNjAzMDYwODA1
# MDdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAO1Tt7MCAQAwBwIBAAICCNUwBwIB
# AAICEnAwCgIFAO1VCTMCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoD
# AqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEA7Ze6
# +C3pMbuSWJOjaEd6fmD4EQsDeWFyO0U0Zq1gIreOF7pSlJeXRpTwaMUThzPaxszy
# gXOrOPB4Afujp9RABahU6isCoooN124zZO7UdOlZdgyvrgknOyq/5h+V/neJKtdx
# +sZTHT78U21rdAAnE7pKH1WWznbrbwsgFh38/VSA4V6nQFFv5faVQH1Of8RMax8a
# ClIb/OOWMvvslcSUl3YhsvUsZLSfEuqx0oTSzWuCim/dDY1w/y2FHQzmqmqo/pBW
# d05p82ySWgP6OLnT3QWIhmaKWo6mXy4Esx/74jpTx/gSVv90HCEJsEyautmsUE9i
# ytrDaPHm/bg/+kn9ZzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAACDizLKH2VIHVjAAEAAAIOMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIB02
# oQbWzyBhihxhxlGPSSZdykPL7STN+p0u+dx/9dGtMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgAXQdcyXw6YGQrbrubGhspKKHA50/R5Q1dAzKk/NPEoYwgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAg4syyh9lSB1
# YwABAAACDjAiBCDkERdKXmyiiXybz/86fcIwM+7CJ/IH8rEyg7pUwURYwzANBgkq
# hkiG9w0BAQsFAASCAgBRJo4L50ivBEFP2WiFjMx0H+5s0d5p7/5pzNXSbizN8ur1
# PpAFGYwoPEBAPx8XbBnoCScuugIYYK0CX00rdqFpj6/lWVX+Cl7DI0Dd1jTnLbZy
# BnUawLiSM9ySSpE119p0j93+e1dxhE7wgvR93Tne5ZOTLWYNNp0GDzkrBKTvUVKp
# uAO5GHDinweqObK9iaSW6xyqFPxfwB4pZoV1UIS73vDYc9zTWIGFk2rTvVzmpsqa
# 582daU8/gLTPw2WF8BAUWDolr9fJYvfGh0ORyp9JOiSbBS37Fk61x3bQM2GdTzqk
# 5/z1EkfuroAK/u+S0Hqmk2T1m+nE2Zwluiqd6NXvs/yoQSAFyGOOP59IcEpLxs6/
# 5sQZzXWW4IjAjcqIaJ5f3Xou5j2p4a8WAkFqbqpKi2n3UcYyewUOduCS0uhqwB9A
# oUQKnn0thPygzk1N99YIsmcI3xk3vuYEKttcy6z7qWlUA0g0e8/P/x3p2j3O0YmO
# 0wxP40cMK1O/4MwysyFq3dnxVl1PI1EqT5P7reJzTKzrd2z2YzVQtituquCHcG3q
# 6MeB9na5OepCESTW8cZyZiXX9uKpJ9/gr6/4GFNRWOa9RXBGKfYm8I8xS/TXJYt0
# NksU5KBGxZ+ry3xuUYVq8u+Afx8evpQN3ZqetU/coC//yMOLBqNmGJDk+JjVew==
# SIG # End signature block
