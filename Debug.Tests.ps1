#Requires -Modules Pester

Describe "Common.ps1" {

    BeforeAll {
        # Dot-source the common script to make its functions available
        . "$PSScriptRoot/../Common.ps1"
    }

    Context "Helper Functions" {
        It "Should recursively convert a PSCustomObject to a Hashtable" {
            # Create a nested PSCustomObject
            $psObject = [pscustomobject]@{
                String = "hello"
                Number = 123
                Nested = [pscustomobject]@{
                    NestedString = "nested hello"
                    Array = @(1, 2, [pscustomobject]@{ Deep = "deep value" })
                }
            }

            # Call the conversion function
            $hashtable = ConvertTo-Hashtable -InputObject $psObject

            # Assert the types and values
            $hashtable | Should -BeOfType ([hashtable])
            $hashtable.String | Should -Be "hello"
            $hashtable.Nested | Should -BeOfType ([hashtable])
            $hashtable.Nested.NestedString | Should -Be "nested hello"
            $hashtable.Nested.Array[2] | Should -BeOfType ([hashtable])
            $hashtable.Nested.Array[2].Deep | Should -Be "deep value"
        }
    }

    Context "Metrics and Reporting" {
        It "Should update migration metrics correctly" {
            # Reset metrics before the test
            $script:MigrationContext.Metrics.VaultsProcessed = 0
            
            # Update a metric
            Update-MigrationMetrics -MetricType "VaultProcessed" -Count 2
            
            # Assert the metric was updated
            $script:MigrationContext.Metrics.VaultsProcessed | Should -Be 2
        }

        It "Should generate a migration report with correct summary data" {
            # Set up some metrics
            $script:MigrationContext.Metrics.VaultsProcessed = 5
            $script:MigrationContext.Metrics.VaultsFailed = 1
            $script:MigrationContext.Metrics.WarningsGenerated = 3
            
            $tempReportPath = Join-Path -Path $env:TEMP -ChildPath "temp-report-$(Get-Random).json"

            # Generate the report
            $report = Get-MigrationReport -OutputPath $tempReportPath

            # Assert the summary data in the report
            $report.Summary.VaultsProcessed | Should -Be 5
            $report.Summary.VaultsFailed | Should -Be 1
            $report.Summary.WarningsGenerated | Should -Be 3
            $report.QualityMetrics.SuccessRate | Should -Be ([math]::Round((5/6)*100, 2))

            # Cleanup
            Remove-Item -Path $tempReportPath -Force
        }
    }

    Context "Initialize-GroupMembershipCache" {

        BeforeEach {
            Reset-MigrationContext
            # Seed the PrincipalCache with entries of different types
            $script:MigrationContext.PrincipalCache['user-1'] = [PSCustomObject]@{ PrincipalType = 'User' }
            $script:MigrationContext.PrincipalCache['sp-1']   = [PSCustomObject]@{ PrincipalType = 'ServicePrincipal' }
            $script:MigrationContext.PrincipalCache['grp-1']  = [PSCustomObject]@{ PrincipalType = 'Group' }
            $script:MigrationContext.PrincipalCache['unk-1']  = [PSCustomObject]@{ PrincipalType = 'Unknown' }
        }

        It "Should resolve transitive group memberships via Graph API" {
            # Mock Invoke-AzRestMethod to return two groups (simulating nested membership)
            Mock Invoke-AzRestMethod {
                return [PSCustomObject]@{
                    StatusCode = 200
                    Content    = (@{
                        value = @(
                            @{ id = 'group-A' },
                            @{ id = 'group-B' }
                        )
                    } | ConvertTo-Json -Depth 5)
                }
            }

            Initialize-GroupMembershipCache -PrincipalIds @('user-1')

            $script:MigrationContext.GroupMembershipCache['user-1'] | Should -Be @('group-A', 'group-B')
            Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly
        }

        It "Should handle Graph API pagination via @odata.nextLink" {
            $callCount = 0
            Mock Invoke-AzRestMethod {
                $callCount++
                if ($callCount -eq 1) {
                    return [PSCustomObject]@{
                        StatusCode = 200
                        Content    = (@{
                            value            = @( @{ id = 'group-page1' } )
                            '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/nextpage'
                        } | ConvertTo-Json -Depth 5)
                    }
                } else {
                    return [PSCustomObject]@{
                        StatusCode = 200
                        Content    = (@{
                            value = @( @{ id = 'group-page2' } )
                        } | ConvertTo-Json -Depth 5)
                    }
                }
            }

            Initialize-GroupMembershipCache -PrincipalIds @('sp-1')

            $script:MigrationContext.GroupMembershipCache['sp-1'] | Should -Be @('group-page1', 'group-page2')
            Should -Invoke Invoke-AzRestMethod -Times 2 -Exactly
        }

        It "Should skip Group and Unknown principal types" {
            Mock Invoke-AzRestMethod {
                return [PSCustomObject]@{
                    StatusCode = 200
                    Content    = (@{ value = @() } | ConvertTo-Json -Depth 5)
                }
            }

            Initialize-GroupMembershipCache -PrincipalIds @('grp-1', 'unk-1')

            $script:MigrationContext.GroupMembershipCache.ContainsKey('grp-1') | Should -Be $false
            $script:MigrationContext.GroupMembershipCache.ContainsKey('unk-1') | Should -Be $false
            Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly
        }

        It "Should cache empty array on API failure and not throw" {
            Mock Invoke-AzRestMethod { throw "Simulated API error" }

            { Initialize-GroupMembershipCache -PrincipalIds @('user-1') } | Should -Not -Throw

            $script:MigrationContext.GroupMembershipCache['user-1'] | Should -Be @()
        }

        It "Should not re-query already cached principals" {
            $script:MigrationContext.GroupMembershipCache['user-1'] = @('existing-group')

            Mock Invoke-AzRestMethod {
                return [PSCustomObject]@{
                    StatusCode = 200
                    Content    = (@{ value = @( @{ id = 'new-group' } ) } | ConvertTo-Json -Depth 5)
                }
            }

            Initialize-GroupMembershipCache -PrincipalIds @('user-1')

            # Should still have original cached value
            $script:MigrationContext.GroupMembershipCache['user-1'] | Should -Be @('existing-group')
            Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly
        }
    }
}
# SIG # Begin signature block
# MIIo2gYJKoZIhvcNAQcCoIIoyzCCKMcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBH7FbKGV1Getb9
# 2oVvJ4xF2R5vmrvG0uYyDwHCKThcDaCCDcMwggatMIIElaADAgECAhMzAAAArn9k
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJmStelxMB6ECIteN35xXnP1
# KrC04znV4JP8S9BJb6+hMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAZj6mlzsMLo+CUMvjPhjnXzytobIzLIliK0NJGgqc19SEsUp4WdnYvsaq
# bM9OKZxAcFcYOlPAxCe1to8aCNDzws3v7c/8nIvJdDaJ90qHWe42jugcXKMsAYAH
# JzW003yIXp5Ao85kh86HceeVbP7klzPhHEGylJvbq09LKJjpQIAH1SOY/R9exOmW
# NDdHXDmMciRtGD3oOSMOiPbjJ8GsOWqcPaETeaXPopscw9sRkgLg4hWcB9ixdbJ8
# AOj1SDA3FOGgIoIcjimaIf8CNAab59hyQToDkw6mEuAQhTbg3bRRQ9KCf07AJbhF
# w01brhZOAScjvTuRiOfBOZjoZOTKErAuB49eyuj10lY+FUDF83IMMd3A55A7JVcN
# vZD4nlO1620Y3+KFu9LicZXPYro0H6X7KIWEBYp+RYuwUhhV7bxJvKjNXWyCTZpq
# Rn95w7mHbb5mhhpyRifF9K9mEFdUZ9FUibJgwKu+G0isCdWtP0leXsROZuPGOO1k
# c6/Jbe+poYIXlDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIX
# bTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIB15pZ1k416h
# C8/AYAyHqOkoM0LFJkbXr+ZcA2503Hd/AgZplKwptkUYEzIwMjYwMzA1MTg0MzAw
# LjcyNVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpEQzAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgEC
# AhMzAAACA7seXAA4bHTKAAEAAAIDMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI0NloXDTI2MDQyMjE5NDI0
# NlowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjpEQzAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AKGXQwfnACc7HxSHxG2J0XQnTJoUMclgdOk+9FHXpfUrEYNh9Pw+twaMIsKJo67c
# rUOZQhThFzmiWd2Nqmk246DPBSiPjdVtsnHk8VNj9rVnzS2mpU/Q6gomVSR8M9IE
# sWBdaPpWBrJEIg20uxRqzLTDmDKwPsgs9m6JCNpx7krEBKMp/YxVfWp8TNgFtMY0
# SKNJAIrDDJzR5q+vgWjdf/6wK64C2RNaKyxTriTysrrSOwZECmIRJ1+4evTJYCZz
# uNM4814YDHooIvaS2mcZ6AsN3UiUToG7oFLAAgUevvM7AiUWrJC4J7RJAAsJsmGx
# P3L2LLrVEkBexTS7RMLlhiZNJsQjuDXR1jHxSP6+H0icugpgLkOkpvfXVthV3RvK
# 1vOV9NGyVFMmCi2d8IAgYwuoSqT3/ZVEa72SUmLWP2dV+rJgdisw84FdytBhbSOY
# o2M4vjsJoQCs3OEMGJrXBd0kA0qoy8nylB7abz9yJvIMz7UFVmq40Ci/03i0kXgA
# K2NfSONc0NQy1JmhUVAf4WRZ189bHW4EiRz3tH7FEu4+NTKkdnkDcAAtKR7hNpEG
# 9u9MFjJbYd6c5PudgspM7iPDlCrpzDdn3NMpI9DoPmXKJil6zlFHYx0y8lLh8Jw8
# kV5pU6+5YVJD8Qa1UFKGGYsH7l7DMXN2l/VS4ma45BNPAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUsilZQH4R55Db2xZ7RV3PFZAYkn0wHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAJAQxt6wPpMLTxHShgJ1ILjnYBCsZ/87z0ZDngK2ASxvHPAYNVRyaNcV
# ydolJM150EpVeQGBrBGic/UuDEfhvPNWPZ5Y2bMYjA7UWWGV0A84cDMsEQdGhJni
# l10W1pDGhptT83W9bIgKI3rQi3zmCcXkkPgwxfJ3qlLx4AMiLpO2N+Ao+i6ZZrQE
# VD9oTONSt883Wvtysr6qSYvO3D8Q1LvN6Z/LHiQZGDBjVYF8Wqb+cWUkM9AGJyp5
# Td06n2GPtaoPRFz7/hVnrBCN6wjIKS/m6FQ3LYuE0OLaV5i0CIgWmaN82TgaeAu8
# LZOP0is4y/bRKvKbkn8WHvJYCI94azfIDdBqmNlO1+vs1/OkEglDjFP+JzhYZaqE
# aVGVUEjm7o6PDdnFJkIuDe9ELgpjKmSHwV0hagqKuOJ0QaVew06j5Q/9gbkqF5uK
# 51MHEZ5x8kK65Sykh1GFK0cBCyO/90CpYEuWGiurY4Jo/7AWETdY+CefHml+W+W6
# Ohw+Cw3bj7510euXc7UUVptbybRSQMdIoKHxBPBORg7C732ITEFVaVthlHPao4gG
# Mv+jMSG0IHRq4qF9Mst640YFRoHP6hln5f1QAQKgyGQRONvph81ojVPu9UBqK6EG
# hX8kI5BP5FhmuDKTI+nOmbAw0UEPW91b/b2r2eRNagSFwQ47Qv03MIIHcTCCBVmg
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
# IFRTUyBFU046REMwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAM2vFFf+LPqyzWUEJcbw/UsX
# EPR7oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtVEAVMCIYDzIwMjYwMzA1MTc0NzAxWhgPMjAyNjAzMDYxNzQ3
# MDFaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAO1UQBUCAQAwBwIBAAICHU0wBwIB
# AAICEpEwCgIFAO1VkZUCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoD
# AqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAO/6a
# FIcocvOeyy2SmcSh/vJZaPhd/74Mq6eRkHecqBc31jkXfUTv+0vTFG3PLbVB7xKi
# MbNaWglNWdPAlLltVbcQgZO596XgmnjK2O0OOC78yNSMyQYlYUyvkYUE+2bLE9Gy
# DmowNPcJ9t5oHl0Pba05IVnPLun8hKAyKA1GL5DMKp/jrd57L7grm+HuzxQaTHEa
# Jj/QyE/i+vAI518AhDH8M6h9UU7BN7vJeuw01Dc1NHvOtke46TFteX6RwK/RLeql
# y8vlIO8PUBoiIoiCc1wrN4HGeECCMdTqAqRDOOam2zNXGNuMFGLCH/hqg7IfTxpg
# n79QYg9OIdF4JO9ZYTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAACA7seXAA4bHTKAAEAAAIDMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEILIu
# iYMsdN4Cf1bSPY1yU4GFHLVWSANs2KotCYM2oNWYMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgSwPdG3GW9pPEU5lmelDDQOSw+ZV26jlLIr2H3D76Ey0wgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgO7HlwAOGx0
# ygABAAACAzAiBCA5n09Qq1NUfFjYaN0R7r1Wuu1Ty3scGqXx6NIYbkYG0zANBgkq
# hkiG9w0BAQsFAASCAgBA5oUJJbQY/fpqsNxqz31SeRX380crKZs0kxPW6zDu5wLW
# MS44sS6aVh9FRi6RGAtv6SaJFYCu28dzXr34LkE3LXkO7kgEOGlJq8kVxAb9hfi1
# fBysZ0nKzeUaiFWYeT6haZn/jUm/c5tMtVCkYxXoZNieE4dSaYyT+LAa1ZxKZGKu
# opu6mzmX4xnpob3eRuSicPWcz1o22lY78znLF8fD0IJalVQJc3U3bt8AeQlzqYn8
# BYXZUoO+28EMDAVrJ3vTt2iWXQ/ReqeqZqfl/BnHpX25y+oUt75Ob4NAMnPNSN+K
# Onj3zSFm+HVKm8emp1iZEFHqafyADQIV8zMbfY58JoaDf65CmZO0o5caiqsR5yde
# KgjX+uD9cxZxiEvWgeY+TqY9J+aKDFmCwe2ENGLvteZx0/wsWoWjV+V7oOsmevDl
# pjO6VrL10HQRBuJUR6wKJWljdOBiIIfQvKA69P6ZIFxyJUzq8MTeFl0WM7v6Nxt+
# e4kJftRFU+oPCB1TQ5fB2owna12qZKDf/nYyPSc6P0j+vkQ7apmVHYoNuaMZuI8H
# sO37tzwLrRfXIBDfcHWfeHZhKJt8AaLrC15r2raqc/BxHba2ju3JoBKwcpFkbrL9
# jTzUVBGOHHt1gQY0UDPiE3zHGj1X6xXaI2BahE8rUDDZfovtgq5YkMpn7FB4tA==
# SIG # End signature block
