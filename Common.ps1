# Common module for KvRbacMigrator
# Consolidates helper, logging, and audit functions.

#region Parameters and Global Variables

param(
    [string]$AuditLogPath = ".\log\audit.log"
)

# Consolidated migration context — single state object for metrics, caches, and lookups
$script:MigrationContext = @{
    Metrics = @{
        StartTime = Get-Date
        VaultsProcessed = 0
        VaultsSkipped = 0
        VaultsFailed = 0
        PrincipalsAnalyzed = 0
        RoleAssignmentsGenerated = 0
        WarningsGenerated = 0
        ErrorsEncountered = 0
        PermissionMappingDecisions = @()
        UnmappedPermissions = @()
    }
    PrincipalCache = @{}
    GroupMembershipCache = @{}
    PermissionRoleLookup = @{}
}

function Reset-MigrationContext {
    [CmdletBinding()]
    param()
    $script:AuditLogWarningShown = $false
    $script:MigrationContext = @{
        Metrics = @{
            StartTime = Get-Date
            VaultsProcessed = 0
            VaultsSkipped = 0
            VaultsFailed = 0
            PrincipalsAnalyzed = 0
            RoleAssignmentsGenerated = 0
            WarningsGenerated = 0
            ErrorsEncountered = 0
            PermissionMappingDecisions = @()
            UnmappedPermissions = @()
        }
        PrincipalCache = @{}
        GroupMembershipCache = @{}
        PermissionRoleLookup = @{}
    }
}

function Get-MigrationContext {
    [CmdletBinding()]
    param()
    return $script:MigrationContext
}
#endregion

#region Core Auditing and Logging

function Write-AuditLog {
    <#
    .SYNOPSIS
    Writes structured audit log entries for compliance and troubleshooting.
    Also writes colored output to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Decision", "Metric")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [hashtable]$Details = @{},
        
        [string]$Category = "General",
        
        [string]$VaultName = $null,
        
        [string]$PrincipalId = $null,

        [switch]$NoConsole
    )
    
    try {
        # Ensure the log file exists before writing
        if (-not (Test-Path $AuditLogPath)) {
            $logDir = Split-Path -Parent $AuditLogPath
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            # Create an empty file
            New-Item -Path $AuditLogPath -ItemType File -Force | Out-Null
        }

        $auditEntry = @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
            Level = $Level
            Category = $Category
            Message = $Message
            VaultName = $VaultName
            PrincipalId = $PrincipalId
            Details = $Details
            ProcessId = $PID
            User = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
        }
        
        $auditJson = $auditEntry | ConvertTo-Json -Compress -Depth 10
        Add-Content -Path $AuditLogPath -Value $auditJson
        
        # Write to console with colors (unless suppressed)
        if (-not $NoConsole) {
            switch ($Level) {
                "Info" { Write-Host $Message -ForegroundColor White }
                "Warning" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
                "Error" { Write-Host "ERROR: $Message" -ForegroundColor Red }
                default { Write-Verbose "AUDIT: [$Level] $Message" }
            }
        }
    }
    catch {
        if (-not $script:AuditLogWarningShown) {
            Write-Warning "Failed to write audit log: $($_.Exception.Message). Subsequent audit log failures will be suppressed."
            $script:AuditLogWarningShown = $true
        }
    }
}

function Initialize-AuditLogging {
    <#
    .SYNOPSIS
    Initializes audit logging for the migration session.
    #>
    [CmdletBinding()]
    param()
    
    $script:AuditLogWarningShown = $false

    try {
        # Ensure audit log directory exists
        $auditDir = Split-Path -Parent $AuditLogPath
        if (-not (Test-Path $auditDir)) {
            New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
        }
        
        # Write session start
        Write-AuditLog -Level "Info" -Message "Audit logging session started" -Details @{
            AuditLogPath = $AuditLogPath
            EnableMetrics = $true
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            User = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
        } -Category "Session" -NoConsole
        
        Write-Verbose "Audit logging initialized: $AuditLogPath"
        return $true
    }
    catch {
        Write-Warning "Failed to initialize audit logging: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Simple Logging Wrappers

function Write-LogInfo {
    <#
    .SYNOPSIS
    Writes an info-level log message.
    #>
    [CmdletBinding()]
    param([string]$Message, [switch]$NoConsole)
    Write-AuditLog -Level "Info" -Message $Message -NoConsole:$NoConsole
}

function Write-LogWarning {
    <#
    .SYNOPSIS
    Writes a warning-level log message.
    #>
    [CmdletBinding()]
    param([string]$Message, [switch]$NoConsole)
    Write-AuditLog -Level "Warning" -Message $Message -NoConsole:$NoConsole
}

function Write-LogError {
    <#
    .SYNOPSIS
    Writes an error-level log message.
    #>
    [CmdletBinding()]
    param([string]$Message, [switch]$NoConsole)
    Write-AuditLog -Level "Error" -Message $Message -NoConsole:$NoConsole
}

function Get-LogFilePath {
    <#
    .SYNOPSIS
    Returns the current audit log file path.
    #>
    return $AuditLogPath
}

#endregion

#region Metrics and Reporting

function Write-PermissionMappingDecision {
    <#
    .SYNOPSIS
    Records detailed information about permission-to-role mapping decisions for audit purposes.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$PrincipalId,
        [string]$PermissionType,
        [string[]]$InputPermissions,
        [string]$MappedRole,
        [string]$DecisionReason,
        [string[]]$UnmappedPermissions = @(),
        [hashtable]$RoleWeights = @{}
    )
    
    $decision = @{
        VaultName = $VaultName
        PrincipalId = $PrincipalId
        PermissionType = $PermissionType
        InputPermissions = $InputPermissions
        MappedRole = $MappedRole
        DecisionReason = $DecisionReason
        UnmappedPermissions = $UnmappedPermissions
        RoleWeights = $RoleWeights
        Timestamp = Get-Date
    }
    
    [void]($script:MigrationContext.Metrics.PermissionMappingDecisions += $decision)
    
    Write-AuditLog -Level "Decision" -Message "Permission mapping decision made" -Details $decision -Category "PermissionMapping" -VaultName $VaultName -PrincipalId $PrincipalId
    
    if ($UnmappedPermissions.Count -gt 0) {
        foreach ($unmapped in $UnmappedPermissions) {
            $unmappedEntry = @{
                Permission = $unmapped
                PermissionType = $PermissionType
                VaultName = $VaultName
                PrincipalId = $PrincipalId
                Timestamp = Get-Date
            }
            [void]($script:MigrationContext.Metrics.UnmappedPermissions += $unmappedEntry)
        }
    }
}

function Update-MigrationMetrics {
    <#
    .SYNOPSIS
    Updates migration metrics for monitoring and reporting.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("VaultProcessed", "VaultSkipped", "VaultFailed", "PrincipalAnalyzed", "RoleAssignmentGenerated", "WarningGenerated", "ErrorEncountered")]
        [string]$MetricType,
        [int]$Count = 1,
        [hashtable]$AdditionalData = @{}
    )
    
    switch ($MetricType) {
        "VaultProcessed" { $script:MigrationContext.Metrics.VaultsProcessed += $Count }
        "VaultSkipped" { $script:MigrationContext.Metrics.VaultsSkipped += $Count }
        "VaultFailed" { $script:MigrationContext.Metrics.VaultsFailed += $Count }
        "PrincipalAnalyzed" { $script:MigrationContext.Metrics.PrincipalsAnalyzed += $Count }
        "RoleAssignmentGenerated" { $script:MigrationContext.Metrics.RoleAssignmentsGenerated += $Count }
        "WarningGenerated" { $script:MigrationContext.Metrics.WarningsGenerated += $Count }
        "ErrorEncountered" { $script:MigrationContext.Metrics.ErrorsEncountered += $Count }
    }
    
    Write-AuditLog -Level "Metric" -Message "$MetricType updated" -Details @{
        MetricType = $MetricType
        Count = $Count
        CurrentValue = $script:MigrationContext.Metrics.$MetricType
        AdditionalData = $AdditionalData
    } -Category "Metrics"
}

function Get-MigrationReport {
    <#
    .SYNOPSIS
    Generates a comprehensive migration report including metrics and recommendations.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\out\migration-report.json"
    )
    
    $endTime = Get-Date
    $duration = $endTime - $script:MigrationContext.Metrics.StartTime
    
    $report = @{
        Summary = @{
            StartTime = $script:MigrationContext.Metrics.StartTime
            EndTime = $endTime
            Duration = $duration.ToString()
            TotalVaultsDiscovered = $script:MigrationContext.Metrics.VaultsProcessed + $script:MigrationContext.Metrics.VaultsSkipped + $script:MigrationContext.Metrics.VaultsFailed
            VaultsProcessed = $script:MigrationContext.Metrics.VaultsProcessed
            VaultsSkipped = $script:MigrationContext.Metrics.VaultsSkipped
            VaultsFailed = $script:MigrationContext.Metrics.VaultsFailed
            PrincipalsAnalyzed = $script:MigrationContext.Metrics.PrincipalsAnalyzed
            RoleAssignmentsGenerated = $script:MigrationContext.Metrics.RoleAssignmentsGenerated
            WarningsGenerated = $script:MigrationContext.Metrics.WarningsGenerated
            ErrorsEncountered = $script:MigrationContext.Metrics.ErrorsEncountered
        }
        PermissionMappingAnalysis = @{
            TotalDecisions = $script:MigrationContext.Metrics.PermissionMappingDecisions.Count
            UnmappedPermissionsCount = $script:MigrationContext.Metrics.UnmappedPermissions.Count
            UnmappedPermissionsSummary = ($script:MigrationContext.Metrics.UnmappedPermissions | Group-Object Permission | ForEach-Object { 
                @{ Permission = $_.Name; Count = $_.Count; PermissionType = $_.Group[0].PermissionType }
            })
            RoleDistribution = ($script:MigrationContext.Metrics.PermissionMappingDecisions | Group-Object MappedRole | ForEach-Object {
                @{ Role = $_.Name; Count = $_.Count }
            })
        }
        Recommendations = @()
        QualityMetrics = @{
            SuccessRate = if (($script:MigrationContext.Metrics.VaultsProcessed + $script:MigrationContext.Metrics.VaultsFailed) -gt 0) {
                [math]::Round(($script:MigrationContext.Metrics.VaultsProcessed / ($script:MigrationContext.Metrics.VaultsProcessed + $script:MigrationContext.Metrics.VaultsFailed)) * 100, 2)
            } else { 100 }
            AverageProblemsPerVault = if ($script:MigrationContext.Metrics.VaultsProcessed -gt 0) {
                [math]::Round(($script:MigrationContext.Metrics.WarningsGenerated + $script:MigrationContext.Metrics.ErrorsEncountered) / $script:MigrationContext.Metrics.VaultsProcessed, 2)
            } else { 0 }
        }
    }
    
    if ($script:MigrationContext.Metrics.UnmappedPermissions.Count -gt 0) {
        $report.Recommendations += "Review unmapped permissions - $($script:MigrationContext.Metrics.UnmappedPermissions.Count) permissions could not be mapped to RBAC roles"
    }
    if ($script:MigrationContext.Metrics.VaultsFailed -gt 0) {
        $report.Recommendations += "Investigate failed vaults - $($script:MigrationContext.Metrics.VaultsFailed) vaults failed processing"
    }
    if ($report.QualityMetrics.AverageProblemsPerVault -gt 2) {
        $report.Recommendations += "High problem rate detected - average of $($report.QualityMetrics.AverageProblemsPerVault) issues per vault may indicate systematic problems"
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath
    
    Write-AuditLog -Level "Info" -Message "Migration report generated" -Details @{ 
        OutputPath = $OutputPath
        VaultsProcessed = $report.Summary.VaultsProcessed
        SuccessRate = $report.QualityMetrics.SuccessRate
    } -Category "Reporting"
    
    return $report
}

#endregion

#region Security and Helpers

function Initialize-PermissionLookupCache {
    <#
    .SYNOPSIS
    Pre-computes permission-to-role lookup tables for performance optimization
    
    .DESCRIPTION
    Builds hashtable lookups from the role mapping configuration to enable O(1)
    permission-to-role mapping during analysis with optimized cache access.
    
    .PARAMETER RoleMapping
    The role mapping hashtable containing permission mappings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RoleMapping
    )
    
    Write-Verbose "Initializing permission lookup cache"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    $script:MigrationContext.PermissionRoleLookup = @{
        secrets = @{}
        keys = @{}
        certificates = @{}
    }
    
    $totalPermissions = 0
    
    foreach ($objectType in @('secrets', 'keys', 'certificates')) {
        if ($RoleMapping[$objectType]) {
            foreach ($permission in $RoleMapping[$objectType].Keys) {
                $role = $RoleMapping[$objectType][$permission]
                $script:MigrationContext.PermissionRoleLookup[$objectType][$permission] = $role
                $totalPermissions++
            }
            Write-Verbose "Cached $($RoleMapping[$objectType].Keys.Count) $objectType permission mappings"
        }
    }
    
    $stopwatch.Stop()
    Write-Verbose "Permission lookup cache initialized: $totalPermissions mappings in $($stopwatch.ElapsedMilliseconds)ms"
    
    Write-AuditLog -Level "Info" -Message "Permission lookup cache initialized" -Details @{
        SecretsPermissions = $script:MigrationContext.PermissionRoleLookup.secrets.Keys.Count
        KeysPermissions = $script:MigrationContext.PermissionRoleLookup.keys.Keys.Count
        CertificatesPermissions = $script:MigrationContext.PermissionRoleLookup.certificates.Keys.Count
        TotalPermissions = $totalPermissions
        ElapsedMs = $stopwatch.ElapsedMilliseconds
    } -Category "Performance" -NoConsole
}

function Initialize-BulkPrincipalCache {
    <#
    .SYNOPSIS
    Bulk resolves principals and pre-populates the principal cache for performance optimization
    
    .DESCRIPTION
    Performs bulk queries for service principals and users in chunks to minimize API calls.
    Pre-populates the $script:MigrationContext.PrincipalCache to enable O(1) lookups during analysis.
    
    .PARAMETER PrincipalIds
    Array of principal object IDs to resolve
    
    .PARAMETER ChunkSize
    Number of principals to query per API call (default: 100)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$PrincipalIds,
        [int]$ChunkSize = 100
    )
    
    if (-not $PrincipalIds -or $PrincipalIds.Count -eq 0) {
        Write-Verbose "No principal IDs provided for bulk resolution"
        return
    }
    
    # Filter out null, empty, or whitespace-only principal IDs
    $uniquePrincipalIds = $PrincipalIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
    
    if ($uniquePrincipalIds.Count -eq 0) {
        Write-Warning "All provided principal IDs were null, empty, or whitespace. This may indicate issues with access policy ObjectId values."
        Write-AuditLog -Level "Warning" -Message "Bulk principal resolution skipped - all principal IDs were empty" -Details @{
            OriginalCount = $PrincipalIds.Count
            FilteredCount = 0
        } -Category "PrincipalResolution"
        return
    }
    Write-Verbose "Starting bulk principal resolution for $($uniquePrincipalIds.Count) unique principals"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Track API calls and cache hits
    $apiCallCount = 0
    $cacheHits = 0
    $newlyCached = 0
    
    for ($i = 0; $i -lt $uniquePrincipalIds.Count; $i += $ChunkSize) {
        $endIndex = [Math]::Min($i + $ChunkSize - 1, $uniquePrincipalIds.Count - 1)
        $chunk = $uniquePrincipalIds[$i..$endIndex]
        
        # Filter out already cached principals
        $uncachedChunk = $chunk | Where-Object { -not $script:MigrationContext.PrincipalCache.ContainsKey($_) }
        $cacheHits += ($chunk.Count - $uncachedChunk.Count)
        
        if ($uncachedChunk.Count -eq 0) {
            Write-Verbose "Chunk $([Math]::Floor($i/$ChunkSize) + 1): All $($chunk.Count) principals already cached"
            continue
        }
        
        Write-Verbose "Processing chunk $([Math]::Floor($i/$ChunkSize) + 1): $($uncachedChunk.Count) uncached principals"
        
        # Resolve each uncached principal individually (-ObjectId accepts a single string, not arrays)
        if ($uncachedChunk.Count -gt 0) {
            Write-Verbose "Resolving $($uncachedChunk.Count) uncached principals individually..."
            foreach ($principalId in $uncachedChunk) {
                if ($script:MigrationContext.PrincipalCache.ContainsKey($principalId)) { continue }

                # Try ServicePrincipal
                $bulkResolveFailed = $false
                try {
                    $sp = Get-AzADServicePrincipal -ObjectId $principalId -ErrorAction Stop
                    $apiCallCount++
                    if ($sp) {
                        $script:MigrationContext.PrincipalCache[$sp.Id] = [PSCustomObject]@{
                            PrincipalId       = $sp.Id
                            DisplayName       = $sp.DisplayName
                            PrincipalType     = "ServicePrincipal"
                            AppId             = $sp.AppId
                            UserPrincipalName = $null
                        }
                        $newlyCached++
                        continue
                    }
                } catch {
                    Write-Verbose "SP lookup failed for $principalId : $($_.Exception.Message)"
                    $bulkResolveFailed = $true
                }

                # Try User
                try {
                    $user = Get-AzADUser -ObjectId $principalId -ErrorAction Stop
                    $apiCallCount++
                    if ($user) {
                        $script:MigrationContext.PrincipalCache[$user.Id] = [PSCustomObject]@{
                            PrincipalId       = $user.Id
                            DisplayName       = $user.DisplayName
                            PrincipalType     = "User"
                            AppId             = $null
                            UserPrincipalName = $user.UserPrincipalName
                        }
                        $newlyCached++
                        continue
                    }
                } catch {
                    Write-Verbose "User lookup failed for $principalId : $($_.Exception.Message)"
                    $bulkResolveFailed = $true
                }

                # Try Group
                try {
                    $group = Get-AzADGroup -ObjectId $principalId -ErrorAction Stop
                    $apiCallCount++
                    if ($group) {
                        $script:MigrationContext.PrincipalCache[$group.Id] = [PSCustomObject]@{
                            PrincipalId       = $group.Id
                            DisplayName       = $group.DisplayName
                            PrincipalType     = "Group"
                            AppId             = $null
                            UserPrincipalName = $null
                        }
                        $newlyCached++
                        continue
                    }
                } catch {
                    Write-Verbose "Group lookup failed for $principalId : $($_.Exception.Message)"
                    $bulkResolveFailed = $true
                }

                Write-Verbose "Could not resolve principal $principalId via bulk cache - will retry individually if needed"
            }
        }
        
        # DON'T cache unknown principals here - let individual lookups handle them with better error reporting
        $stillUnknown = $uncachedChunk | Where-Object { -not $script:MigrationContext.PrincipalCache.ContainsKey($_) }
        if ($stillUnknown.Count -gt 0) {
            Write-Verbose "Did not resolve $($stillUnknown.Count) principals via bulk query - will retry individually if needed"
            Write-Verbose "Unresolved principal IDs: $($stillUnknown -join ', ')"
        }
    }
    
    $stopwatch.Stop()

    # Warn if all lookups failed — likely an auth or connectivity issue
    $totalAttempted = $uniquePrincipalIds.Count - $cacheHits
    if ($totalAttempted -gt 0 -and $newlyCached -eq 0) {
        Write-Warning "Could not resolve any of the $totalAttempted uncached principals. Principal names will show as 'Unknown'. Check Azure AD permissions (Directory.Read.All) and connectivity."
    }

    Write-Verbose "Bulk principal resolution completed: $newlyCached newly cached, $cacheHits cache hits, $apiCallCount API calls in $($stopwatch.ElapsedMilliseconds)ms"
    
    Write-AuditLog -Level "Info" -Message "Bulk principal resolution completed" -Details @{
        TotalPrincipals = $uniquePrincipalIds.Count
        NewlyCached = $newlyCached
        CacheHits = $cacheHits
        ApiCalls = $apiCallCount
        ElapsedMs = $stopwatch.ElapsedMilliseconds
        CacheSizeAfter = $script:MigrationContext.PrincipalCache.Count
    } -Category "Performance" -NoConsole
}

function Initialize-GroupMembershipCache {
    <#
    .SYNOPSIS
    Builds a user-to-groups mapping so that group-inherited role assignments can be detected.

    .DESCRIPTION
    For each principal of type User or ServicePrincipal in the PrincipalCache,
    queries Microsoft Graph for **transitive** group memberships (including nested groups)
    and stores them in MigrationContext.GroupMembershipCache as principalId -> @(groupId1, groupId2, ...).
    Uses Invoke-AzRestMethod against the Graph API to avoid requiring the Microsoft.Graph module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$PrincipalIds
    )

    $uniqueIds = @($PrincipalIds | Sort-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($uniqueIds.Count -eq 0) { return }

    Write-Verbose "Starting transitive group membership resolution for $($uniqueIds.Count) unique principals"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $apiCallCount = 0
    $resolved = 0
    $failed = 0
    $graphPermissionWarned = $false

    foreach ($principalId in $uniqueIds) {
        # Skip if already cached
        if ($script:MigrationContext.GroupMembershipCache.ContainsKey($principalId)) { continue }

        # Only look up group memberships for Users and ServicePrincipals
        $cached = $script:MigrationContext.PrincipalCache[$principalId]
        if (-not $cached -or $cached.PrincipalType -eq "Group" -or $cached.PrincipalType -eq "Unknown") {
            continue
        }

        try {
            # Use Graph transitive memberOf endpoint to resolve nested groups
            $graphUri = "https://graph.microsoft.com/v1.0/directoryObjects/$principalId/transitiveMemberOf/microsoft.graph.group?`$select=id"
            $groupIds = @()
            $nextLink = $null

            do {
                $requestUri = if ($nextLink) { $nextLink } else { $graphUri }
                $response = Invoke-AzRestMethod -Uri $requestUri -Method GET -ErrorAction Stop
                $apiCallCount++

                if ($response.StatusCode -eq 429) {
                    Write-Warning "Graph API throttled (429) while resolving group memberships for principal $principalId. Group-inherited role assignments may be missed."
                    $failed++
                    break
                }
                if ($response.StatusCode -eq 403 -and -not $graphPermissionWarned) {
                    Write-Warning "Graph API returned 403 Forbidden. Ensure the identity has Directory.Read.All permission. Group-inherited role assignments will not be detected."
                    $graphPermissionWarned = $true
                    $failed++
                    break
                }
                if ($response.StatusCode -ne 200) {
                    Write-Warning "Graph API returned status $($response.StatusCode) for principal $principalId. Group membership lookup skipped."
                    $failed++
                    break
                }

                $body = $response.Content | ConvertFrom-Json
                $groupIds += @($body.value | ForEach-Object { $_.id })
                $nextLink = $body.'@odata.nextLink'
            } while ($nextLink)

            $script:MigrationContext.GroupMembershipCache[$principalId] = $groupIds
            $resolved++
            if ($groupIds.Count -gt 0) {
                Write-Verbose "Principal $principalId is a transitive member of $($groupIds.Count) group(s)"
            }
        }
        catch {
            Write-Warning "Could not resolve group memberships for principal $principalId : $($_.Exception.Message)"
            $script:MigrationContext.GroupMembershipCache[$principalId] = @()
            $failed++
        }
    }

    $stopwatch.Stop()

    if ($failed -gt 0) {
        Write-Warning "Group membership resolution: $failed of $($uniqueIds.Count) principal(s) failed. Group-inherited role assignments may be missed for these principals."
    }

    Write-Verbose "Transitive group membership resolution completed: $resolved resolved, $failed failed, $apiCallCount API calls in $($stopwatch.ElapsedMilliseconds)ms"

    Write-AuditLog -Level "Info" -Message "Transitive group membership resolution completed" -Details @{
        TotalPrincipals = $uniqueIds.Count
        Resolved        = $resolved
        Failed          = $failed
        ApiCalls        = $apiCallCount
        ElapsedMs       = $stopwatch.ElapsedMilliseconds
    } -Category "Performance" -NoConsole
}

function Get-ResolvedPrincipal {
    <#
    .SYNOPSIS
    Resolves a principal object from cache or Entra ID, with caching.
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId
    )

    if ([string]::IsNullOrEmpty($PrincipalId)) {
        return $null
    }

    # Check cache first
    if ($script:MigrationContext.PrincipalCache.ContainsKey($PrincipalId)) {
        Write-Verbose "Principal $PrincipalId found in cache."
        return $script:MigrationContext.PrincipalCache[$PrincipalId]
    }

    Write-Verbose "Principal $PrincipalId not in cache. Querying Entra ID."
    $principalObject = $null
    
    # Try to get as a service principal first
    try {
        Write-Verbose "Attempting to resolve '$PrincipalId' as service principal..."
        $sp = Get-AzADServicePrincipal -ObjectId $PrincipalId -ErrorAction Stop
        if ($sp) {
            Write-Verbose "Successfully resolved service principal: $($sp.DisplayName)"
            $principalObject = [PSCustomObject]@{
                PrincipalId = $sp.Id
                DisplayName = $sp.DisplayName
                PrincipalType = "ServicePrincipal"
                AppId = $sp.AppId
                UserPrincipalName = $null
            }
        }
    }
    catch {
        $spErrorMsg = $_.Exception.Message
        Write-Verbose "Service principal query failed for '$PrincipalId': $spErrorMsg"
        
        # Try to get as a user
        try {
            Write-Verbose "Attempting to resolve '$PrincipalId' as user..."
            $user = Get-AzADUser -ObjectId $PrincipalId -ErrorAction Stop
            if ($user) {
                Write-Verbose "Successfully resolved user: $($user.DisplayName)"
                $principalObject = [PSCustomObject]@{
                    PrincipalId = $user.Id
                    DisplayName = $user.DisplayName
                    PrincipalType = "User"
                    AppId = $null
                    UserPrincipalName = $user.UserPrincipalName
                }
            }
        }
        catch {
            Write-Warning "Could not resolve principal ID '$PrincipalId' as user or service principal:"
            Write-Warning "  Service Principal Error: $spErrorMsg"
            Write-Warning "  User Error: $($_.Exception.Message)"
            Write-Warning "This may indicate insufficient Azure AD permissions or authentication issues."
        }
    }

    if ($null -eq $principalObject) {
        # Cache the failure to avoid repeated lookups for invalid IDs
        $principalObject = [PSCustomObject]@{
            PrincipalId = $PrincipalId
            DisplayName = "Unknown"
            PrincipalType = "Unknown"
            AppId = $null
            UserPrincipalName = $null
        }
    }
    
    # Add to cache
    $script:MigrationContext.PrincipalCache[$PrincipalId] = $principalObject
    
    return $principalObject
}

function Test-AzureADPermissions {
    <#
    .SYNOPSIS
    Tests Azure AD permissions required for principal name resolution
    
    .DESCRIPTION
    Verifies that the current user has sufficient permissions to query Azure AD
    for service principals and users. This helps diagnose "Unknown" principal issues.
    
    .OUTPUTS
    Boolean indicating whether Azure AD queries are working
    #>
    [CmdletBinding()]
    param()
    
    $hasPermissions = $true
    $failures = @()
    
    try {
        $testUser = Get-AzADUser -First 1 -ErrorAction Stop
    } catch {
        $failures += "User query: $($_.Exception.Message)"
        $hasPermissions = $false
    }
    
    try {
        $testSP = Get-AzADServicePrincipal -First 1 -ErrorAction Stop
    } catch {
        $failures += "Service Principal query: $($_.Exception.Message)"
        $hasPermissions = $false
    }
    
    try {
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            $failures += "No active Azure context"
            $hasPermissions = $false
        }
    } catch {
        $failures += "Azure authentication: $($_.Exception.Message)"
        $hasPermissions = $false
    }
    
    if (-not $hasPermissions) {
        Write-Host "Azure AD permission check failed:" -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Yellow }
        Write-Host "Ensure you have Directory.Read.All and are connected to the correct tenant." -ForegroundColor Yellow
    }
    
    return $hasPermissions
}

function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
    Recursively converts a PSCustomObject to a Hashtable.
    #>
    param(
        [Parameter(ValueFromPipeline)]
        $InputObject
    )
    
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [hashtable]) { return $InputObject }
    
    $hash = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Value -is [PSCustomObject]) {
            $hash[$property.Name] = ConvertTo-Hashtable $property.Value
        } elseif ($property.Value -is [System.Array]) {
            $hash[$property.Name] = @()
            foreach ($item in $property.Value) {
                if ($item -is [PSCustomObject]) {
                    $hash[$property.Name] += ConvertTo-Hashtable $item
                } else {
                    $hash[$property.Name] += $item
                }
            }
        } else {
            $hash[$property.Name] = $property.Value
        }
    }
    return $hash
}

#endregion

#region Initialization

# Auto-initialize when module is imported
if ($MyInvocation.InvocationName -ne ".") {
    Initialize-AuditLogging
}

#endregion
# SIG # Begin signature block
# MIIo2gYJKoZIhvcNAQcCoIIoyzCCKMcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCNUth4QjJnQvcm
# Hlmox+hIVSczey8D8xjTLk3h6DvlyqCCDcMwggatMIIElaADAgECAhMzAAAArn9k
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMOBRUcic0WtHogCkmswy/7L
# JQZFmzKVWTtiUY1Ny3IBMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAZWIULAgkMQWCEvlCJuC3aUAIlTtduags7yZqrmt49SHUvqaV0spXwc9M
# W90fUG9WFE6/gWl46rpQqXPHG1Zy00vOx+o0yMv6CZsMabtuFUWhoJKHszB4V7a4
# VwUx/tMtKD6HRw+JjBmNDg9iAAY+rcfJ01t66dWdFnKHBTSE27StZtwkPSxLF8ZF
# GEDZsHZs2MER+MFK2vmcdr48wLB/zDJid92JmxHsxBLn9qGyXzYgdLoPuPXfqGz2
# WQI81o3lyMOzhaNweb8v20PBwPn736/q0NkYJcO41J3f20uVuHElJ0qkbtZpDC5+
# 8Eb5bcQxk5KeY3DXtn/NX3rpahwSuGTNbbfVwtimeq473kKMQPqNt0HqBOzP+rmM
# oTVtLq7SlLlSXn+gw0gZ8Uqyibj0AkXx2ek7eeHfSRfn9MnQOQKTKXQGtVOstr26
# oJ8UyVvWl/kLAQ3ej1AZA1BzYo2h5Zlt0DFBW7lVh2HgGTBhAs0LKFEzCwWthJ0W
# hRN3NkdsoYIXlDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIX
# bTCCF2kCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIF3I9Hia0Dbt
# fB5zrZAc7bt54qJ5AIk7cl1IHkVLiZBbAgZplO9jD0AYEzIwMjYwMzA1MTg0MjU4
# LjMwNVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5NjAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgEC
# AhMzAAACBNjgDgeXMliYAAEAAAIEMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI0N1oXDTI2MDQyMjE5NDI0
# N1owgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjo5NjAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# APDdJtx57Z3rq+RYZMheF8aqqBAbFBdOerjheVS83MVK3sQu07gH3f2PBkVfsOtG
# 3/h+nMY2QV0alzsQvlLzqopi/frR5eNb58i/WUCoMPfV3+nwCL38BnPwz3nOjSsO
# krZyzP1YDJH0W1QPHnZU6z2o/f+mCke+BS8Pyzr/co0hPOazxALW0ndMzDVxGf0J
# mBUhjPDaIP9m85bSxsX8NF2AzxR23GMUgpNdNoj9smGxCB7dPBrIpDaPzlFp8UVU
# JHn8KFqmSsFBYbA0Vo/OmZg3jqY+I69TGuIhIL2dD8asNdQlbMsOZyGuavZtoAEl
# 6+/DfVRiVOUtljrNSaOSBpF+mjN34aWr1NjYTcOCWvo+1MQqA+7aEzq/w2JTmdO/
# GEOfF2Zx/xQ3uCh5WUQtds6buPzLDXEz0jLJC5QxaSisFo3/mv2DiW9iQyiFFcRg
# HS0xo4+3QWZmZAwsEWk1FWdcFNriFpe+fVp0qu9PPxWV+cfGQfquID+HYCWphaG/
# RhQuwRwedoNaCoDb2vL6MfT3sykn8UcYfGT532QfYvlok+kBi42Yw08HsUNM9YDH
# sCmOv8nkyFTHSLTuBXZusBn0n1EeL58w9tL5CbgCicLmI5OP50oK21VGz6Moq47r
# cIvCqWWO+dQKa5Jq85fnghc60pwVmR8N05ntwTgOKg/VAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUGnV2S0Bwalb8qbqqb6+7gzUZol8wHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAF5y/qxHDYdMszJQLVYkn4VH4OAD0mS/SUawi3jLr0KY6PxHregVuFKZ
# x2lqTGo1uvy/13JNvhEPI2q2iGKJdu2teZArlfvL9D74XTMyi1O1OlM+8bd6W3JX
# 8u87Xmasug1DtbhUfnxou3TfS05HGzxWcBBAXkGZBAw65r4RCAfh/UXi4XquXcQL
# XskFInTCMdJ5r+fRZiIc9HSqTP81EB/yVJRRXSBsgxrAYiOfv5ErIKv7yXXF02Qr
# 8XRRi5feEbScT71ZzQvgD96eW5Q3s9r285XpWLcE4lJPRFj9rHuJnjmV4zySoLDs
# EU9xMiRbPGmOvacK2KueTDs4FDoU2DAi4C9g1NTuvrRbjbVgU4vmlOwxlw0M46wD
# TXG/vKYIXrOScwalEe7DRFvYEAkL2q5TsJdZsxsAkt1npcg0pquJKYJff8wt3Nxb
# lc7JwrRCGhE1F/hapdGyEQFpjbKYm8c7jyhJJj+Sm5i8FLeWMAC4s3tGnyNZLu33
# XqloZ4Tumuas/0UmyjLUsUqYWdb6+DjcA2EHK4ARer0JrLmjsrYfk0WdHnCP9ItE
# rArWLJRf3bqLVMS+ISICH89XIlsAPiSiKmKDbyn/ocO6Jg5nTBSSb9rlbyisiOg5
# 1TdewniLTwJ82nkjvcKy8HlA9gxwukX007/Uu+hADDdQ90vnkzkdMIIHcTCCBVmg
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
# IFRTUyBFU046OTYwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVALo9gdHD371If7WnDLqrNUbe
# T2VuoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtU9qSMCIYDzIwMjYwMzA1MTAzMzU0WhgPMjAyNjAzMDYxMDMz
# NTRaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAO1T2pICAQAwBwIBAAICBoAwBwIB
# AAICEpwwCgIFAO1VLBICAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoD
# AqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAcZhb
# SHuVKqxA0ouXgL2jInSr1HqAF1zmiNeHrp6f3qhhYXQ3hjuplvEk4ZWAp3dUdgya
# AN2IQWsiN/vjZfngvaGoYxOE1LI0FVZpkXtpY1iB6QW49o/npQwwszNoq8f5TkgS
# X5V/hfd3lOih8ZditaQnv3hv5TDQB4yH+ANCqDTk5Ucpnw1MSmwipdZqnkYiLUa9
# YtDT9iZA74ZKD1lufLnoizybMbfDZ6ab+A94LsGy3HmNRNx1SwmgcMPZDtpjKWpg
# aGDQ0iDFVF6LT5A6CwSLvvCYQrMAwU7QWkAuSOXgmz7QdR/3txIp/KapkkNzyL+e
# GEE4koVXteU8+Ph+NzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAACBNjgDgeXMliYAAEAAAIEMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEILzz
# 9B4wySj9GeNvPzMOdreoECaH3gAqje5aotQitgVyMIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQg+e14Zf1bCrxV0kzqaN/HUYQmy7v/qRTqXRJLmtx5uf4wgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgTY4A4HlzJY
# mAABAAACBDAiBCCHuRWClMsIgde9405KRA5CkyRV08ujYIE8vUstJFUz3DANBgkq
# hkiG9w0BAQsFAASCAgCkXkMm60wkGCLcikkQ9kxeadDaRodQuTi5/4mJAho6i3+B
# DMFhvWiIHfmM+kC5hDYI1tEbiIGI+SENw9M+DbHSvZkNySkl4vDp388Rku5Q/Xaz
# g+mLJri1F0g8HjZn2AgRnFXoD/2lehUCj/EB1d4SLiykR97JD2jGhkCK6e/m0GIp
# nRY1raDjrUWZA5QssrtYJwRsCeFjZP358kMZVfZHRY/4QkAcd+pogi/Y2XnTOT2B
# wcbPknCJvujvoDqecmDksIk3n2S0V0ELwxgJUGDuYfQlAxMdoPUILeUDSl0za3Ky
# YBqZeE09kj41y6E3wj2vUzt0FLA5fEmCgIiKKCubU9ZEGqSC785DK/Gun+FlVKYe
# hmYCnw41Iok1jbfXXN96zTs+AIR7U0JqqZBwcPQdp+H4p11xJ6uY/uq0MipR4xkM
# UQJTIgc9POy7BG4YNwuhMTFDbUCmJzHL/KAxZVSEOr/J5A61aCxi13oovU2oL/Gn
# 67m2PIJ5J6ljUsrAveu9UCl/bN+kP3L2rd+jMlqlf3JzGptE0fxCaOIXQL5cC26d
# RtqA6EIO54cchjeyHL8O0XoD5sCiprBzlrz0KiOmJdgu/hTZQO/o18i1pRbU6S9P
# SC/3+XlVA2HTduNyne5it0pZuzjtUvX10D1bkpJv5/LDwUOM6OvZSxnzhU/pVw==
# SIG # End signature block
