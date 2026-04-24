[CmdletBinding()]
param(
    [string[]]$VaultName = $null,
    [string]$ResourceGroup = $null,
    [string]$SubscriptionId = $null,
    [hashtable]$TagFilter = $null,
    [string]$OutputFolder = ".\out",
    [switch]$GetPermissionMapping,
    [string]$PolicyAsJson,
    [switch]$GenerateAutomationScripts
)

# Import common functionality
. (Join-Path $PSScriptRoot "Common.ps1")

function Get-RoleMapping {
    <#
    .SYNOPSIS
    Loads the role mapping configuration from RoleMapping.json
    
    .DESCRIPTION
    Reads and parses the RoleMapping.json file that contains mappings from 
    Key Vault access policy permissions to Azure RBAC built-in roles.
    
    .OUTPUTS
    Hashtable containing the role mappings and role definitions
    #>
    [CmdletBinding()]
    param()
    
    try {
        $mappingPath = Join-Path $PSScriptRoot "RoleMapping.json"
        
        if (-not (Test-Path $mappingPath)) {
            throw "RoleMapping.json not found at: $mappingPath"
        }
        
        $content = Get-Content -Path $mappingPath -Raw -ErrorAction Stop
        $mappingObject = ConvertFrom-Json -InputObject $content -ErrorAction Stop
        $mapping = ConvertTo-Hashtable $mappingObject
        
        if (-not $mapping) {
            throw "RoleMapping.json contains no data or is invalid"
        }
        
        # Validate required sections
        if (-not $mapping.roleDefinitions) {
            throw "RoleMapping.json missing required 'roleDefinitions' section"
        }
        
        Write-Verbose "Successfully loaded role mapping with $($mapping.Keys.Count) sections and $($mapping.roleDefinitions.Keys.Count) role definitions"
        return $mapping
    }
    catch {
        Write-Error "Failed to load role mapping: $($_.Exception.Message)"
        throw
    }
}

function Test-ScopeParameters {
    <#
    .SYNOPSIS
    Validates that exactly one scope parameter is provided
    
    .PARAMETER VaultName
    Array of vault names
    
    .PARAMETER ResourceGroup
    Resource group name
    
    .PARAMETER SubscriptionId
    Subscription ID
    #>
    [CmdletBinding()]
    param(
        [string[]]$VaultName,
        [string]$ResourceGroup,
        [string]$SubscriptionId
    )
    
    $scopeParams = @($VaultName, $ResourceGroup, $SubscriptionId)
    $scopeParamsProvided = ($scopeParams | Where-Object { $_ }).Count
    
    if ($scopeParamsProvided -eq 0) {
        throw "Must specify exactly one of: VaultName, ResourceGroup, or SubscriptionId"
    }
    
    if ($scopeParamsProvided -gt 1) {
        throw "Cannot specify more than one scope parameter"
    }
}


function Get-KeyVaults {
    <#
    .SYNOPSIS
    Discovers Key Vaults using Azure Resource Graph
    
    .DESCRIPTION
    Finds Key Vaults using Azure Resource Graph queries.    
    .PARAMETER VaultName
    Specific vault names to target
    
    .PARAMETER ResourceGroup
    Resource group to scan
    
    .PARAMETER SubscriptionId
    Subscription to scan
    
    .PARAMETER TagFilter
    Hashtable of tags to filter by
    
    .OUTPUTS
    Array of vault objects
    #>
    [CmdletBinding()]
    param(
        [string[]]$VaultName,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [hashtable]$TagFilter
    )
    
    # Use Azure Resource Graph for vault discovery
    $vaults = Get-KeyVaultsViaARG -VaultName $VaultName -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -TagFilter $TagFilter
    Write-Verbose "Successfully discovered $($vaults.Count) vaults using Azure Resource Graph"
    
    foreach ($vault in $vaults) {
        $resourceId = "/subscriptions/$($vault.subscriptionId)/resourceGroups/$($vault.resourceGroup)/providers/Microsoft.KeyVault/vaults/$($vault.name)"
        $vault | Add-Member -NotePropertyName "ResourceId" -NotePropertyValue $resourceId -Force
    }
    
    Write-Verbose "Successfully processed $($vaults.Count) vault objects"
    return $vaults
}

function Get-KeyVaultsViaARG {
    [CmdletBinding()]
    param(
        [string[]]$VaultName,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [hashtable]$TagFilter
    )
    
    # Build the KQL query
    $query = 'resources | where type == "microsoft.keyvault/vaults"'
    
    # Add scope filters
    if ($VaultName) {
        $nameFilter = ($VaultName | ForEach-Object { "'$_'" }) -join ','
        $query += " | where name in ($nameFilter)"
    }
    
    if ($ResourceGroup) {
        $query += " | where resourceGroup == '$ResourceGroup'"
    }
    
    # Add tag filters
    if ($TagFilter) {
        foreach ($tag in $TagFilter.GetEnumerator()) {
            $query += " | where tags['$($tag.Key)'] == '$($tag.Value)'"
        }
    }
    
    # Count total vaults matching scope filters (before RBAC exclusion)
    $totalQuery = $query + ' | project id'
    $totalParams = @{ Query = $totalQuery; First = 1000 }
    if ($SubscriptionId) { $totalParams.Subscription = $SubscriptionId }
    $totalResult = Search-AzGraph @totalParams
    $totalCount = @($totalResult).Count

    # Now filter out RBAC-enabled vaults
    $query += ' | where properties.enableRbacAuthorization != true'
    $query += ' | project id, name, resourceGroup, subscriptionId, location, tags, properties'
    
    Write-Verbose "ARG Query: $query"
    
    # Execute the query
    $searchParams = @{
        Query = $query
        First = 1000
    }
    
    if ($SubscriptionId) {
        $searchParams.Subscription = $SubscriptionId
    }
    
    $result = Search-AzGraph @searchParams
    $filteredCount = @($result).Count

    $rbacSkipped = $totalCount - $filteredCount
    if ($rbacSkipped -gt 0) {
        Write-Host "Skipped $rbacSkipped vault(s) already using RBAC authorization (out of $totalCount total)" -ForegroundColor Yellow
        Write-AuditLog -Level "Info" -Message "Skipped $rbacSkipped vault(s) already using RBAC authorization" -Category "VaultDiscovery" -NoConsole -Details @{
            TotalVaults = $totalCount
            RbacVaultsSkipped = $rbacSkipped
            VaultsToAnalyze = $filteredCount
        }
    }

    return $result
}


function Get-VaultAccessPolicies {
    <#
    .SYNOPSIS
    Retrieves access policies from a Key Vault with enhanced error handling
    
    .PARAMETER VaultName
    Name of the Key Vault
    
    .PARAMETER ResourceGroupName
    Resource group containing the vault
    
    .PARAMETER SubscriptionId
    Subscription ID (optional, for better error context)
    
    .PARAMETER VaultCounter
    Current vault number being processed (for progress display)
    
    .PARAMETER TotalVaults
    Total number of vaults being processed (for progress display)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultName,
        
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [string]$SubscriptionId,
        
        [int]$VaultCounter = 0,
        
        [int]$TotalVaults = 0
    )
    
    # Input validation
    if ([string]::IsNullOrWhiteSpace($VaultName)) {
        $errorMsg = "VaultName parameter is null or empty. This indicates a vault discovery issue."
        Write-Error $errorMsg
        Write-AuditLog -Level "Error" -Message $errorMsg -Category "VaultAccess" -Details @{
            VaultName         = $VaultName
            ResourceGroupName = $ResourceGroupName
            SubscriptionId    = $SubscriptionId
        }
        throw $errorMsg
    }
    
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        $errorMsg = "ResourceGroupName parameter is null or empty for vault '$VaultName'"
        Write-Error $errorMsg
        Write-AuditLog -Level "Error" -Message $errorMsg -Category "VaultAccess" -VaultName $VaultName
        throw $errorMsg
    }
    
    try {
        Write-Verbose "Retrieving vault information for '$VaultName' in resource group '$ResourceGroupName'"
        
        # Build parameters for Get-AzKeyVault
        $getVaultParams = @{
            VaultName         = $VaultName
            ResourceGroupName = $ResourceGroupName
        }
        
        # Add subscription context if provided
        if ($SubscriptionId) {
            $getVaultParams.SubscriptionId = $SubscriptionId
        }
        
        $vault = Get-AzKeyVault @getVaultParams -ErrorAction Stop
        
        if (-not $vault) {
            $errorMsg = "Vault '$VaultName' not found in resource group '$ResourceGroupName'"
            Write-Warning $errorMsg
            Write-AuditLog -Level "Warning" -Message $errorMsg -Category "VaultAccess" -VaultName $VaultName -Details @{
                ResourceGroupName = $ResourceGroupName
                SubscriptionId    = $SubscriptionId
            }
            return $null
        }
        
        # Check if vault is already using RBAC
        if ($vault.EnableRbacAuthorization) {
            $progressPrefix = if ($VaultCounter -gt 0 -and $TotalVaults -gt 0) { "[Vault $VaultCounter of $TotalVaults] " } else { "" }
            $infoMsg = "${progressPrefix}Vault '$VaultName' is already using RBAC authorization - skipping access policy analysis"
            Write-Verbose $infoMsg
            Write-AuditLog -Level "Info" -Message $infoMsg -Category "VaultAccess" -VaultName $VaultName
            return $null
        }
        
        # Check if vault has access policies
        if (-not $vault.AccessPolicies -or $vault.AccessPolicies.Count -eq 0) {
            $progressPrefix = if ($VaultCounter -gt 0 -and $TotalVaults -gt 0) { "[Vault $VaultCounter of $TotalVaults] " } else { "" }
            $infoMsg = "${progressPrefix}Vault '$VaultName' has no access policies to analyze"
            Write-Verbose $infoMsg
            Write-AuditLog -Level "Info" -Message $infoMsg -Category "VaultAccess" -VaultName $VaultName
            return @{ NoAccessPolicies = $true }
        }
        
        $progressPrefix = if ($VaultCounter -gt 0 -and $TotalVaults -gt 0) { "[Vault $VaultCounter of $TotalVaults] " } else { "" }
        Write-Verbose "${progressPrefix}Successfully retrieved $($vault.AccessPolicies.Count) access policies for vault '$VaultName'"
        Write-AuditLog -Level "Info" -Message "${progressPrefix}Access policies retrieved successfully" -Category "VaultAccess" -VaultName $VaultName -NoConsole -Details @{
            AccessPolicyCount       = $vault.AccessPolicies.Count
            EnableRbacAuthorization = $vault.EnableRbacAuthorization
        }
        
        return $vault.AccessPolicies
    }
    catch {
        $errorMsg = "Failed to get access policies for vault '$VaultName' in resource group '$ResourceGroupName': $($_.Exception.Message)"
        Write-Warning $errorMsg
        Write-AuditLog -Level "Error" -Message $errorMsg -Category "VaultAccess" -VaultName $VaultName -Details @{
            ResourceGroupName = $ResourceGroupName
            SubscriptionId    = $SubscriptionId
            ErrorType         = $_.Exception.GetType().Name
            FullException     = $_.Exception.ToString()
        }
        
        # Check for specific error types to provide better guidance
        if ($_.Exception.Message -like "*not found*" -or $_.Exception.Message -like "*does not exist*") {
            Write-Warning "Vault '$VaultName' may not exist in resource group '$ResourceGroupName' or you may not have access to it"
        }
        elseif ($_.Exception.Message -like "*authorization*" -or $_.Exception.Message -like "*permission*") {
            Write-Warning "You may not have sufficient permissions to access vault '$VaultName'. Ensure you have 'Key Vault Reader' role or equivalent."
        }
        
        return $null
    }
}

function Test-AdministratorMode {
    <#
    .SYNOPSIS
    Tests whether Administrator mode should be used based on exact permission matching
    
    .DESCRIPTION
    Administrator role is ONLY assigned when it grants no additional permissions beyond what
    the user currently has. This prevents privilege escalation by ensuring the Administrator
    role never grants new permissions the user didn't already have.
    
    SECURITY DESIGN: Zero privilege escalation - Administrator only assigned if it grants same or fewer permissions.
    
    WHY THIS IS SECURE:
    - Administrator is essentially a "convenience role" that combines multiple smaller roles
    - It should only be used when the user already has equivalent permissions through other roles
    - Users get individual roles that match their exact needs (principle of least privilege)
    - This prevents accidental privilege escalation during RBAC migration
    
    .PARAMETER RecommendedRoles
    Array of roles recommended based on individual object type analysis
    
    .PARAMETER ObjectTypesWithPermissions
    Array of object types (secrets, keys, certificates) that the user has permissions for
    
    .PARAMETER PermissionCounts
    Hashtable with count of permissions per object type
    
    .PARAMETER RoleMapping
    The role mapping configuration
    
    .PARAMETER VaultName
    Vault name for audit logging
    
    .PARAMETER PrincipalId
    Principal ID for audit logging
    #>
    [CmdletBinding()]
    param(
        [string[]]$RecommendedRoles,
        [string[]]$ObjectTypesWithPermissions,
        [hashtable]$PermissionCounts,
        [hashtable]$RoleMapping,
        [string]$VaultName,
        [string]$PrincipalId
    )
    
    # Return original roles if Administrator mode not configured or no rolePermissions defined
    if (-not $RoleMapping.administratorModeMapping -or -not $RoleMapping.rolePermissions) {
        return $RecommendedRoles
    }
    
    $adminConfig = $RoleMapping.administratorModeMapping
    $adminRoleName = "Key Vault Administrator"
    
    # Check if Administrator role permissions are defined
    if (-not $RoleMapping.rolePermissions[$adminRoleName]) {
        Write-AuditLog -Level "Warning" -Message "Administrator role permissions not defined in rolePermissions" -VaultName $VaultName -PrincipalId $PrincipalId -Category "AdministratorMode"
        return $RecommendedRoles
    }
    
    # SECURITY REQUIREMENT: User must have permissions to ALL required object types
    $requiredObjectTypes = $adminConfig.requiredObjectTypes
    if (-not $requiredObjectTypes) {
        $requiredObjectTypes = @("secrets", "keys", "certificates")
    }
    
    $missingObjectTypes = @()
    foreach ($requiredType in $requiredObjectTypes) {
        if ($requiredType -notin $ObjectTypesWithPermissions) {
            $missingObjectTypes += $requiredType
        }
    }
    
    if ($missingObjectTypes.Count -gt 0) {
        Write-AuditLog -Level "Decision" -Message "Administrator denied: User lacks permissions to required object types" -VaultName $VaultName -PrincipalId $PrincipalId -Category "AdministratorMode" -Details @{
            MissingObjectTypes  = $missingObjectTypes
            UserObjectTypes     = $ObjectTypesWithPermissions
            RequiredObjectTypes = $requiredObjectTypes
            SecurityReason      = "Prevents privilege escalation - Administrator requires access to ALL object types"
        }
        return $RecommendedRoles
    }
    
    # Get user's effective permission set by combining permissions from recommended roles
    $userEffectivePermissions = @{
        secrets      = @()
        keys         = @()
        certificates = @()
    }
    
    foreach ($role in $RecommendedRoles) {
        if ($RoleMapping.rolePermissions[$role]) {
            $objectTypes = @('secrets', 'keys', 'certificates')
            foreach ($objectType in $objectTypes) {
                if ($RoleMapping.rolePermissions[$role][$objectType]) {
                    $userEffectivePermissions[$objectType] = $userEffectivePermissions[$objectType] + $RoleMapping.rolePermissions[$role][$objectType]
                }
            }
        }
    }
    
    # Remove duplicates from user permissions
    foreach ($objectType in @('secrets', 'keys', 'certificates')) {
        $userEffectivePermissions[$objectType] = $userEffectivePermissions[$objectType] | Sort-Object -Unique
    }
    
    # Get Administrator role permissions
    $adminPermissions = $RoleMapping.rolePermissions[$adminRoleName]
    
    # CRITICAL SECURITY CHECK: Verify Administrator role would not grant any new permissions
    $privilegeEscalationDetected = $false
    $newPermissions = @{}
    
    foreach ($objectType in @('secrets', 'keys', 'certificates')) {
        if ($adminPermissions[$objectType]) {
            $newPermsForType = @()
            foreach ($permission in $adminPermissions[$objectType]) {
                if ($permission -notin $userEffectivePermissions[$objectType]) {
                    $newPermsForType += $permission
                    $privilegeEscalationDetected = $true
                }
            }
            if ($newPermsForType.Count -gt 0) {
                $newPermissions[$objectType] = $newPermsForType
            }
        }
    }
    
    if ($privilegeEscalationDetected) {
        Write-AuditLog -Level "Decision" -Message "Administrator denied: Would grant new permissions (privilege escalation)" -VaultName $VaultName -PrincipalId $PrincipalId -Category "AdministratorMode" -Details @{
            SecurityReason           = "Administrator role would grant permissions user does not currently have"
            NewPermissions           = $newPermissions
            UserEffectivePermissions = $userEffectivePermissions
            AdminPermissions         = $adminPermissions
            RecommendedRoles         = $RecommendedRoles
        }
        return $RecommendedRoles
    }
    
    # Administrator role is safe - it grants no new permissions
    Write-AuditLog -Level "Decision" -Message "Administrator granted: No privilege escalation detected" -VaultName $VaultName -PrincipalId $PrincipalId -Category "AdministratorMode" -Details @{
        SecurityReason           = "Administrator role grants no additional permissions beyond user's current set"
        UserEffectivePermissions = $userEffectivePermissions
        AdminPermissions         = $adminPermissions
        OriginalRoles            = $RecommendedRoles
    }
    
    Write-PermissionMappingDecision -VaultName $VaultName -PrincipalId $PrincipalId -PermissionType "multi-object" -InputPermissions @() -MappedRole $adminRoleName -DecisionReason "Exact permission match - no privilege escalation"
    
    return @($adminRoleName)
}

function ConvertTo-RbacRole {
    <#
    .SYNOPSIS
    Maps Key Vault access policy permissions to RBAC roles

    .PARAMETER AccessPolicy
    The access policy object to analyze

    .PARAMETER RoleMapping
    The role mapping hashtable

    .PARAMETER VaultName
    The name of the vault being analyzed (for audit logging)
    #>
    [CmdletBinding()]
    param(
        [object]$AccessPolicy,
        [hashtable]$RoleMapping,
        [string]$VaultName = "Unknown"
    )

    $recommendedRoles = @()
    $warnings = @()
    $objectTypesWithPermissions = @()
    $permissionCounts = @{}

    # Compound identity logic
    if ($AccessPolicy.PSObject.Properties["ApplicationId"] -and $RoleMapping.compoundIdentities) {
        $compound = $RoleMapping.compoundIdentities | Where-Object { $_.appId -eq $AccessPolicy.ApplicationId }
        if ($compound) {
            # Gather permissions
            $hasSecrets = $AccessPolicy.PermissionsToSecrets -and $AccessPolicy.PermissionsToSecrets.Count -gt 0
            $hasKeys = $AccessPolicy.PermissionsToKeys -and $AccessPolicy.PermissionsToKeys.Count -gt 0
            $hasCerts = $AccessPolicy.PermissionsToCertificates -and $AccessPolicy.PermissionsToCertificates.Count -gt 0

            $allowed = $false
            foreach ($allowedSet in $compound.allowedPermissions) {
                if ($allowedSet.secrets -and $hasSecrets -and -not $hasKeys -and -not $hasCerts) {
                    $onlyGet = @($AccessPolicy.PermissionsToSecrets | ForEach-Object { $_.ToLower() }) -eq $allowedSet.secrets
                    if ($onlyGet -or (@($AccessPolicy.PermissionsToSecrets).Count -eq 1 -and $AccessPolicy.PermissionsToSecrets[0].ToLower() -eq $allowedSet.secrets[0])) {
                        $allowed = $true
                        break
                    }
                }
                if ($allowedSet.certificates -and $hasCerts -and -not $hasKeys -and -not $hasSecrets) {
                    $onlyGet = @($AccessPolicy.PermissionsToCertificates | ForEach-Object { $_.ToLower() }) -eq $allowedSet.certificates
                    if ($onlyGet -or (@($AccessPolicy.PermissionsToCertificates).Count -eq 1 -and $AccessPolicy.PermissionsToCertificates[0].ToLower() -eq $allowedSet.certificates[0])) {
                        $allowed = $true
                        break
                    }
                }
            }
            $roleName = $compound.role
            if ($allowed) {
                $recommendedRoles = @($roleName)
            }
            else {
                $recommendedRoles = @($roleName)
                $warnings += $compound.warning
            }
            return @{
                Principal        = $AccessPolicy.ObjectId
                RecommendedRoles = $recommendedRoles
                Warnings         = $warnings
            }
        }
    }

    # Analyze secrets permissions
    if ($AccessPolicy.PermissionsToSecrets) {
        $objectTypesWithPermissions += "secrets"
        $permissionCounts["secrets"] = $AccessPolicy.PermissionsToSecrets.Count
        $normalizedSecrets = $AccessPolicy.PermissionsToSecrets | ForEach-Object { $_.ToLower() }
        $secretsRole = Get-MinimalRole -Permissions $normalizedSecrets -PermissionType "secrets" -RoleMapping $RoleMapping -VaultName $VaultName -PrincipalId $AccessPolicy.ObjectId
        if ($secretsRole.Role) {
            $recommendedRoles += $secretsRole.Role
            if ($secretsRole.Warning) {
                $warnings += $secretsRole.Warning
            }
        }
    }

    # Analyze keys permissions
    if ($AccessPolicy.PermissionsToKeys) {
        $objectTypesWithPermissions += "keys"
        $permissionCounts["keys"] = $AccessPolicy.PermissionsToKeys.Count
        $normalizedKeys = $AccessPolicy.PermissionsToKeys | ForEach-Object { $_.ToLower() }
        $keysRole = Get-MinimalRole -Permissions $normalizedKeys -PermissionType "keys" -RoleMapping $RoleMapping -VaultName $VaultName -PrincipalId $AccessPolicy.ObjectId
        if ($keysRole.Role) {
            $recommendedRoles += $keysRole.Role
            if ($keysRole.Warning) {
                $warnings += $keysRole.Warning
            }
        }
    }

    # Analyze certificates permissions
    if ($AccessPolicy.PermissionsToCertificates) {
        $objectTypesWithPermissions += "certificates"
        $permissionCounts["certificates"] = $AccessPolicy.PermissionsToCertificates.Count
        $normalizedCerts = $AccessPolicy.PermissionsToCertificates | ForEach-Object { $_.ToLower() }
        $certsRole = Get-MinimalRole -Permissions $normalizedCerts -PermissionType "certificates" -RoleMapping $RoleMapping -VaultName $VaultName -PrincipalId $AccessPolicy.ObjectId
        if ($certsRole.Role) {
            $recommendedRoles += $certsRole.Role
            if ($certsRole.Warning) {
                $warnings += $certsRole.Warning
            }
        }
    }

    # Analyze storage permissions (deprecated Managed Storage)
    if ($AccessPolicy.PSObject.Properties["PermissionsToStorage"] -and $AccessPolicy.PermissionsToStorage -and $AccessPolicy.PermissionsToStorage.Count -gt 0) {
        $normalizedStorage = $AccessPolicy.PermissionsToStorage | ForEach-Object { $_.ToLower() }
        $storagePermsDisplay = ($normalizedStorage -join ', ')
        $warnings += "Principal has deprecated Managed Storage permissions ($storagePermsDisplay). Mapping to Key Vault Administrator is a significant privilege escalation. Consider using Azure Storage RBAC roles on the storage account instead."
        Write-Warning "Vault '$VaultName', Principal '$($AccessPolicy.ObjectId)': Deprecated Managed Storage permissions ($storagePermsDisplay) mapped to Key Vault Administrator. This is a significant privilege escalation. Consider Azure Storage RBAC instead."
        if ('Key Vault Administrator' -notin $recommendedRoles) {
            $recommendedRoles += 'Key Vault Administrator'
        }
        $objectTypesWithPermissions += "storage"
        $permissionCounts["storage"] = $AccessPolicy.PermissionsToStorage.Count
    }

    # Check for Administrator mode (only if user has permissions across multiple object types)
    $finalRoles = Test-AdministratorMode -RecommendedRoles $recommendedRoles -ObjectTypesWithPermissions $objectTypesWithPermissions -PermissionCounts $permissionCounts -RoleMapping $RoleMapping -VaultName $VaultName -PrincipalId $AccessPolicy.ObjectId

    $result = @{
        Principal        = $AccessPolicy.ObjectId
        RecommendedRoles = $finalRoles | Sort-Object -Unique
    }
    if ($warnings.Count -gt 0) {
        $result.Warnings = $warnings
    }
    # Remove Warnings property if it is null, empty, or contains only null/empty values
    if ($result.ContainsKey('Warnings')) {
        $w = $result.Warnings
        $isEmpty = $false
        if ($null -eq $w) { $isEmpty = $true }
        elseif ($w -is [System.Array] -and $w.Count -eq 0) { $isEmpty = $true }
        elseif ($w -is [System.Array] -and ($w | Where-Object { $_ -ne $null -and $_ -ne "" }).Count -eq 0) { $isEmpty = $true }
        elseif ($w -is [string] -and $w -eq "") { $isEmpty = $true }
        if ($isEmpty) { $result.Remove('Warnings') }
    }
    return $result
}

function Get-MinimalRole {
    <#
    .SYNOPSIS
    Determines the minimal RBAC role needed for given permissions with administrator mode support
    #>
    [CmdletBinding()]
    param(
        [string[]]$Permissions,
        [string]$PermissionType,
        [hashtable]$RoleMapping,
        [string]$VaultName = "Unknown",
        [string]$PrincipalId = "Unknown"
    )
    
    # Use cached permission lookup if available, otherwise use direct mapping
    $typeMapping = if ($script:MigrationContext.PermissionRoleLookup -and $script:MigrationContext.PermissionRoleLookup[$PermissionType]) {
        $script:MigrationContext.PermissionRoleLookup[$PermissionType]
    } else {
        $RoleMapping[$PermissionType]
    }
    
    if (-not $typeMapping) {
        $warningText = "No mapping found for permission type: $PermissionType"
        Write-AuditLog -Level "Warning" -Message $warningText -VaultName $VaultName -PrincipalId $PrincipalId -Category "PermissionMapping"
        return @{ Role = $null; Warning = $warningText }
    }
    
    $requiredRoles = @()
    $unmappedPermissions = @()
    $warnings = @() # Use an array to accumulate warnings
    
    foreach ($permission in $Permissions) {
        $permLower = $permission.ToLower()
        if ($typeMapping.ContainsKey($permLower)) {
            $requiredRoles += $typeMapping[$permLower]
        }
        else {
            $unmappedPermissions += $permission
        }
    }
    
    # Track unmapped permissions for audit
    if ($unmappedPermissions.Count -gt 0) {
        $warningText = "Unmapped permissions for $PermissionType : $($unmappedPermissions -join ', ')"
        $warnings += $warningText
        Write-Warning $warningText
        Write-AuditLog -Level "Warning" -Message $warningText -VaultName $VaultName -PrincipalId $PrincipalId -Category "PermissionMapping" -Details @{
            UnmappedPermissions = $unmappedPermissions
            PermissionType      = $PermissionType
        }
        Update-MigrationMetrics -MetricType "WarningGenerated"
    }
    
    # Determine minimal role using weight-based hierarchy
    $uniqueRoles = @()
    foreach ($role in $requiredRoles) {
        if ($role -notin $uniqueRoles) {
            $uniqueRoles += $role
        }
    }
    
    if ($uniqueRoles.Count -eq 0) {
        $warningText = "No roles mapped for permissions: $($Permissions -join ', ')"
        $warnings += $warningText
        Write-AuditLog -Level "Warning" -Message $warningText -VaultName $VaultName -PrincipalId $PrincipalId -Category "PermissionMapping"
        $result = @{ Role = $null }
        if ($warnings.Count -gt 0) {
            $result.Warning = ($warnings -join "; ")
        }
        return $result
    }
    
    # If only one role, return it
    if ($uniqueRoles.Count -eq 1) {
        $selectedRole = $uniqueRoles[0]
        Write-PermissionMappingDecision -VaultName $VaultName -PrincipalId $PrincipalId -PermissionType $PermissionType -InputPermissions $Permissions -MappedRole $selectedRole -DecisionReason "Single role mapping" -UnmappedPermissions $unmappedPermissions
        $result = @{ Role = $selectedRole }
        if ($warnings.Count -gt 0) {
            $result.Warning = ($warnings -join "; ")
        }
        return $result
    }
    
    # For multiple roles, choose the one with highest weight (most permissive)
    $roleWeights = @{}
    foreach ($role in $uniqueRoles) {
        if ($RoleMapping.roleDefinitions[$role] -and $RoleMapping.roleDefinitions[$role].weight) {
            $roleWeights[$role] = $RoleMapping.roleDefinitions[$role].weight
        }
        else {
            # Default weight for roles without explicit weight
            $roleWeights[$role] = 15
            Write-Warning "Role '$role' does not have a weight defined, using default weight 15"
            Write-AuditLog -Level "Warning" -Message "Role missing weight definition" -VaultName $VaultName -PrincipalId $PrincipalId -Category "Configuration" -Details @{
                Role          = $role
                DefaultWeight = 15
            }
        }
    }
    
    # Sort by weight descending and pick the highest (most permissive)
    $finalRole = ($roleWeights.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key

    $decisionReason = "Weight-based selection"
    if ($uniqueRoles.Count -gt 1) {
        $decisionReason = "Multiple roles, selected highest weight: $($roleWeights[$finalRole])"
    }

    Write-PermissionMappingDecision -VaultName $VaultName -PrincipalId $PrincipalId -PermissionType $PermissionType -InputPermissions $Permissions -MappedRole $finalRole -DecisionReason $decisionReason -UnmappedPermissions $unmappedPermissions -RoleWeights $roleWeights

    $result = @{ Role = $finalRole }
    if ($warnings.Count -gt 0) {
        $result.Warning = ($warnings -join "; ")
    }
    return $result
}

function Get-BulkRoleAssignments {
    <#
    .SYNOPSIS
    Retrieves all Key Vault role assignments for a subscription in a single API call
    
    .DESCRIPTION
    Optimizes role assignment queries by fetching all assignments at subscription level
    and building a lookup hashtable for O(1) access during analysis.
    
    .PARAMETER SubscriptionId
    The subscription ID to query for role assignments
    
    .OUTPUTS
    Hashtable with keys in format "scope|principalId" pointing to assignment arrays
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )
    
    Write-Verbose "Fetching all Key Vault role assignments for subscription $SubscriptionId"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Single API call for entire subscription
        $rawAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop
        $script:LastTotalAssignmentCount = @($rawAssignments).Count

        $allAssignments = $rawAssignments |
            Where-Object { $_.Scope -like "*/providers/Microsoft.KeyVault/vaults/*" }
        
        # Build O(1) lookup hashtable: "scope|principalId" -> assignment array
        $lookup = @{}
        foreach ($assignment in $allAssignments) {
            $key = "$($assignment.Scope)|$($assignment.ObjectId)"
            if (-not $lookup.ContainsKey($key)) {
                $lookup[$key] = @()
            }
            $lookup[$key] += $assignment
        }
        
        $stopwatch.Stop()
        Write-Verbose "Cached $($allAssignments.Count) role assignments in $($stopwatch.ElapsedMilliseconds)ms for O(1) lookup"
        Write-AuditLog -Level "Info" -Message "Bulk role assignments cached" -NoConsole -Details @{
            SubscriptionId = $SubscriptionId
            TotalAssignments = $allAssignments.Count
            UniqueKeys = $lookup.Keys.Count
            ElapsedMs = $stopwatch.ElapsedMilliseconds
        } -Category "Performance"
        
        return $lookup
    }
    catch {
        $stopwatch.Stop()
        Write-Warning "Failed to retrieve bulk role assignments for subscription $SubscriptionId : $($_.Exception.Message)"
        Write-AuditLog -Level "Error" -Message "Bulk role assignment query failed" -Details @{
            SubscriptionId = $SubscriptionId
            Error = $_.Exception.Message
            ElapsedMs = $stopwatch.ElapsedMilliseconds
        } -Category "Performance"
        return @{}
    }
}

function Get-ExistingRoleAssignments {
    <#
    .SYNOPSIS
    Checks for existing RBAC role assignments on a vault for the ObjectId,
    including assignments inherited through group membership.
    Enhanced with bulk role assignment cache support for performance.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultResourceId,
        [string]$PrincipalId,
        [string]$ApplicationId = $null,
        [hashtable]$RoleAssignmentCache = $null,
        [hashtable]$GroupMembershipCache = $null
    )
    
    $allAssignments = @()
    
    try {
        # Use cached lookup if available (optimized path)
        if ($RoleAssignmentCache) {
            # Direct assignments
            $lookupKey = "$VaultResourceId|$PrincipalId"
            if ($RoleAssignmentCache.ContainsKey($lookupKey)) {
                $directAssignments = $RoleAssignmentCache[$lookupKey]
                foreach ($assignment in $directAssignments) {
                    $allAssignments += @{
                        RoleDefinitionName = $assignment.RoleDefinitionName
                        AssignmentType     = "Direct"
                        Source             = $PrincipalId
                    }
                }
                Write-Verbose "Found $($directAssignments.Count) cached direct role assignments for principal $PrincipalId"
            }

            # Group-inherited assignments
            if ($GroupMembershipCache -and $GroupMembershipCache.ContainsKey($PrincipalId)) {
                $groupIds = $GroupMembershipCache[$PrincipalId]
                foreach ($groupId in $groupIds) {
                    $groupKey = "$VaultResourceId|$groupId"
                    if ($RoleAssignmentCache.ContainsKey($groupKey)) {
                        $groupAssignments = $RoleAssignmentCache[$groupKey]
                        foreach ($assignment in $groupAssignments) {
                            $allAssignments += @{
                                RoleDefinitionName = $assignment.RoleDefinitionName
                                AssignmentType     = "GroupInherited"
                                Source             = $groupId
                            }
                        }
                        Write-Verbose "Found $($groupAssignments.Count) group-inherited role assignments for principal $PrincipalId via group $groupId"
                    }
                }
            }
        } else {
            # Use individual API call when cache not available
            Write-Verbose "Using individual API call for role assignments (cache not available)"
            $directAssignments = Get-AzRoleAssignment -Scope $VaultResourceId -ObjectId $PrincipalId -ErrorAction SilentlyContinue
            foreach ($assignment in $directAssignments) {
                $allAssignments += @{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    AssignmentType     = "Direct"
                    Source             = $PrincipalId
                }
            }

            # Group-inherited assignments (non-cached path)
            if ($GroupMembershipCache -and $GroupMembershipCache.ContainsKey($PrincipalId)) {
                $groupIds = $GroupMembershipCache[$PrincipalId]
                foreach ($groupId in $groupIds) {
                    $groupAssignments = Get-AzRoleAssignment -Scope $VaultResourceId -ObjectId $groupId -ErrorAction SilentlyContinue
                    foreach ($assignment in $groupAssignments) {
                        $allAssignments += @{
                            RoleDefinitionName = $assignment.RoleDefinitionName
                            AssignmentType     = "GroupInherited"
                            Source             = $groupId
                        }
                    }
                }
            }
        }
        
        return $allAssignments
    }
    catch {
        Write-Warning "Could not retrieve role assignments for principal $PrincipalId on vault $VaultResourceId : $($_.Exception.Message)"
        return @()
    }
}

#region Vault Result Helpers

function New-VaultSkipResult {
    [CmdletBinding()]
    param([object]$Vault, [string]$SkipReason)
    return @{
        VaultName          = $Vault.name
        ResourceGroup      = $Vault.resourceGroup
        SubscriptionId     = $Vault.subscriptionId
        Status             = "Skipped - $SkipReason"
        SkipReason         = $SkipReason
        Principals         = @()
        Timestamp          = Get-Date
    }
}

function New-VaultReadyResult {
    [CmdletBinding()]
    param([object]$Vault, [string]$SkipReason = "No access policies")
    return @{
        VaultName          = $Vault.name
        ResourceGroup      = $Vault.resourceGroup
        SubscriptionId     = $Vault.subscriptionId
        Status             = "Analyzed"
        RbacMigrationReady = $true
        SkipReason         = $SkipReason
        Principals         = @()
        Timestamp          = Get-Date
    }
}

function New-VaultFailResult {
    [CmdletBinding()]
    param([object]$Vault, [string]$ErrorMessage)
    return @{
        VaultName      = if ($Vault.name) { $Vault.name } else { "Unknown" }
        ResourceGroup  = if ($Vault.resourceGroup) { $Vault.resourceGroup } else { "Unknown" }
        SubscriptionId = if ($Vault.subscriptionId) { $Vault.subscriptionId } else { "Unknown" }
        Status         = "Failed"
        Error          = $ErrorMessage
        Timestamp      = Get-Date
    }
}

function Get-VaultSkipReason {
    <#
    .SYNOPSIS
    Determines why access policies are null for a vault
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$ResourceGroupName,
        [string]$SubscriptionId
    )
    $vaultObj = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if ($vaultObj -and $vaultObj.EnableRbacAuthorization) {
        return "Already RBAC"
    }
    elseif ($vaultObj -and (!$vaultObj.AccessPolicies -or $vaultObj.AccessPolicies.Count -eq 0)) {
        return "No access policies"
    }
    return "Unknown skip reason"
}

#endregion

#region Single Vault Analysis

function Invoke-SingleVaultAnalysis {
    <#
    .SYNOPSIS
    Analyzes a single vault's access policies and maps them to RBAC roles.
    Shared implementation used by both optimized and sequential paths.

    .PARAMETER Vault
    Vault object with name, resourceGroup, subscriptionId properties

    .PARAMETER AccessPolicies
    Pre-fetched access policies (if null, fetched live)

    .PARAMETER RoleMapping
    Role mapping hashtable

    .PARAMETER RoleAssignmentCache
    Optional bulk role assignment cache for O(1) lookups

    .PARAMETER GroupMembershipCache
    Optional group membership cache

    .PARAMETER VaultCounter
    Current vault number (for progress display)

    .PARAMETER TotalVaults
    Total vault count (for progress display)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Vault,
        [object]$AccessPolicies = $null,
        [Parameter(Mandatory)]
        [hashtable]$RoleMapping,
        [hashtable]$RoleAssignmentCache = $null,
        [hashtable]$GroupMembershipCache = $null,
        [int]$VaultCounter = 0,
        [int]$TotalVaults = 0
    )

    # Validate vault object
    if (-not $Vault.name -or -not $Vault.resourceGroup -or -not $Vault.subscriptionId) {
        Write-Warning "Skipping vault due to missing required properties. Available properties: $($Vault.PSObject.Properties.Name -join ', ')"
        return New-VaultFailResult -Vault $Vault -ErrorMessage "Invalid vault object - missing required properties"
    }

    if ($VaultCounter -gt 0 -and $TotalVaults -gt 0) {
        Write-Host "[$VaultCounter/$TotalVaults] $($Vault.name)" -ForegroundColor Cyan
    }

    # Fetch access policies if not pre-cached
    if ($null -eq $AccessPolicies) {
        $AccessPolicies = Get-VaultAccessPolicies -VaultName $Vault.name -ResourceGroupName $Vault.resourceGroup -SubscriptionId $Vault.subscriptionId -VaultCounter $VaultCounter -TotalVaults $TotalVaults
    }

    # Handle no-access-policies indicator
    if ($AccessPolicies -is [hashtable] -and $AccessPolicies.NoAccessPolicies) {
        Write-Verbose "Vault '$($Vault.name)' has no access policies - marking as ready for RBAC migration"
        return New-VaultReadyResult -Vault $Vault
    }

    # Handle null access policies (vault not found, already RBAC, etc.)
    if (-not $AccessPolicies) {
        $skipReason = Get-VaultSkipReason -VaultName $Vault.name -ResourceGroupName $Vault.resourceGroup -SubscriptionId $Vault.subscriptionId
        if ($skipReason -eq "No access policies") {
            Write-Verbose "Vault '$($Vault.name)' has no access policies - marking as ready for RBAC migration"
            return New-VaultReadyResult -Vault $Vault -SkipReason $skipReason
        }
        Write-Verbose "Skipping vault '$($Vault.name)': $skipReason"
        return New-VaultSkipResult -Vault $Vault -SkipReason $skipReason
    }

    # Use group membership cache from migration context if not explicitly provided
    if (-not $GroupMembershipCache) {
        $GroupMembershipCache = $script:MigrationContext.GroupMembershipCache
    }

    # Analyze each access policy
    Write-Verbose "Analyzing $($AccessPolicies.Count) access policies for vault '$($Vault.name)'"
    $principalAnalysis = [System.Collections.ArrayList]::new()

    foreach ($policy in $AccessPolicies) {
        try {
            Write-Verbose "Processing access policy for principal: $($policy.ObjectId)"

            $roleMappingResult = ConvertTo-RbacRole -AccessPolicy $policy -RoleMapping $RoleMapping -VaultName $Vault.name

            # Skip non-existent principals
            $principalInfo = Get-ResolvedPrincipal -PrincipalId $policy.ObjectId
            if ($principalInfo -and $principalInfo.PrincipalType -eq "Unknown") {
                Write-Warning "Vault '$($Vault.name)': Skipping non-existent principal '$($policy.ObjectId)' - this identity no longer exists in Entra ID and will be excluded from the migration report."
                continue
            }

            # Resolve vault resource ID
            $vaultResourceId = if ($Vault.ResourceId) { $Vault.ResourceId }
                elseif ($Vault.id) { $Vault.id }
                else { "/subscriptions/$($Vault.subscriptionId)/resourceGroups/$($Vault.resourceGroup)/providers/Microsoft.KeyVault/vaults/$($Vault.name)" }

            # Resolve application name for compound identities
            $resolvedAppName = $null
            if ($policy.PSObject.Properties["ApplicationId"] -and $policy.ApplicationId) {
                # Check if this is a known compound identity — use the name from config
                $compound = if ($RoleMapping.compoundIdentities) {
                    $RoleMapping.compoundIdentities | Where-Object { $_.appId -eq $policy.ApplicationId } | Select-Object -First 1
                }
                if ($compound) {
                    $resolvedAppName = $compound.name
                }
                else {
                    # Non-compound: look up the SP by AppId
                    try {
                        $appSp = Get-AzADServicePrincipal -ApplicationId $policy.ApplicationId -ErrorAction Stop
                        if ($appSp) { $resolvedAppName = $appSp.DisplayName }
                    }
                    catch {
                        Write-Warning "Could not resolve ApplicationId $($policy.ApplicationId) to a service principal: $($_.Exception.Message)"
                    }
                }
            }

            # Check existing role assignments (uses cache when available, falls back to live API)
            $existingAssignments = Get-ExistingRoleAssignments -VaultResourceId $vaultResourceId -PrincipalId $policy.ObjectId -ApplicationId $null -RoleAssignmentCache $RoleAssignmentCache -GroupMembershipCache $GroupMembershipCache

            # Build per-role status
            $rolesWithStatus = foreach ($role in $roleMappingResult.RecommendedRoles) {
                $hasRole = $existingAssignments | Where-Object { $_.RoleDefinitionName -eq $role } | Select-Object -First 1
                $source = if ($hasRole) {
                    if ($hasRole.AssignmentType -eq 'GroupInherited') { "GroupInherited (via $($hasRole.Source))" } else { 'Direct' }
                } else { $null }
                [PSCustomObject]@{
                    RoleName         = $role
                    AlreadyAssigned  = [bool]$hasRole
                    AssignmentSource = $source
                }
            }

            [void]$principalAnalysis.Add(@{
                PrincipalId         = $policy.ObjectId
                ApplicationId       = $policy.ApplicationId
                ApplicationName     = $resolvedAppName
                RecommendedRoles    = $roleMappingResult.RecommendedRoles
                RolesWithStatus     = $rolesWithStatus
                AllAssignmentsExist = ($rolesWithStatus | Where-Object { -not $_.AlreadyAssigned }).Count -eq 0
                ExistingAssignments = $existingAssignments
                Warnings            = $roleMappingResult.Warnings
            })

            Write-Verbose "Successfully processed principal $($policy.ObjectId) - Recommended roles: $($roleMappingResult.RecommendedRoles -join ', ')"
        }
        catch {
            Write-Warning "Failed to process access policy for principal $($policy.ObjectId) in vault '$($Vault.name)': $($_.Exception.Message)"
            Write-AuditLog -Level "Error" -Message "Access policy processing failed" -VaultName $Vault.name -PrincipalId $policy.ObjectId -Details @{
                Error         = $_.Exception.Message
                ExceptionType = $_.Exception.GetType().Name
            }
            continue
        }
    }

    # Build final vault result
    $allAssignmentsReady = ($principalAnalysis | Where-Object { -not $_.AllAssignmentsExist }).Count -eq 0
    $vaultStatus = if ($allAssignmentsReady) { "Ready for RBAC" } else { "Analyzed" }

    Write-Verbose "Successfully analyzed vault '$($Vault.name)' with $((($principalAnalysis | Select-Object -ExpandProperty PrincipalId) | Sort-Object -Unique).Count) principals"

    return @{
        VaultName          = $Vault.name
        ResourceGroup      = $Vault.resourceGroup
        SubscriptionId     = $Vault.subscriptionId
        Status             = $vaultStatus
        RbacMigrationReady = $allAssignmentsReady
        Principals         = $principalAnalysis.ToArray()
        Timestamp          = Get-Date
    }
}

#endregion

function Invoke-OptimizedVaultAnalysis {
    <#
    .SYNOPSIS
    Processes vaults with performance optimizations using bulk operations and caching
    #>
    [CmdletBinding()]
    param(
        [array]$Vaults,
        [hashtable]$RoleMapping,
        [bool]$UseOptimizations = $true
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not $UseOptimizations) {
        Write-Warning "Performance optimizations disabled, falling back to sequential implementation"
        return Invoke-VaultAnalysis -Vaults $Vaults -RoleMapping $RoleMapping
    }

    # PHASE 1: Bulk Data Collection
    Write-Verbose "Phase 1: Bulk data collection and cache initialization"
    $phase1Start = [System.Diagnostics.Stopwatch]::StartNew()

    $subscriptionId = $Vaults[0].subscriptionId
    Initialize-PermissionLookupCache -RoleMapping $RoleMapping

    # Collect access policies and principal IDs
    Write-Host "Retrieving access policies..." -ForegroundColor Cyan
    $allPrincipalIds = @()
    $vaultAccessPolicies = @{}

    $vaultCounter = 0
    foreach ($vault in $Vaults) {
        $vaultCounter++
        try {
            $accessPolicies = Get-VaultAccessPolicies -VaultName $vault.name -ResourceGroupName $vault.resourceGroup -SubscriptionId $vault.subscriptionId -VaultCounter $vaultCounter -TotalVaults $Vaults.Count
            $vaultAccessPolicies[$vault.name] = $accessPolicies

            if ($accessPolicies) {
                $vaultPrincipalIds = $accessPolicies | ForEach-Object {
                    if ([string]::IsNullOrWhiteSpace($_.ObjectId)) {
                        Write-Warning "Found access policy with empty ObjectId in vault '$($vault.name)' - this may indicate a malformed access policy"
                        Write-AuditLog -Level "Warning" -Message "Empty ObjectId found in access policy" -VaultName $vault.name -Details @{
                            AccessPolicyCount = $accessPolicies.Count
                        } -Category "VaultAccess"
                        return $null
                    }
                    return $_.ObjectId
                } | Where-Object { $_ }
                $allPrincipalIds += $vaultPrincipalIds
            }
        }
        catch {
            Write-Warning "Failed to get access policies for vault $($vault.name): $($_.Exception.Message)"
            $vaultAccessPolicies[$vault.name] = $null
        }
    }

    # Bulk caches
    Write-Host "Caching role assignments..." -ForegroundColor Cyan
    $roleAssignmentCache = Get-BulkRoleAssignments -SubscriptionId $subscriptionId
    $script:LastRoleAssignmentCache = $roleAssignmentCache

    if ($allPrincipalIds.Count -gt 0) {
        $uniqueCount = ($allPrincipalIds | Sort-Object -Unique).Count
        Write-Host "Resolving $uniqueCount principals..." -ForegroundColor Cyan
        Initialize-BulkPrincipalCache -PrincipalIds $allPrincipalIds
        Write-Host "Resolving group memberships..." -ForegroundColor Cyan
        Initialize-GroupMembershipCache -PrincipalIds $allPrincipalIds
    }
    $groupMembershipCache = $script:MigrationContext.GroupMembershipCache

    $phase1Start.Stop()
    Write-Verbose "Phase 1 completed in $($phase1Start.ElapsedMilliseconds)ms"

    # PHASE 2: Analysis using cached data
    Write-Verbose "Phase 2: Analysis phase using cached data"
    $allResults = [System.Collections.ArrayList]::new()
    $totalVaults = $Vaults.Count

    for ($i = 0; $i -lt $totalVaults; $i++) {
        $vault = $Vaults[$i]
        try {
            $result = Invoke-SingleVaultAnalysis -Vault $vault -AccessPolicies $vaultAccessPolicies[$vault.name] -RoleMapping $RoleMapping -RoleAssignmentCache $roleAssignmentCache -GroupMembershipCache $groupMembershipCache -VaultCounter ($i + 1) -TotalVaults $totalVaults
            [void]$allResults.Add($result)
        }
        catch {
            Write-Warning "Failed to process vault '$($vault.name)': $($_.Exception.Message)"
            Write-AuditLog -Level "Error" -Message "Vault processing failed" -VaultName $vault.name -Details @{
                Error         = $_.Exception.Message
                ExceptionType = $_.Exception.GetType().Name
            }
            [void]$allResults.Add((New-VaultFailResult -Vault $vault -ErrorMessage $_.Exception.Message))
        }
    }

    $stopwatch.Stop()
    Write-Verbose "Optimized processing completed in $($stopwatch.Elapsed.TotalMinutes.ToString('F1')) minutes. Processed $($allResults.Count) vaults"

    Write-AuditLog -Level "Info" -Message "Optimized vault analysis completed" -Details @{
        TotalVaults = $Vaults.Count
        ProcessedVaults = $allResults.Count
        ElapsedMinutes = $stopwatch.Elapsed.TotalMinutes
        Phase1TimeMs = $phase1Start.ElapsedMilliseconds
        OptimizationsUsed = @("BulkRoleAssignments", "BulkPrincipalResolution", "PermissionLookupCache", "PrecomputedResourceIds")
    } -Category "Performance" -NoConsole

    return $allResults.ToArray()
}

function Invoke-VaultAnalysis {
    <#
    .SYNOPSIS
    Processes vaults sequentially (non-optimized fallback, also used by tests)
    #>
    [CmdletBinding()]
    param(
        [array]$Vaults,
        [hashtable]$RoleMapping
    )

    $allResults = @()
    $totalVaults = $Vaults.Count

    for ($i = 0; $i -lt $totalVaults; $i++) {
        $vault = $Vaults[$i]
        try {
            $result = Invoke-SingleVaultAnalysis -Vault $vault -RoleMapping $RoleMapping -VaultCounter ($i + 1) -TotalVaults $totalVaults
            $allResults += $result
        }
        catch {
            Write-Warning "Failed to process vault '$($vault.name)': $($_.Exception.Message)"
            Write-AuditLog -Level "Error" -Message "Vault processing failed" -VaultName $vault.name -Details @{
                Error         = $_.Exception.Message
                ExceptionType = $_.Exception.GetType().Name
            }
            $allResults += New-VaultFailResult -Vault $vault -ErrorMessage $_.Exception.Message
        }
    }

    Write-Verbose "Sequential processing completed. Processed $($allResults.Count) vaults"
    return $allResults
}

function Invoke-KvRbacAnalysis {
    # Handle GetPermissionMapping mode
    if ($GetPermissionMapping) {
        if (-not $PolicyAsJson) {
            Write-LogError "The -PolicyAsJson parameter is required when using -GetPermissionMapping."
            return
        }

        try {
            $policyObject = $PolicyAsJson | ConvertFrom-Json -ErrorAction Stop
            
            # The ConvertTo-RbacRole function expects a specific object structure,
            # so we need to map our simplified JSON to it.
            $accessPolicy = [PSCustomObject]@{
                PermissionsToSecrets      = if ($policyObject.secrets) { $policyObject.secrets } else { @() }
                PermissionsToKeys         = if ($policyObject.keys) { $policyObject.keys } else { @() }
                PermissionsToCertificates = if ($policyObject.certificates) { $policyObject.certificates } else { @() }
                ObjectId                  = "N/A (GetPermissionMapping Mode)" # Dummy value
            }

            $roleMapping = Get-RoleMapping
            $result = ConvertTo-RbacRole -AccessPolicy $accessPolicy -RoleMapping $roleMapping -VaultName "N/A (GetPermissionMapping Mode)"
            
            Write-Host "Recommended Roles:" -ForegroundColor Green
            $result.RecommendedRoles | ForEach-Object { Write-Host "- $_" }

            if ($result.Warnings) {
                Write-Host "`nWarnings:" -ForegroundColor Yellow
                $result.Warnings | ForEach-Object { Write-Host "- $_" }
            }
            return
        }
        catch {
            Write-LogError "Failed to process JSON policy: $($_.Exception.Message)"
            return
        }
    }
    # Validate parameters
    try {
        Test-ScopeParameters -VaultName $VaultName -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
    }
    catch {
        Write-LogError $_.Exception.Message
        return
    }
    
    Write-LogInfo "Key Vault RBAC Analysis Started"
    Write-LogInfo "Log file: $(Get-LogFilePath)"
    
    # Test Azure AD permissions before proceeding
    if (-not (Test-AzureADPermissions)) {
        Write-LogError "Azure AD permission issues detected. Principal names may show as 'Unknown'."
        Write-Host "You can continue the analysis, but principal names will not be resolved." -ForegroundColor Yellow
        $response = Read-Host "Continue anyway? (y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-LogInfo "Analysis cancelled by user due to Azure AD permission issues."
            return
        }
    }
    
    # Load role mappings
    try {
        $roleMapping = Get-RoleMapping
    }
    catch {
        Write-LogError "Failed to load role mapping: $_"
        return
    }
    
    # Discover vaults
    try {
        Write-LogInfo "Discovering Key Vaults..."
        $vaults = Get-KeyVaults -VaultName $VaultName -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -TagFilter $TagFilter
        Write-LogInfo "Found $($vaults.Count) Key Vault(s) using access policies"
        
        if ($vaults.Count -eq 0) {
            Write-LogWarning "No vaults found matching the specified criteria"
            return
        }
        
        # Process vaults with performance optimizations
        $analysisResults = Invoke-OptimizedVaultAnalysis -Vaults $vaults -RoleMapping $roleMapping
        
        # Export reports
        Write-LogInfo "Generating reports..."
        $reportPaths = Export-AnalysisReport -AnalysisResults $analysisResults -OutputFolder $OutputFolder -RoleMapping $roleMapping
        
        # Generate artifacts if requested
        if ($GenerateAutomationScripts) {
            Write-LogInfo "Generating deployment artifacts..."
            Export-VaultArtifacts -AnalysisResults $analysisResults -OutputFolder $OutputFolder -RoleMapping $roleMapping
            Write-LogInfo "Analysis complete! All reports and automation files are saved in: $($reportPaths.JsonPath | Split-Path -Parent)"
        }
        else {
            Write-LogInfo "Analysis complete! All reports are saved in: $($reportPaths.JsonPath | Split-Path -Parent)"
        }

        # Display assignment summary
        Write-AssignmentSummary -AnalysisResults $analysisResults -RoleAssignmentCache $script:LastRoleAssignmentCache
        
        # Do not return $reportPaths to avoid printing the hashtable
        return
        
    }
    catch {
        Write-LogError "Failed to discover vaults: $_"
        return
    }
}

function Export-AnalysisReport {
    <#
    .SYNOPSIS
    Exports analysis results to CSV and JSON formats

    .PARAMETER AnalysisResults
    Array of vault analysis results

    .PARAMETER OutputFolder
    Folder to save the reports

    .PARAMETER RoleMapping
    Role mapping hashtable containing role definitions
    #>
    [CmdletBinding()]
    param(
        [array]$AnalysisResults,
        [string]$OutputFolder = ".\out",
        [hashtable]$RoleMapping
    )

    # Create unique analysis folder for this run
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $analysisFolder = Join-Path $OutputFolder "analysis-$timestamp"
    if (-not (Test-Path $analysisFolder)) {
        New-Item -Path $analysisFolder -ItemType Directory -Force | Out-Null
        Write-Verbose "Created analysis folder: $analysisFolder"
    }

    $jsonPath = Join-Path $analysisFolder "analysis.json"
    $csvPath = Join-Path $analysisFolder "analysis.csv"
    
    # Export JSON (machine-readable)
    try {
        # Build a new array with Principals as [ordered] hashtables in the requested field order
        $orderedResults = foreach ($vault in $AnalysisResults) {
            $orderedVault = [ordered]@{
                VaultName              = $vault.VaultName
                ResourceGroup          = $vault.ResourceGroup
                SubscriptionId         = $vault.SubscriptionId
                Status                 = $vault.Status
                RbacMigrationReady = $vault.RbacMigrationReady
                Timestamp              = $vault.Timestamp
            }
            if ($vault.Principals -and $vault.Principals.Count -gt 0) {
                # Group principals by PrincipalId and ApplicationId (if present)
                $groupedPrincipals = $vault.Principals | Group-Object -Property @{Expression = { $_.PrincipalId + '|' + ($_.ApplicationId ? $_.ApplicationId : '') } }
                $orderedPrincipals = foreach ($group in $groupedPrincipals) {
                    $first = $group.Group | Select-Object -First 1
                    # Aggregate all roles and warnings (flatten arrays, deduplicate)
                    $allRoles = $group.Group | Select-Object -ExpandProperty RecommendedRoles -ErrorAction SilentlyContinue | Where-Object { $_ } | Sort-Object -Unique
                    $allWarnings = $group.Group | Select-Object -ExpandProperty Warnings -ErrorAction SilentlyContinue | Where-Object { $_ } | Sort-Object -Unique
                    # Resolve PrincipalName
                    $principalInfo = Get-ResolvedPrincipal -PrincipalId $first.PrincipalId
                    $principalName = if ($principalInfo -and $principalInfo.DisplayName -ne "Unknown") {
                        $principalInfo.DisplayName
                    } else {
                        "Unknown (ID: $($first.PrincipalId))"
                    }
                    $obj = [ordered]@{
                        PrincipalId   = $first.PrincipalId
                        PrincipalName = $principalName
                    }
                    if ($first.ApplicationId) {
                        $obj.ApplicationId = $first.ApplicationId
                    }
                    if ($first.ApplicationName) {
                        $obj.ApplicationName = $first.ApplicationName
                    }
                    $requiredRbacRoles = @()
                    foreach ($roleName in $allRoles) {
                        $roleDef = $RoleMapping.roleDefinitions[$roleName]

                        # BUGFIX: Find the original analysis object for this specific role to get the correct 'AlreadyAssigned' status.
                        # The original code incorrectly used the status of the *first* role for all subsequent roles for the same principal.
                        $principalInfo = $group.Group | Select-Object -First 1
                        $roleStatus = $principalInfo.RolesWithStatus | Where-Object { $_.RoleName -eq $roleName } | Select-Object -First 1
                        $isAssigned = if ($roleStatus) { $roleStatus.AlreadyAssigned } else { $false }
                        $assignmentSource = if ($roleStatus) { $roleStatus.AssignmentSource } else { $null }

                        if ($roleDef) {
                            $requiredRbacRoles += [PSCustomObject]@{
                                id               = $roleDef.id
                                name             = $roleDef.name
                                AlreadyAssigned  = $isAssigned
                                AssignmentSource = $assignmentSource
                            }
                        }
                        else {
                            $requiredRbacRoles += [PSCustomObject]@{
                                id               = $null
                                name             = $roleName
                                AlreadyAssigned  = $isAssigned
                                AssignmentSource = $assignmentSource
                            }
                        }
                    }
                    $obj.RequiredRBACRoles = $requiredRbacRoles
                    if ($allWarnings -and $allWarnings.Count -gt 0) {
                        $obj.Warnings = $allWarnings
                    }
                    $obj
                }
                $orderedVault.Principals = $orderedPrincipals
            }
            $orderedVault
        }
        @($orderedResults) | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        # JSON report generated
    }
    catch {
        Write-Error "Failed to save JSON report: $($_.Exception.Message)"
        $jsonPath = $null
    }
    
    # Prepare CSV data (human-readable)
    $csvData = @()
    foreach ($vault in $AnalysisResults) {
        if ($vault.Status -eq "Failed") {
            $csvData += [PSCustomObject]@{
                Subscription        = $vault.SubscriptionId
                ResourceGroup       = $vault.ResourceGroup
                Vault               = $vault.VaultName
                Principal           = "N/A"
                NeededRole          = "N/A"
                AssignmentStatus    = "Failed"
                Notes               = "Analysis failed: $($vault.Error)"
                AllAssignmentsReady = $false
            }
            continue
        }
        if ($vault.Status -eq "Skipped - Already RBAC or no policies") {
            $csvData += [PSCustomObject]@{
                Subscription        = $vault.SubscriptionId
                ResourceGroup       = $vault.ResourceGroup
                Vault               = $vault.VaultName
                Principal           = "N/A"
                NeededRole          = "N/A"
                AssignmentStatus    = "Skipped"
                Notes               = "Vault already uses RBAC or has no access policies"
                AllAssignmentsReady = $false
            }
            continue
        }
        if ($vault.Status -eq "Analyzed" -and $vault.SkipReason -eq "No access policies") {
            $csvData += [PSCustomObject]@{
                Subscription        = $vault.SubscriptionId
                ResourceGroup       = $vault.ResourceGroup
                Vault               = $vault.VaultName
                Principal           = "N/A"
                NeededRole          = "N/A"
                AssignmentStatus    = "Ready for RBAC"
                Notes               = "Vault has no access policies - ready for RBAC migration"
                AllAssignmentsReady = $true
            }
            continue
        }
        if ($vault.Principals.Count -eq 0) {
            $csvData += [PSCustomObject]@{
                Subscription        = $vault.SubscriptionId
                ResourceGroup       = $vault.ResourceGroup
                Vault               = $vault.VaultName
                Principal           = "N/A"
                NeededRole          = "N/A"
                AssignmentStatus    = "No Principals"
                Notes               = "No principals found in access policies"
                AllAssignmentsReady = $false
            }
            continue
        }
        # All-up flag: are all assignments for this vault "Exists"?
        $allAssignmentsReady = ($vault.Principals | Where-Object { -not $_.AllAssignmentsExist }).Count -eq 0

        foreach ($principal in $vault.Principals) {
            foreach ($roleStatus in $principal.RolesWithStatus) {
                $notes = @()
                if ($principal.Warnings) {
                    $notes += $principal.Warnings
                }
                $principalInfo = Get-ResolvedPrincipal -PrincipalId $principal.PrincipalId
                $principalName = if ($principalInfo) { $principalInfo.DisplayName } else { "Unknown" }
                $principalType = if ($principalInfo) { $principalInfo.PrincipalType } else { "Unknown" }
                $principalEmail = if ($principalInfo -and $principalInfo.PrincipalType -eq "User") { $principalInfo.UserPrincipalName } else { $null }
                # Get role definition ID
                $role = $roleStatus.RoleName
                $isAssigned = $roleStatus.AlreadyAssigned
                $roleDefinitionId = $null
                if ($role -and $roleMapping.roleDefinitions[$role]) {
                    $roleDefinitionId = $roleMapping.roleDefinitions[$role].id
                }
                
                $assignmentSource = $roleStatus.AssignmentSource
                $csvData += [PSCustomObject]@{
                    Vault            = $vault.VaultName
                    ResourceGroup    = $vault.ResourceGroup
                    Subscription     = $vault.SubscriptionId
                    PrincipalId      = $principal.PrincipalId
                    PrincipalName    = $principalName
                    PrincipalEmail   = $principalEmail
                    PrincipalType    = $principalType
                    RequiredRBACRole = $role
                    RoleDefinitionId = $roleDefinitionId
                    AlreadyAssigned  = $isAssigned
                    AssignmentSource = $assignmentSource
                    Warnings         = ($notes -join "; ")
                }
            }
        }
    }
    # Export CSV
    try {
        $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        # CSV report generated
    }
    catch {
        Write-Error "Failed to save CSV report: $($_.Exception.Message)"
        $csvPath = $null
    }
    return @{
        JsonPath = $jsonPath
        CsvPath  = $csvPath
    }
}
function New-RoleAssignmentCommands {
    <#
    .SYNOPSIS
    Generates PowerShell and Azure CLI commands for role assignments
    
    .PARAMETER VaultName
    Name of the Key Vault
    
    .PARAMETER ResourceGroup
    Resource group name
    
    .PARAMETER SubscriptionId
    Subscription ID
    
    .PARAMETER PrincipalId
    Principal Object ID
    
    .PARAMETER RoleName
    RBAC role name
    
    .PARAMETER RoleId
    RBAC role definition ID
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$RoleId
    )
    
    $vaultResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
    
    # Use role definition ID for more reliable assignment
    $powerShellCommand = @"
New-AzRoleAssignment ``
    -ObjectId '$PrincipalId' ``
    -RoleDefinitionId '$RoleId' ``
    -Scope '$vaultResourceId'
"@

    $azCommand = @"
az role assignment create ``
    --assignee '$PrincipalId' ``
    --role '$RoleId' ``
    --scope '$vaultResourceId'
"@

    return @{
        PowerShell = $powerShellCommand
        AzCli      = $azCommand
    }
}

function New-RoleAssignmentRemovalCommands {
    <#
    .SYNOPSIS
    Generates PowerShell and Azure CLI commands for role assignment removal
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$ResourceGroup,
        [string]$SubscriptionId,
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$RoleId
    )
    
    $vaultResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
    
    # Use role definition ID for more reliable assignment removal
    $powerShellCommand = @"
Remove-AzRoleAssignment ``
    -ObjectId '$PrincipalId' ``
    -RoleDefinitionId '$RoleId' ``
    -Scope '$vaultResourceId'
"@

    $azCommand = @"
az role assignment delete ``
    --assignee '$PrincipalId' ``
    --role '$RoleId' ``
    --scope '$vaultResourceId'
"@

    return @{
        PowerShell = $powerShellCommand
        AzCli      = $azCommand
    }
}

function New-ArmTemplate {
    <#
    .SYNOPSIS
    Generates ARM template snippet for role assignment
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$RoleId,
        [string]$PrincipalType = "User"
    )
    
    $armTemplate = @"
{
    "type": "Microsoft.Authorization/roleAssignments",
    "apiVersion": "2022-04-01",
    "name": "[guid(resourceId('Microsoft.KeyVault/vaults', '$VaultName'), '$PrincipalId', '$RoleId')]",
    "scope": "[resourceId('Microsoft.KeyVault/vaults', '$VaultName')]",
    "properties": {
        "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '$RoleId')]",
        "principalId": "$PrincipalId",
        "principalType": "$PrincipalType"
    }
}
"@

    return $armTemplate
}

function New-BicepModule {
    <#
    .SYNOPSIS
    Generates Bicep module snippet for role assignment
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$RoleId,
        [string]$PrincipalType = "User"
    )
    
    $bicepModule = @"
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, '$PrincipalId', '$RoleId')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '$RoleId')
    principalId: '$PrincipalId'
    principalType: '$PrincipalType'
  }
}
"@

    return $bicepModule
}


function Export-VaultArtifacts {
    <#
    .SYNOPSIS
    Exports ARM and Bicep artifacts for each vault
    #>
    [CmdletBinding()]
    param(
        [array]$AnalysisResults,
        [string]$OutputFolder = ".\out",
        [hashtable]$RoleMapping
    )

    # Find latest analysis folder (assumes Export-AnalysisReport was just called)
    $analysisFolders = Get-ChildItem -Path $OutputFolder -Directory | Where-Object { $_.Name -like "analysis-*" } | Sort-Object Name -Descending
    $analysisFolder = if ($analysisFolders.Count -gt 0) { $analysisFolders[0].FullName } else { $OutputFolder }

    foreach ($vault in $AnalysisResults) {
        if ($vault.Status -ne "Analyzed" -or $vault.Principals.Count -eq 0) {
            continue
        }


        $neededAssignments = @()
        $armSnippets = @()
        $bicepSnippets = @()

        foreach ($principal in $vault.Principals) {
            if (-not $principal.AllAssignmentsExist) {
                # Resolve principal type for ARM/Bicep templates
                $principalInfo = Get-ResolvedPrincipal -PrincipalId $principal.PrincipalId
                $principalType = if ($principalInfo -and $principalInfo.PrincipalType -ne 'Unknown') { $principalInfo.PrincipalType } else { 'User' }

                foreach ($roleStatus in $principal.RolesWithStatus) {
                    if (-not $roleStatus.AlreadyAssigned) {
                        $role = $roleStatus.RoleName
                        $roleId = $RoleMapping.roleDefinitions[$role].id
                        $neededAssignments += @{
                            PrincipalId   = $principal.PrincipalId
                            RoleName      = $role
                            RoleId        = $roleId
                            PrincipalType = $principalType
                        }

                        $armSnippets += New-ArmTemplate -VaultName $vault.VaultName -PrincipalId $principal.PrincipalId -RoleName $role -RoleId $roleId -PrincipalType $principalType
                        $bicepSnippets += New-BicepModule -VaultName $vault.VaultName -PrincipalId $principal.PrincipalId -RoleName $role -RoleId $roleId -PrincipalType $principalType
                    }
                }
            }
        }

        if ($neededAssignments.Count -eq 0) {
            Write-Verbose "No role assignments needed for vault: $($vault.VaultName)"
            continue
        }

        # Create vault-specific folder inside analysis folder
        $vaultFolder = Join-Path $analysisFolder $vault.VaultName
        if (-not (Test-Path $vaultFolder)) {
            New-Item -Path $vaultFolder -ItemType Directory -Force | Out-Null
        }

        # Create templates subfolder for ARM/Bicep/YAML
        $templatesFolder = Join-Path $vaultFolder "templates"
        if (-not (Test-Path $templatesFolder)) {
            New-Item -Path $templatesFolder -ItemType Directory -Force | Out-Null
        }

        # Create scripts subfolder for PowerShell/CLI
        $scriptsFolder = Join-Path $vaultFolder "scripts"
        if (-not (Test-Path $scriptsFolder)) {
            New-Item -Path $scriptsFolder -ItemType Directory -Force | Out-Null
        }

        # Build role definitions object for ARM template
        $roleDefEntries = @()
        foreach ($roleName in $RoleMapping.roleDefinitions.Keys) {
            $roleId = $RoleMapping.roleDefinitions[$roleName].id
            $roleDefEntries += "            `"$roleName`": `"$roleId`""
        }
        $roleDefinitionsJson = $roleDefEntries -join ",`n"

        # Save ARM template
        $armPath = Join-Path $templatesFolder "roleAssignments.json"
        $armContent = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "variables": {
        "roleDefinitions": {
$roleDefinitionsJson
        }
    },
    "resources": [
$($armSnippets -join ",`n")
    ]
}
"@
        $armContent | Out-File -FilePath $armPath -Encoding UTF8

        # Build role definitions for Bicep
        $bicepRoleDefEntries = @()
        foreach ($roleName in $RoleMapping.roleDefinitions.Keys) {
            $roleId = $RoleMapping.roleDefinitions[$roleName].id
            $bicepRoleDefEntries += "  '$roleName': '$roleId'"
        }
        $bicepRoleDefinitions = $bicepRoleDefEntries -join "`n"

        # Save Bicep module
        $bicepPath = Join-Path $templatesFolder "roleAssignments.bicep"
        $bicepContent = @"
// Bicep module for Key Vault RBAC role assignments
// Vault: $($vault.VaultName)

@description('Key Vault resource reference')
param keyVault object

var roleDefinitions = {
$bicepRoleDefinitions
}

$($bicepSnippets -join "`n`n")
"@
        $bicepContent | Out-File -FilePath $bicepPath -Encoding UTF8


        # Generate PowerShell commands file
        $powerShellCommands = @()
        $azCliCommands = @()
        $powerShellRemovalCommands = @()
        $azCliRemovalCommands = @()
        
        foreach ($assignment in $neededAssignments) {
            $commands = New-RoleAssignmentCommands -VaultName $vault.VaultName -ResourceGroup $vault.ResourceGroup -SubscriptionId $vault.SubscriptionId -PrincipalId $assignment.PrincipalId -RoleName $assignment.RoleName -RoleId $assignment.RoleId
            $powerShellCommands += "# Assign role '$($assignment.RoleName)' to principal '$($assignment.PrincipalId)'"
            $powerShellCommands += $commands.PowerShell
            $powerShellCommands += ""
            
            $azCliCommands += "# Assign role '$($assignment.RoleName)' to principal '$($assignment.PrincipalId)'"
            $azCliCommands += $commands.AzCli
            $azCliCommands += ""

            $removalCommands = New-RoleAssignmentRemovalCommands -VaultName $vault.VaultName -ResourceGroup $vault.ResourceGroup -SubscriptionId $vault.SubscriptionId -PrincipalId $assignment.PrincipalId -RoleName $assignment.RoleName -RoleId $assignment.RoleId
            $powerShellRemovalCommands += "# Remove role '$($assignment.RoleName)' from principal '$($assignment.PrincipalId)'"
            $powerShellRemovalCommands += $removalCommands.PowerShell
            $powerShellRemovalCommands += ""

            $azCliRemovalCommands += "# Remove role '$($assignment.RoleName)' from principal '$($assignment.PrincipalId)'"
            $azCliRemovalCommands += $removalCommands.AzCli
            $azCliRemovalCommands += ""
        }
        
        # Save PowerShell commands file
        $powerShellPath = Join-Path $scriptsFolder "roleAssignments.ps1"
        $powerShellHeader = @"
# PowerShell commands for Key Vault RBAC role assignments
# Vault: $($vault.VaultName)
# Resource Group: $($vault.ResourceGroup)
# Subscription: $($vault.SubscriptionId)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
        ($powerShellHeader + ($powerShellCommands -join "`n")) | Out-File -FilePath $powerShellPath -Encoding UTF8
        
        # Save Azure CLI commands file
        $azCliPath = Join-Path $scriptsFolder "roleAssignments.sh"
        $azCliHeader = @"
#!/bin/bash
# Azure CLI commands for Key Vault RBAC role assignments
# Vault: $($vault.VaultName)
# Resource Group: $($vault.ResourceGroup)
# Subscription: $($vault.SubscriptionId)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
        ($azCliHeader + ($azCliCommands -join "`n")) | Out-File -FilePath $azCliPath -Encoding UTF8

        # Save PowerShell revert commands file
        $powerShellRevertPath = Join-Path $scriptsFolder "roleAssignments-revert.ps1"
        $powerShellRevertHeader = @"
# PowerShell commands to REVERT Key Vault RBAC role assignments
# Vault: $($vault.VaultName)
# Resource Group: $($vault.ResourceGroup)
# Subscription: $($vault.SubscriptionId)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
        ($powerShellRevertHeader + ($powerShellRemovalCommands -join "`n")) | Out-File -FilePath $powerShellRevertPath -Encoding UTF8

        # Save Azure CLI revert commands file
        $azCliRevertPath = Join-Path $scriptsFolder "roleAssignments-revert.sh"
        $azCliRevertHeader = @"
#!/bin/bash
# Azure CLI commands to REVERT Key Vault RBAC role assignments
# Vault: $($vault.VaultName)
# Resource Group: $($vault.ResourceGroup)
# Subscription: $($vault.SubscriptionId)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
        ($azCliRevertHeader + ($azCliRemovalCommands -join "`n")) | Out-File -FilePath $azCliRevertPath -Encoding UTF8

        # Artifacts generated for vault
    }
}

function Get-RoleAssignmentCount {
    [CmdletBinding()]
    param(
        [string]$Scope
    )
    try {
        Write-Verbose "Getting role assignment count for scope: $Scope"
        $assignments = Get-AzRoleAssignment -Scope $Scope -ErrorAction Stop
        if ($null -ne $assignments) {
            return $assignments.Count
        }
        return 0
    }
    catch {
        Write-Warning "Could not get role assignments for scope '$Scope'. Error: $($_.Exception.Message)"
        return 0
    }
}

function Write-AssignmentSummary {
    [CmdletBinding()]
    param(
        [array]$AnalysisResults,
        [hashtable]$RoleAssignmentCache = $null
    )

    if ($AnalysisResults.Count -eq 0) {
        return
    }

    Write-Host "`n--- RBAC Assignment Summary ---" -ForegroundColor Green

    $subscriptions = $AnalysisResults | Where-Object { $_.SubscriptionId } | Group-Object -Property SubscriptionId

    foreach ($subGroup in $subscriptions) {
        $subscriptionId = $subGroup.Name

        Write-Host "`nSubscription: $subscriptionId" -ForegroundColor Cyan

        $currentSubAssignments = if ($script:LastTotalAssignmentCount) { $script:LastTotalAssignmentCount } else { 0 }

        $totalNewAssignmentsInSub = 0
        $vaultsInSub = $subGroup.Group | Where-Object { $_.Status -ne "Skipped - Already RBAC" -and $_.Status -ne "Failed" -and $_.Status -ne "Skipped - No access policies" }

        $vaultsNearLimit = @()
        foreach ($vaultResult in $vaultsInSub) {
            $newAssignmentsForVault = 0
            $currentVaultAssignments = 0

            if ($vaultResult.Principals) {
                foreach ($principal in $vaultResult.Principals) {
                    if ($principal.RolesWithStatus) {
                        $newRoles = $principal.RolesWithStatus | Where-Object { -not $_.AlreadyAssigned }
                        $newAssignmentsForVault += $newRoles.Count
                        $currentVaultAssignments += ($principal.RolesWithStatus | Where-Object { $_.AlreadyAssigned }).Count
                    }
                }
            }

            $totalNewAssignmentsInSub += $newAssignmentsForVault
            $futureVaultAssignments = $currentVaultAssignments + $newAssignmentsForVault

            if ($futureVaultAssignments -ge 1500) {
                $vaultsNearLimit += @{
                    Name          = $vaultResult.VaultName
                    ResourceGroup = $vaultResult.ResourceGroup
                    Current       = $currentVaultAssignments
                    Future        = $futureVaultAssignments
                }
            }
        }

        $futureSubAssignments = $currentSubAssignments + $totalNewAssignmentsInSub

        Write-Host "Total Assignments on Subscription:"
        Write-Host "  Current: $currentSubAssignments"
        Write-Host "  After migration: $futureSubAssignments (+ $totalNewAssignmentsInSub new)"

        if ($futureSubAssignments -ge 3500) {
            Write-Host "WARNING: Subscription is approaching the 4000 role assignment limit." -ForegroundColor Yellow
        }

        if ($vaultsNearLimit.Count -gt 0) {
            Write-Host "Resource-Specific Assignment Limits (2000 per resource):"
            foreach ($vaultWarning in $vaultsNearLimit) {
                Write-Host "  - WARNING for Vault '$($vaultWarning.Name)' in RG '$($vaultWarning.ResourceGroup)':" -ForegroundColor Yellow
                Write-Host "    - Current assignments: $($vaultWarning.Current)" -ForegroundColor Yellow
                Write-Host "    - Future assignments: $($vaultWarning.Future)" -ForegroundColor Yellow
                Write-Host "    - This is approaching the 2000 assignment limit for a single resource." -ForegroundColor Yellow
            }
        }
    }
}

function Get-UserChoice {
    <#
    .SYNOPSIS
    Prompts the user for a choice with multiple options
    
    .DESCRIPTION
    Displays a prompt and allows the user to choose from Yes, No, All, or Quit options.
    Used for interactive confirmation during vault processing.
    
    .PARAMETER Message
    The message to display to the user
    
    .OUTPUTS
    String representing the user's choice: 'Yes', 'No', 'All', or 'Quit'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    
    do {
        $choice = Read-Host "$Message [Y]es/[N]o/[A]ll/[Q]uit"
        switch ($choice.ToLower()) {
            'y' { return 'Yes' }
            'yes' { return 'Yes' }
            'n' { return 'No' }
            'no' { return 'No' }
            'a' { return 'All' }
            'all' { return 'All' }
            'q' { return 'Quit' }
            'quit' { return 'Quit' }
            default {
                Write-Host "Please enter Y (Yes), N (No), A (All), or Q (Quit)" -ForegroundColor Yellow
            }
        }
    } while ($true)
}

# Main execution - only run if not dot-sourced
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-KvRbacAnalysis @PSBoundParameters
}

# SIG # Begin signature block
# MIIo3QYJKoZIhvcNAQcCoIIozjCCKMoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCdTSwZV/cw+SoP
# TkEdlOCKASM0skCcTxZdRtblB/9kd6CCDcMwggatMIIElaADAgECAhMzAAAArn9k
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
# cDCCGmwCAQEweTBiMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTMwMQYDVQQDEypBenVyZSBSU0EgUHVibGljIFNlcnZpY2VzIENv
# ZGUgU2lnbmluZyBQQ0ECEzMAAACuf2TW1iwx/gkAAAAAAK4wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFZ7p0lgbHfS43ApND5t5RGC
# ubWG+orWpZEjJoB2rpJSMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggGAV/7tK4TwlAm/DX1AG1CFHszw9ZuXERDPzMCKwe1EN7SSKj81YZ6r+D++
# GNrPnZ4sC+6Am4oF328u1r8laP1MwdBOG8QSIopp4FZdCAXWexEZntdZQTSwmjAL
# 0eSwlAtOS4se5ye2iDmeqgFhWfVJ/2NgAvCFnNSYbstoQuNgCKk0gqSTzePkr4qX
# UJ+BAESFp1K0f0CiA0iTiZFWEgLkq+qBSXHwGPXdum/mdZjnZfvYyH4L+pp3tf3g
# A/EzLeeviYyhD7OYCoRE8+sywMQL97Mrg2z4ldQ88mUJxoOeaVTzubpxGmoGiGu4
# A9EYhTFPPE/HFW28bF1BcsiQdToyOrlwkEHJGxLbJeHVqTD7M7ZLWBnBDkjSCe4p
# Wo7pSUfkF6AusZ3fl9fL0dG8K72R4J36opcWmZHKuG16SN8vSdLlJhk1el+6v+Sr
# +t6lQ9vLuGAJt6RP1fJqtAt20L+SCmQOdR00hCMYIDOH0ZW5PLJMxCzEN503hkcQ
# 85uit7ZkoYIXlzCCF5MGCisGAQQBgjcDAwExgheDMIIXfwYJKoZIhvcNAQcCoIIX
# cDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSC
# AT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJYjRhNX7QvJ
# WdgYx12lQdngHLOBjXD6y418JQCVQWdNAgZpnK6GojsYEzIwMjYwMzA1MTg0MjU4
# LjUyMVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpGMDAyLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEe0wggcgMIIFCKADAgEC
# AhMzAAACBTx1bIJEh83+AAEAAAIFMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI0OVoXDTI2MDQyMjE5NDI0
# OVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjpGMDAyLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AJKS8t93uAXWvbAZ3LzkIVhcdQLzLATIPgtEu/RZgRd55nS7li4runZxdXNCZk84
# dM3xNaobZI+VRv7s+V3MUMMCVHe9TymI6OaG72sdbjczZ1uiv2OX2CW6HPBR3ZJy
# JUZrt/23ru0zcoUpFIxcW0coXcrAEHtpWj5vWrLmn0NaWjY3kUasGocwRWU3LOt4
# digMsv6bx9Kyoy7+JhSrHMrkXhLshjk16YAHwH4DdCDBUiLrgokh94plR6JYoJN/
# ih1SA/cBCKXGHjw/rPsBPggDR0wS0qFgsWzhb8o0MyxivsqlA8pUJwLkTy4Md0p7
# C5vLN6eRPHLh9/U3eDzKGjk+L0F+NHRXK2uSakN96nwk/BxvgE04hc6jWl90dnwS
# +dHskVkVCKqkxkWU7kIC5Ngfy6Nzk9QeVowAnw0Rr1MUlM5IGsHs9GB6H/o0nbG7
# 3LE+H+RU30Eayz3cwLpSOmjF4zjHvRvBvCIrxI0cg7wPxyqXtVJ69RhuM3g2iAUX
# CEEKWGh0T/N4Y+rrLqLEPjPrkgdjfPAVBsFVf/D4v9Uc2f8EwazY8YeeVGM78qTw
# 0ik3iyGQVCoDV8zTx+usNI0Rj1UoO2mxSkAXnVjWhDq0mFYzV3ed4JeHpv/o35d4
# c5ELCdjzcr6kUwyGDyKxdBvopGXrmSDxdgF3gnCRsqhVAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUdHpauzbtvr7IndsRn2jk10vVsvAwHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAA67GTjtvWLvlXzVPHrGjXTE0ivjNnFhV+QXlMWraSd08eDNXIueyzD8
# cqQRlEKBlWmQoQnpjiO8bm26AyL5aO3uFQxKKmT5GkHmAVC+HXGYAQvZ+V6DNNYS
# yePTCsRKmUjlne+B/Z4ZcCv9FyoaNKmi4dsPYdj1jcXQ6XoVEMJX8cQYpEfOfYzm
# tCkUZKNpxPgOSpViZ6b8Cs59K9WiOcoQhb3XhTEa26ElKv2M6jlGpNfsYipu283v
# OFaV36LdfF2F01x+VDP1iGgWpB7EF6eghGAA8C3AfrzFzOv0swLeX0AsSmey87RG
# Io9cXiXbb859wV99qmGeX9MPCSIl/E7IAx9QXfEj37eLNPVZfYIWzZFo4Crd1yiH
# InD7FEbQTzCQIeqRXnsFtQETMtfwv2UYnUOjFg2mgNfuJDMn1B2TKmLl+/vvcTcK
# HwD62jF4WnoWJ9BnIJzwhwgGUfJqToxtPphNVA2BD+HwUX5Lk6o/sIQIW8gfYq3Y
# /QaU670LQF9qyGdOOh2a1kVmym1S+KuT/Yc4suMGIyMPAmxAAUDMm7Phm1PKiuu8
# RHXQaX+ZuZWIeqG80AJ9PM+It+MODK+n2zv9se78JqUqZ6IlQsaOH+XACPnfX2mC
# CwYmpuEngVsVz6hTnN99ub+sqNVnyTE0PeKbXRCnjWfa3+qnI/oRMIIHcTCCBVmg
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
# f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA1AwggI4AgEBMIH5oYHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVANWwf2nW0mf6SvAIy+o6FW9e
# tt60oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDtU7G5MCIYDzIwMjYwMzA1MDczOTM3WhgPMjAyNjAzMDYwNzM5
# MzdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAO1TsbkCAQAwCgIBAAICLGsCAf8w
# BwIBAAICE9EwCgIFAO1VAzkCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEA
# s+u+TgL55+NK4GMbrrLgo9rcyGRWR4Puv4yufAsr+1UvGJWdVVxzxCkqlpnGoYDM
# FdHVBxD4Y2nyjOeeE5XqTTIK3NQmxew12vDplMovVY6qKO/HMlmuKWiRShvbG4vR
# 6tUToP1+G/Q+0gsogg/UXgZa9AeMUcXcSL9bUGQIucPP8nQKE7hQDbf30i9Et01D
# gd7O6P8QncSbWzjqCVgBP1pi2uuQKYYS6UcslXbYIaxrXJdjOEm5DyRPg0ngYU14
# eLp6rr2MIxl1qVXPQjsBUX6r0ayBk540am/AOmfZP05lKHIQ46dboPoM4juQHlOs
# 8oFRBMLikSjMYHa6EZnmYTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAACBTx1bIJEh83+AAEAAAIFMA0GCWCGSAFlAwQCAQUA
# oIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIE
# IGeww0mYsAXT+33VD85ELFfGCbEuyDt7TS1/xI29g2SxMIH6BgsqhkiG9w0BCRAC
# LzGB6jCB5zCB5DCBvQQggA0DPdx5jS6aF1YtHawmmrQ4+q0kNMBhGaMdWTARb0gw
# gZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgU8dWyC
# RIfN/gABAAACBTAiBCB+B5xNRTQPD6W0kwAqjtO1Vm30wLqUKCg4I4EcwaAmHzAN
# BgkqhkiG9w0BAQsFAASCAgApAHfUe7MCG+z6h7cGGzlNXgHfscxHx/QfkokAHaIx
# M3y4D/9t8yzx0U5V8Y0nW4VkEk3wh584T4DAI/XS56oQ+iWE1qh1UeEfUUiQoM5F
# AmVaKSm7mm3Qx6JLHvoTsbq/1zZLmjhlmZvQjVnzdPNkL6/26wtX2/B28ZA1CUCH
# xQWbUxsqAlnVbxhIlqTOXH5RPUhfiZm0TcIlFZZPyTZNd1vHHS3mBYT/xWUCbFjL
# GrmLQHFIUxCk9lHhqbDOeT/tfAqUAWu1HwOd3nUAteOd0VsYOsd8lLYvxPAc6hmU
# ACN0ihy2UOpEbbGv38Bbkr2wfZEvL1MJ4pWA+dj//mwt7O03Lys/ZueiYrBggaYt
# DRp9w8m2C+oXjQSrtBWFIe7qLmofN+0gBZiPPB1nXYNUBWDcCxK8Lufs46JrPQvr
# 35kt6ZOltyqJnJIW+EPNOD3YOCxkTc9hGYGjRRn2dh+C082qrhbYjwWe1NTaVjht
# 1rBKNHCiLS+uPpmwwiycYKAF7TTD99m9J1Z11ut2iH1mYPRN0D2qMopX4ui6QyUI
# Txwx5hIhYiYWX1AP3irn0JDpPIRtxervKv0mUxd94TklADvYKz1fpigZzxDJND5W
# IBoUhNntG21BzUKJ5Gngcg0Xs6hQEW4F/LfAc7JoHyLLHSv+F2kGB7Y/pCJuMinI
# iw==
# SIG # End signature block
