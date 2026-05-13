# KvRbacMigrator

A PowerShell toolkit for migrating Azure Key Vaults from access policy authentication to Azure RBAC authorization, designed for enterprise-scale management of hundreds to thousands of Key Vaults.

## Overview

KvRbacMigrator provides a comprehensive solution for:
- **Analyzing** Key Vault access policies and mapping them to appropriate RBAC roles
- **Generating** deployment artifacts (ARM, Bicep, CLI commands)
- **Applying** RBAC role assignments with safety controls

## Documentation

For the Microsoft Learn how-to that places this toolkit in the broader Azure Key Vault access-control migration workflow, see [Migrate Key Vaults to Azure RBAC at scale with KvRbacMigrator](https://learn.microsoft.com/azure/key-vault/general/rbac-migration-toolkit). For the end-to-end migration guidance — including Azure Policy governance and the manual single-vault workflow — see [Migrate to Azure RBAC from access policies](https://learn.microsoft.com/azure/key-vault/general/rbac-migration).

## Features

**Discovery & Analysis**
- Scans single vaults, resource groups, or entire subscriptions
- Uses Azure Resource Graph for efficient large-scale discovery with automatic fallback to ARM APIs
- Filters out vaults already using RBAC authorization during discovery
- Supports tag-based filtering for targeted migrations
- Optimized processing with bulk operations and caching for improved performance at scale
- Automatically skips non-existent principals (deleted users, groups, or service principals)
- Comprehensive error handling with detailed failure reporting and recovery

**Intelligent Role Mapping**
- Maps access policy permissions to least-privilege RBAC roles using sophisticated algorithms
- Detects existing role assignments to prevent duplicates, including assignments inherited through transitive group membership (nested groups)
- **Administrator Mode Security**: Assigns the Key Vault Administrator role only when it grants no additional permissions beyond the user's current access, preventing privilege escalation
- Maps storage permissions to Key Vault Administrator with escalation warnings (storage APIs are deprecated)
- Supports compound identities for Azure services with predefined configurations
- Provides detailed warnings for permission gaps and over-provisioning scenarios

**Permission Analysis Mode**
- Instantly determine the minimal RBAC role for a set of permissions using [`-GetPermissionMapping`](Invoke-KvRbacAnalysis.ps1) mode
- Ideal for developers and security engineers to quickly validate access requirements
- No vault discovery required - works with JSON permission definitions

**Comprehensive Reporting**
- Human-readable CSV reports with detailed assignment status
- Machine-readable JSON for automation and integration
- Structured audit logging with compliance tracking and decision rationale
- Ready-to-execute PowerShell and Azure CLI command generation
- Performance metrics and optimization recommendations

**Deployment Artifacts**
- ARM template snippets with proper resource definitions
- Bicep modules with modern syntax and best practices
- PowerShell and Azure CLI scripts with error handling
- Revert scripts for rollback scenarios

**Enterprise Safety & Reliability**
- Dry-run mode by default with clear execution indicators
- Per-vault confirmation prompts with batch override options
- Idempotent operations that safely handle re-execution
- Comprehensive error handling with detailed failure reporting
- Zero privilege escalation security model

## Prerequisites

- **PowerShell 7.0+** (Windows, Linux, or macOS)
- **Azure PowerShell modules:**
  - `Az.KeyVault`
  - `Az.Resources` 
  - `Az.Accounts`
  - `Az.ResourceGraph` (recommended)
- **Permissions:**
  - Key Vault Reader (for analysis)
  - User Access Administrator (for role assignments)

## Important Notes

- The tool analyzes and suggests Key Vault-level role assignments. It does not account for effective permissions inherited from subscription-level role assignments, so duplicate role suggestions can occur. If a principal already receives required access through subscription-level roles, skip creating the suggested vault-level duplicate assignments.
- The tool runs at subscription scope (or narrower scopes such as resource group or vault) and does not support tenant-scope execution.
- The least-privilege mappings are recommendations, not guarantees. Review all suggested role assignments before applying them to avoid over-permissioning or under-permissioning.
- Use the audit functionality throughout planning and rollout to validate decisions and support a smooth migration.

## Quick Start

This Quick Start is the fastest path through the toolkit. For migration context — when to use it, how it fits with Azure Policy governance, and how to switch authentication mode safely — see the [Microsoft Learn how-to](https://learn.microsoft.com/azure/key-vault/general/rbac-migration-toolkit).

### 1. Install Prerequisites

```powershell
# Install required Azure PowerShell modules
Install-Module Az.KeyVault, Az.Resources, Az.Accounts, Az.ResourceGraph -Force

# Connect to Azure
Connect-AzAccount
```

### 2. Analyze Key Vaults

```powershell
# Analyze all vaults in a resource group (generates reports only)
.\Invoke-KvRbacAnalysis.ps1 -ResourceGroup "my-keyvaults-rg"

# Analyze specific vaults and generate automation scripts
.\Invoke-KvRbacAnalysis.ps1 -VaultName "kv-prod-01","kv-prod-02" -GenerateAutomationScripts

# Analyze entire subscription with tag filter
.\Invoke-KvRbacAnalysis.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc" -TagFilter @{ "MigrateToRBAC" = "true" }
```

### 3. Review Results

The analysis generates reports in a timestamped subdirectory, such as `.\out\analysis-20250703-143022`:
- `analysis.csv` - Human-readable report for auditing and review
- `analysis.json` - Machine-readable data for the [`Invoke-KvRbacApply.ps1`](Invoke-KvRbacApply.ps1) step

If you use the `-GenerateAutomationScripts` flag, it creates vault-specific folders containing deployment artifacts:
- ARM and Bicep templates in `templates/` subfolder
- PowerShell and Azure CLI scripts in `scripts/` subfolder
- Revert scripts for rollback scenarios

### 4. Apply Role Assignments

```powershell
# Preview changes using the -WhatIf parameter
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-20250703-143022\analysis.json" -WhatIf

# Apply the changes (prompts for confirmation per vault)
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-20250703-143022\analysis.json"

# Apply all without confirmation prompts (use with caution)
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-20250703-143022\analysis.json" -Confirm:$false
```

### 5. Switch Authentication Mode

After verifying the new RBAC roles work, switch each Key Vault's authentication mode using the Azure CLI or Az PowerShell.

```powershell
# Azure CLI
az keyvault update --name "kv-prod-01" --enable-rbac-authorization true

# Az PowerShell
Update-AzKeyVault -VaultName "kv-prod-01" -ResourceGroupName "my-keyvaults-rg" -EnableRbacAuthorization $true
```

## Usage Examples

### Large-Scale Migration Workflow

```powershell
# 1. Analyze all vaults in subscription
.\Invoke-KvRbacAnalysis.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789abc"

# 2. Review CSV report for human analysis
Import-Csv ".\out\analysis-20250703-143022\analysis.csv" | Out-GridView

# 3. Apply role assignments
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-20250703-143022\analysis.json"

# 4. Switch authentication mode after verifying access (per vault)
az keyvault update --name "kv-prod-01" --enable-rbac-authorization true
```

### CI/CD Integration

```powershell
# Generate pipeline artifacts for automated deployment
.\Invoke-KvRbacAnalysis.ps1 -ResourceGroup "prod-keyvaults" -GenerateAutomationScripts

# Deploy using generated templates
# (Submit out/analysis-*/[vaultname]/templates/* to your build system)
```

### Filtering and Targeting

```powershell
# Target vaults by tags
.\Invoke-KvRbacAnalysis.ps1 -SubscriptionId "sub-id" -TagFilter @{
    "Environment" = "production"
    "MigrateToRBAC" = "true"
}

# Process specific vaults
.\Invoke-KvRbacAnalysis.ps1 -VaultName "kv-app1-prod","kv-app2-prod"
```

### Permission Analysis Mode

Use the `-GetPermissionMapping` mode to quickly determine the recommended RBAC role(s) for a given set of permissions without performing a full vault analysis. This is useful for understanding how a specific set of permissions maps to built-in RBAC roles.

```powershell
# Define permissions in a JSON string
$jsonPolicy = @'
{
    "secrets": ["get", "list"],
    "keys": ["get"],
    "certificates": ["get", "list"]
}
'@

# Run the analysis
.\Invoke-KvRbacAnalysis.ps1 -GetPermissionMapping -PolicyAsJson $jsonPolicy
```

## Role Mapping

The tool maps Key Vault access policy permissions to these built-in RBAC roles:

| Permission Type | Access Policy Permissions | RBAC Role |
|-----------------|---------------------------|-----------|
| **Secrets** | get, list | Key Vault Secrets User |
| | set, delete, backup, restore, recover, purge | Key Vault Secrets Officer |
| **Keys** | get, list, decrypt, encrypt, unwrapKey, wrapKey, verify, sign | Key Vault Crypto User |
| | create, update, import, delete, backup, restore, recover, purge | Key Vault Crypto Officer |
| **Certificates** | get, list, getissuers, listissuers | Key Vault Certificate User |
| | set, create, update, import, delete, managecontacts, manageissuers, setissuers, deleteissuers | Key Vault Certificates Officer |
| **Storage** | get, list, set, update, delete, etc. | Key Vault Administrator (with escalation warning) |

When multiple permission types are needed, the tool assigns multiple roles following the principle of least privilege.

## Configuration

### Role Mapping Customization

Edit `RoleMapping.json` to customize the permission-to-role mappings:

```json
{
    "secrets": {
        "get": "Key Vault Secrets User",
        "set": "Key Vault Secrets Officer"
    },
    "keys": {
        "get": "Key Vault Crypto User",
        "create": "Key Vault Crypto Officer"
    }
}
```

### Logging

All operations are logged to `.\log\audit.log` with:
- **Info**: General progress and status
- **Warning**: Non-fatal issues and recommendations
- **Error**: Failures and critical issues
- **Decision**: Rationale for security-sensitive choices

**Log Management**: A single `audit.log` file is used for all sessions, providing a comprehensive, structured audit trail for compliance and troubleshooting. Users can manually clean up or archive the log file as needed.

## Architecture

### CLI Surface

The toolkit consists of three main scripts that work side-by-side:

```powershell
# Analysis Phase
.\Invoke-KvRbacAnalysis.ps1 `
    -SubscriptionId <sub> `
    -ResourceGroup <rg> `
    -VaultName <vault1>,<vault2> `
    -TagFilter @{ 'MigrateToRBAC' = 'true' } `
    -OutputFolder .\out `
    [-GenerateAutomationScripts] `
    [-Verbose]

# Permission Analysis Mode (standalone)
.\Invoke-KvRbacAnalysis.ps1 -GetPermissionMapping -PolicyAsJson '{"secrets":["get","list"]}'

# Application Phase
.\Invoke-KvRbacApply.ps1 -InputJson .\out\analysis-YYYYMMDD-HHmmss\analysis.json [-WhatIf]

# Auth Mode Migration Phase (per vault, using Azure CLI or Az PowerShell)
az keyvault update --name 'kv1' --enable-rbac-authorization true
```

### File Structure

```
/KvRbacMigrator
 ├─ Invoke-KvRbacAnalysis.ps1    # Main analysis engine with optimized processing
 ├─ Invoke-KvRbacApply.ps1       # Role assignment application with safety controls
 ├─ Common.ps1                    # Consolidated logging, audit, metrics, and utilities
 ├─ RoleMapping.json              # Comprehensive role mapping configuration
 ├─ README.md                     # Complete user documentation
 └─ QUICKSTART.md                 # Quick start guide
```

### Performance Optimizations

For large deployments (1000+ vaults), the tool uses several optimizations:

| Area | Optimization | Benefit |
|------|-------------|---------|
| **Discovery** | Azure Resource Graph with KQL queries | 10x faster vault enumeration vs ARM API |
| **Principal Resolution** | Bulk API calls with caching | Reduces API calls from N to N/100 |
| **Group Membership** | Transitive Graph API with caching | Detects nested group-inherited assignments |
| **Role Assignment Detection** | Bulk queries with O(1) lookups | Scales linearly with vault count |
| **Permission Mapping** | Pre-computed lookup tables | Sub-millisecond role selection |
| **Memory Management** | Streaming and batching | Handles 1000+ vaults in <2GB RAM |

## Troubleshooting

### Common Issues

**"Must specify exactly one of: VaultName, ResourceGroup, or SubscriptionId"**
- Provide exactly one scope parameter (`-VaultName`, `-ResourceGroup`, or `-SubscriptionId`), not multiple or none.

**"Azure Resource Graph unavailable, falling back to ARM"**
- Install `Az.ResourceGraph` module or ensure proper permissions
- Fallback to ARM still works but may be slower for large scopes

```powershell
# Install Azure Resource Graph module
Install-Module Az.ResourceGraph -Force
```

**"Could not resolve group memberships for principal ..."**
- The tool uses the Microsoft Graph transitive membership API to detect group-inherited role assignments, including nested groups. This warning indicates the Graph API call failed for a specific principal. Ensure the Azure context has `Directory.Read.All` or equivalent permissions.

**Role assignment failures**
- Ensure you have "User Access Administrator" role on the Key Vault
- Check that the principal IDs are valid and haven't been deleted

```powershell
# Test specific vault access
Get-AzKeyVault -VaultName "your-vault-name" -ResourceGroup "your-rg"

# Check current role assignments
Get-AzRoleAssignment -Scope "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault-name"
```

### Performance Tuning

For optimal performance:
- Filter by tags or resource groups to reduce scope
- Ensure Az.ResourceGraph module is installed for fastest discovery
- Monitor memory usage on very large deployments (1000+ vaults)

```powershell
# Monitor memory usage during processing
Get-Process -Name pwsh | Select-Object -ExpandProperty WorkingSet64
```

### Validation Commands

```powershell
# Test prerequisites
Get-Module Az.KeyVault, Az.Resources, Az.Accounts -ListAvailable

# Validate Azure connection
Get-AzContext

# Test ARM template syntax
Test-AzResourceGroupDeployment -ResourceGroup "test-rg" -TemplateFile ".\out\arm-template.json"

# Verify role definitions exist
Get-AzRoleDefinition -Name "Key Vault Secrets User"
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Commit your changes: `git commit -am 'Add my feature'`
5. Push to the branch: `git push origin feature/my-feature`
6. Submit a pull request

## Security

- Scripts run under your existing Azure session - no credentials stored
- Sensitive data is redacted from logs (except object GUIDs needed for troubleshooting)
- All operations are audited through Azure Activity Log
- Report issues through [Microsoft Security Response Center](https://msrc.microsoft.com/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### Current Release
- Transitive group membership resolution via Microsoft Graph API for detecting nested group-inherited role assignments
- Automatic skipping of non-existent principals (deleted users/groups/service principals) during analysis
- Certificates `set` permission mapping to Key Vault Certificates Officer
- Storage permissions mapping to Key Vault Administrator with escalation warnings
- RBAC-enabled vaults filtered out during Azure Resource Graph discovery
- Improved bulk principal resolution and optimized assignment summary
- Complete analysis and migration workflow with optimized performance
- ARM, Bicep, and deployment script generation with revert capabilities
- Enhanced security controls with zero privilege escalation
- Bulk operations and caching for enterprise-scale deployments
- Permission analysis mode for quick role validation

---

**Important:** Always test in non-production environments first. Switching to RBAC disables access policy authorization immediately - ensure proper RBAC roles are assigned before switching authentication modes.

For end-to-end migration guidance, see [Migrate to Azure RBAC from access policies](https://learn.microsoft.com/azure/key-vault/general/rbac-migration) on Microsoft Learn.
