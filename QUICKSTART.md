# KvRbacMigrator Quick Start

This guide provides the essential steps to get started with the KvRbacMigrator toolkit. For detailed documentation, please see the [README.md](../README.md).

## 1. Prerequisites

- **PowerShell 7.0+** (Windows, Linux, or macOS)
- **Azure PowerShell modules:**
  - `Az.KeyVault`
  - `Az.Resources`
  - `Az.Accounts`
  - `Az.ResourceGraph` (recommended)
- **Permissions:**
  - Key Vault Reader (for analysis)
  - User Access Administrator (for role assignments)

## 2. Installation

```powershell
# Install required Azure PowerShell modules
Install-Module Az.KeyVault, Az.Resources, Az.Accounts, Az.ResourceGraph -Force

# Connect to Azure
Connect-AzAccount
```

## Important Notes

- The tool analyzes and suggests Key Vault-level role assignments. It does not account for effective permissions inherited from subscription-level role assignments, so duplicate role suggestions can occur. If a principal already receives required access through subscription-level roles, skip creating the suggested vault-level duplicate assignments.
- The tool runs at subscription scope (or narrower scopes such as resource group or vault) and does not support tenant-scope execution.
- The least-privilege mappings are recommendations, not guarantees. Review all suggested role assignments before applying them to avoid over-permissioning or under-permissioning.
- Use the audit functionality throughout planning and rollout to validate decisions and support a smooth migration.

## 3. Migration Workflow

The migration process involves three main steps:

### Step 1: Analyze Key Vaults

Analyze your Key Vaults to generate a migration plan. By default, the analysis creates reports in the `.\out` directory. To generate deployment scripts, add the `-GenerateAutomationScripts` flag.

```powershell
# Analyze all vaults in a resource group (reports only)
.\Invoke-KvRbacAnalysis.ps1 -ResourceGroup "my-keyvaults-rg"

# Analyze specific vaults and generate automation scripts
.\Invoke-KvRbacAnalysis.ps1 -VaultName "kv-prod-01","kv-prod-02" -GenerateAutomationScripts
```

### Step 2: Apply Role Assignments

Apply the generated RBAC role assignments from the analysis file.

```powershell
# Preview changes using the -WhatIf parameter
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-YYYYMMDD-HHmmss\analysis.json" -WhatIf

# Apply the changes (will prompt for confirmation per vault)
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-YYYYMMDD-HHmmss\analysis.json"

# Apply all without confirmation prompts (use with caution)
.\Invoke-KvRbacApply.ps1 -InputJson ".\out\analysis-YYYYMMDD-HHmmss\analysis.json" -Confirm:$false
```

### Step 3: Switch Authentication Mode

After verifying the new RBAC roles, switch each Key Vault's authentication mode using the Azure CLI or Az PowerShell.

```powershell
# Azure CLI
az keyvault update --name "kv-prod-01" --enable-rbac-authorization true

# Az PowerShell
Update-AzKeyVault -VaultName "kv-prod-01" -ResourceGroupName "my-keyvaults-rg" -EnableRbacAuthorization $true
```

**⚠️ Important:** Always test in non-production environments first. Switching to RBAC disables access policy authorization immediately.

## Permission Analysis Mode

Use the `-GetPermissionMapping` mode to quickly determine the recommended RBAC role(s) for a given set of permissions without performing a full vault analysis. This is ideal for developers and security engineers who need to validate access requirements.

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

**Output Example:**
```
Recommended Roles:
- Key Vault Secrets User
- Key Vault Crypto User
- Key Vault Certificate User
```

## Next Steps

For advanced usage, including large-scale migrations, CI/CD integration, and configuration, please refer to the full [README.md](../README.md).