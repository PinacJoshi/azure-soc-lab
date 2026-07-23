resource "random_id" "suffix" {
  byte_length = 4
}

# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "rg-soc-lab-prod"
  location = "norwayeast"
}

# Log Analytics Workspace (30-day retention for zero storage cost)
resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-soc-${random_id.suffix.hex}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# Microsoft Sentinel Solution
resource "azurerm_log_analytics_solution" "sentinel" {
  solution_name         = "SecurityInsights"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  workspace_resource_id = azurerm_log_analytics_workspace.law.id
  workspace_name        = azurerm_log_analytics_workspace.law.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/SecurityInsights"
  }
}

# Honey-Storage Account (For Blob Deception)
resource "azurerm_storage_account" "honey_sa" {
  name                     = "sthoneypot${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "honey_container" {
  name                  = "confidential-backups"
  storage_account_id    = azurerm_storage_account.honey_sa.id
  container_access_type = "private"
}

# Key Vault (For Secret Deception)
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "honey_kv" {
  name                        = "kv-honeypot-${random_id.suffix.hex}"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge"
    ]
  }
}

# Honey Secret
resource "azurerm_key_vault_secret" "honey_secret" {
  name         = "db-prod-connection-string"
  value        = "Server=tcp:db-prod.database.windows.net;Database=customers;User=admin;Password=FakePassword123!"
  key_vault_id = azurerm_key_vault.honey_kv.id
}


# Diagnostic Settings for Key Vault Audit Logs
resource "azurerm_monitor_diagnostic_setting" "kv_diag" {
  name                       = "kv-audit-to-sentinel"
  target_resource_id         = azurerm_key_vault.honey_kv.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "AuditEvent"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel_onboarding" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}

# Sentinel Analytics Rule (Detection as Code)
resource "azurerm_sentinel_alert_rule_scheduled" "kv_honeypot_alert" {
  name                       = "deception-honey-vault-access"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Deception - Unauthorized Honey-Vault Access Attempt"
  severity                   = "High"
  enabled                    = true

  # ISO 8601 Duration Format: PT5M = Period Time 5 Minutes
  query_frequency   = "PT5M"
  query_period      = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  # MITRE ATT&CK Mapping
  tactics    = ["CredentialAccess"]
  techniques = ["T1552"]

  query = <<-QUERY
    AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where Resource startswith "KV-HONEYPOT"
    | where ResultSignature == "Unauthorized" or httpStatusCode_d == 401 or httpStatusCode_d == 403
    | project TimeGenerated, Resource, OperationName, requestUri_s, CallerIPAddress, ResultSignature, httpStatusCode_d
  QUERY
}