resource "azurerm_storage_account" "bad" {
  name                     = "badstorageacct"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only = false
}

resource "azurerm_network_security_rule" "ssh_in" {
  name                        = "allow-ssh-internet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg1"
}
