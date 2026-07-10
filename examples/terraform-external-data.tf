# ILLUSTRATIVE ONLY — insecure defaults for demos.
# Do not use these patterns with production credentials or live firewall rules as-is.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# 1. We use the external data source to execute the WGPL CLI locally.
# We pipe the JSON output of 'wgpl peer list' into 'jq' to extract
# all active peer IPs and format them as a JSON array of strings
# that Terraform can ingest.
data "external" "wg_peers" {
  program = ["bash", "-c", "wgpl -j peer list | jq -r '{ips: [.[] | .ip_address + \"/32\"] | join(\",\")}'"]
}

# 2. Extract the comma-separated IPs into a Terraform list
# If WGPL is empty, 'ips' will be blank, so we safely fallback to an empty list.
locals {
  peer_ips = data.external.wg_peers.result["ips"] != "" ? split(",", data.external.wg_peers.result["ips"]) : []
}

# 3. Create a Cloud Firewall (AWS Security Group)
# We dynamically allow SSH access ONLY to active WireGuard peers!
resource "aws_security_group" "private_db_access" {
  name        = "wireguard-internal-access"
  description = "Allow inbound SSH traffic only from active VPN peers"
  vpc_id      = "vpc-12345678" # Replace with your VPC ID

  ingress {
    description = "SSH from WGPL Peers"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # Dynamically inject the VPN IPs!
    # If a peer expires in WGPL, Terraform will remove them from the firewall
    # on the next 'terraform apply'.
    cidr_blocks = local.peer_ips
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "allowed_vpn_ips" {
  value = local.peer_ips
}
