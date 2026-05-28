terraform {
  required_providers {
    keyblind = {
      source = "keyblind/keyblind"
    }
  }
}

# Store a secret
resource "keyblind_secret" "openai_key" {
  name  = "OPENAI_API_KEY"
  value = var.openai_api_key
}

# Store another secret
resource "keyblind_secret" "github_token" {
  name  = "GITHUB_TOKEN"
  value = var.github_token
}

# Read a secret from the vault
data "keyblind_secret" "stripe_key" {
  name = "STRIPE_SECRET_KEY"
}

# Use the secret in another resource
output "stripe_key_value" {
  value     = data.keyblind_secret.stripe_key.value
  sensitive = true
}
