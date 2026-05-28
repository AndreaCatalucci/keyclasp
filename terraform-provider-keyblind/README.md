# Terraform Provider: Keyblind

Manage [Keyblind](https://keyblind.dev) encrypted secrets through Terraform.

## Requirements

- [Keyblind CLI](https://keyblind.dev) installed and initialized (`keyblind init`)
- [Terraform](https://www.terraform.io/) >= 1.4
- [Go](https://go.dev/) >= 1.22 (build only)

## Building & Installing

```bash
make install
```

This builds the provider binary and places it in `~/.terraform.d/plugins/registry.terraform.io/keyblind/keyblind/<version>/<os>_<arch>/`.

## Usage

```hcl
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

# Read a secret
data "keyblind_secret" "stripe_key" {
  name = "STRIPE_SECRET_KEY"
}

output "stripe_key_value" {
  value     = data.keyblind_secret.stripe_key.value
  sensitive = true
}
```

## Resources

### `keyblind_secret`

Stores an encrypted secret in the Keyblind vault.

| Attribute | Required | Sensitive | Description |
|-----------|----------|-----------|-------------|
| `name`    | Yes      | No        | Secret name. Changing this recreates the secret. |
| `value`   | Yes      | Yes       | Secret value. |

## Data Sources

### `keyblind_secret`

Reads a secret from the Keyblind vault.

| Attribute | Required | Sensitive | Description |
|-----------|----------|-----------|-------------|
| `name`    | Yes      | No        | Name of the secret to retrieve. |
| `value`   | Computed | Yes       | The secret value. |

## Limitations

- The provider shells out to the `keyblind` CLI, which must be on `$PATH`.
- Secret values are stored in Terraform state. Use a [Terraform Cloud](https://app.terraform.io/) or encrypted remote backend.
- No import support yet. Imported secrets issue a `terraform apply` to reconcile.

## License

MIT — see the main [Keyblind repository](https://github.com/keyblind/keyblind).
