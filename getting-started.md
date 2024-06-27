# Get started with the Terraform Provider for Keyfactor EJBCA

## System Requirements

* [EJBCA](https://ejbca.org) (>= 7.10)
* [Terraform](https://www.terraform.io/downloads) (>= 1.0)
* [Go](https://go.dev/doc/install) (1.22.3)
* [GNU Make](https://www.gnu.org/software/make/)

> The Terraform Provider for EJBCA uses [Terraform Plugin Protocol version 6](https://developer.hashicorp.com/terraform/plugin/terraform-plugin-protocol) and is only compatible with Terraform 1.0 and later.

## Installation
The first step of installing the Keyfactor EJBCA Terraform Provider is to require the provider in your Terraform configuration file.
```terraform
terraform {
  required_providers {
    ejbca = {
      source  = "registry.terraform.io/keyfactor-pub/ejbca"
    }
  }
}
```

### From Terraform Registry
Run `terraform init` to initialize the provider. Terraform will automatically download the provider and install it in the
`.terraform` directory in your current working directory.

### From Source (Mac OS/Linux)
To build and install the provider from source, clone the repository to your local machine and configure Terraform manually.

1. Clone the GitHub repo and compile the provider.

    ```shell
    git clone https://github.com/keyfactor-pub/terraform-provider-ejbca.git
    cd terraform-provider-ejbca
    make build
    ```

2. Move the binary to the plugin directory

    ```shell
    mkdir -p "$HOME/.terraform.d/plugins/registry.terraform.io/keyfactor-pub/ejbca/1.0.0/$(go env GOOS)_$(go env GOARCH)"
    mv "bin/terraform-provider-ejbca" "$HOME/.terraform.d/plugins/registry.terraform.io/keyfactor-pub/ejbca/1.0.0/$(go env GOOS)_$(go env GOARCH)"
    ```

3. Create or modify a `.terraformrc` file

    ```shell
    cat <<EOF > "$HOME/.terraformrc"
    provider_installation {
        filesystem_mirror {
            path    = "$HOME/.terraform.d/plugins"
            include = ["registry.terraform.io/keyfactor-pub/ejbca"]
        }
        direct {
            exclude = ["registry.terraform.io/keyfactor-pub/ejbca"]
        }
    }
    EOF
    ```

4. Initialize the provider

    ```shell
    [ -f .terraform.lock.hcl ] && echo "Removing .terraform.lock.hcl" && rm .terraform.lock.hcl
    terraform init -upgrade
    ```

## Using the provider

* [Documentation](index.md)
* [Examples](../examples)

