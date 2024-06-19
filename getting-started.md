# Get started with the Terraform Provider for Keyfactor EJBCA

## System Requirements

### To use
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [Terraform](https://www.terraform.io/downloads.html) >= 1.0
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

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

