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
The Makefile takes care of these steps for you by adding a `provider_installation` block to your `~/.terraformrc` file.

```bash
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-ejbca
make local-config install
```

###### Be cautious when running `make uninstall-local` as it will remove all custom installation (`provider_installation`) steps in the `~/.terraformrc` file.

### From Source (Windows)
```powershell
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-ejbca
go build -o %APPDATA%\terraform.d\plugins\registry.terraform.io\keyfactor-pub\ejbca\1.0.0\terraform-provider-ejbca.exe
terraform init -upgrade
```

## Using the provider

* [Documentation](docs/index.md)
* [Examples](examples)

