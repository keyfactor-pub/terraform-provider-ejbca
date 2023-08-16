# Terraform Provider for Keyfactor EJBCA

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Terraform provider for EJBCA enables management of EJBCA resources with HashiCorp Terraform.

## Support for Keyfactor EJBCA Terraform Provider

The Keyfactor EJBCA Terraform Provider is open source and there is **no SLA** for this tool/library/client. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
___

## Requirements
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
* [Contributing](CONTRIBUTING.md)
* [License](LICENSE)