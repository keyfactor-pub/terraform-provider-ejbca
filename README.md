# Terraform Provider for Keyfactor EJBCA

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Terraform provider enables management of EJBCA resources utilizing HashiCorp Terraform.

## Support for Keyfactor EJBCA Terraform Provider

The Keyfactor EJBCA Terraform Provider is open source and there is **no SLA** for this tool/library/client. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
___

## Requirements
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19

### To use
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [Terraform](https://www.terraform.io/downloads.html) >= 1.0

## Installation
### From GitHub (future use)
- Download the latest release from the [releases page](https://github.com/Keyfactor/terraform-provider-ejbca/releases)
- Unzip the release
- Move the binary to a location in your local Terraform plugins directory (typically `$HOME/.terraform.d/plugins` or `%APPDATA%\terraform.d\plugins` on Windows)
  for more information refer to the [Hashicorp documentation](https://www.terraform.io/docs/cli/config/config-file.html#implied-local-mirror-directories)
- Run `terraform init` to initialize the provider

### From Source (Mac OS/Linux)
```bash
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-ejbca
make install
```

### From Source (Windows)
```powershell
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-keyfactor
go build -o %APPDATA%\terraform.d\plugins\keyfactor.com\keyfactor\ejbca\1.0.3\terraform-provider-ejbca.exe
```

## Using the provider

* [Documentation](docs/index.md)
* [Examples](examples)
* [Contributing](CONTRIBUTING.md)
* [License](LICENSE)