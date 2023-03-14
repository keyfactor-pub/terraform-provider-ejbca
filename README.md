# Terraform Provider for Keyfactor EJBCA

The Terraform provider enables management of EJBCA resources utilizing HashiCorp Terraform.

## Support for Keyfactor EJBCA Terraform Provider

The Keyfactor EJBCA Terraform Provider is open source and there is **no SLA** for this tool/library/client. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
___

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.18


## Installation

### From GitHub
- Download the latest release from the [releases page](https://github.com/Keyfactor/terraform-provider-ejbca/releases)
- Unzip the release
- Move the binary to a location in your local Terraform plugins directory (typically `$HOME/.terraform.d/plugins` or `%APPDATA%\terraform.d\plugins` on Windows)
  for more information refer to the [Hashicorp documentation](https://www.terraform.io/docs/cli/config/config-file.html#implied-local-mirror-directories)
- Run `terraform init` to initialize the provider

### From Source (Mac OS/Linux)
```bash
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-keyfactor
make install
```

### From Source (Windows)
```powershell
git clone https://github.com/Keyfactor/terraform-provider-ejbca.git
cd terraform-provider-keyfactor
go build -o %APPDATA%\terraform.d\plugins\keyfactor.com\keyfactor\keyfactor\1.0.3\terraform-provider-keyfactor.exe
```

## Using the provider

* [Documentation](docs/index.md)
* [Examples](examples)
* [Contributing](CONTRIBUTING.md)
* [License](LICENSE)

## Contributing
The Keyfactor EJBCA Terraform Provider is an open source project. To contribute, see the [contribution guidelines](https://github.com/Keyfactor/terraform-provider-keyfactor/blob/main/CONTRIBUTING.md).
[Issues](../../issues) may also be reported.