---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ejbca Provider"
subcategory: ""
description: |-
  The EJBCA Terraform provider extends Terraform to interact with EJBCA. The provider can authenticate to EJBCA using mTLS (client certificate) or using the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).
  Requirements
  EJBCA Community https://www.ejbca.org/ or EJBCA Enterprise https://www.keyfactor.com/products/ejbca-enterprise/
  The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration.
  EJBCA Enterprise is required for the OAuth 2.0 "client credentials" token flow. EJBCA Community only supports mTLS (client certificate) authentication.
---

# ejbca Provider

The EJBCA Terraform provider extends Terraform to interact with EJBCA. The provider can authenticate to EJBCA using mTLS (client certificate) or using the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

### Requirements

* EJBCA [Community](https://www.ejbca.org/) or EJBCA [Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/)
  * The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration.

> EJBCA Enterprise is required for the OAuth 2.0 "client credentials" token flow. EJBCA Community only supports mTLS (client certificate) authentication.

## Example Usage

```terraform
provider "ejbca" {
  hostname     = "ejbca.example.com" # Hostname to EJBCA server
  ca_cert_path = "/path/to/ca.pem"   # Absolute path to CA certificate used to verify EJBCA server certificate

  # The cert_auth block must be present if client certificate authentication is used. If the *_path attributes
  # are provided via environment variables, the cert_auth block must still be present.
  cert_auth {
    client_cert_path     = "/path/to/cert.pem" # Absolute path to client certificate used for authentication to EJBCA
    client_cert_key_path = "/path/to/key.pem"  # Absolute path to private key used for authentication to EJBCA
  }

  # The oauth block must be present if OAuth2 authentication is used. The oauth block must be present even if all
  # configuration attributes are configured using environment variables.
  oauth {
    token_url     = "https://dev.idp.com/oauth/token"
    client_id     = "<client_id>"
    client_secret = "<client_secret>"
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `ca_cert_path` (String) The path to the CA certificate file used to validate the EJBCA server's certificate. Certificates must be in PEM format.
- `cert_auth` (Block, Optional) An object containing configuration on where the provider should read the client certificate/private key from. Required if Client Cert Auth is used. (see [below for nested schema](#nestedblock--cert_auth))
- `hostname` (String) Hostname of the EJBCA instance. Hostname can include the port in the format {hostname}:{port}. If not specified, the environment variable EJBCA_HOSTNAME will be used.
- `oauth` (Block, Optional) An object containing configuration for OAuth 2.0 authentication. Required if OAuth 2.0 is used. (see [below for nested schema](#nestedblock--oauth))

<a id="nestedblock--cert_auth"></a>
### Nested Schema for `cert_auth`

Optional:

- `client_cert_path` (String) Local path to the client certificate used to authenticate to EJBCA. File must include a PEM formatted X509v3 certificate, and optionally an unencrypted, PEM formatted PKCS#8 private key. If not specified, the environment variable EJBCA_CLIENT_CERT_PATH will be used.
- `client_key_path` (String) Local path to the private key of the client certificate. Must be an unencrypted, PEM formatted PKCS#8 private key. If not specified, the environment variable EJBCA_CLIENT_CERT_KEY_PATH will be used.


<a id="nestedblock--oauth"></a>
### Nested Schema for `oauth`

Optional:

- `audience` (String) The OAuth 2.0 audience used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_AUDIENCE will be used.
- `client_id` (String) The OAuth 2.0 client ID used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_CLIENT_ID will be used.
- `client_secret` (String) The OAuth 2.0 client secret used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_CLIENT_SECRET will be used.
- `scopes` (String) A comma-separated list of OAuth 2.0 scopes used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_SCOPES will be used.
- `token_url` (String) The OAuth 2.0 token URL used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_TOKEN_URL will be used.
