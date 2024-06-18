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
