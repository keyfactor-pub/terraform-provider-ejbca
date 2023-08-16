provider "ejbca" {
  hostname             = "ejbca.example.com" # Hostname to EJBCA server
  client_cert_path     = "/path/to/cert.pem" # Absolute path to client certificate used for authentication to EJBCA
  client_cert_key_path = "/path/to/key.pem"  # Absolute path to private key used for authentication to EJBCA
}