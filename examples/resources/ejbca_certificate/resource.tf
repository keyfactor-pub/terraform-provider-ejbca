# Create a private key
resource "tls_private_key" "rsa_4096" {
  # Create a private key for the certificate request.
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Create a new CSR
resource "tls_cert_request" "csr" {
  # Create a CSR using the TLS private key above
  private_key_pem = tls_private_key.rsa_4096.private_key_pem

  subject {
    common_name         = "mycsr.kfdelivery.com"
    organizational_unit = "IT"
  }
}

# Sign the CSR with EJBCA
resource "ejbca_certificate" "Certificate" {
  certificate_signing_request = tls_cert_request.csr.cert_request_pem
  certificate_profile_name    = "tlsServerAuth"
  end_entity_profile_name     = "endEntityProfileName"
  certificate_authority_name  = "ManagementCA"
  end_entity_name             = "ejbca_tf_demo"
  account_binding_id          = "abc123"
  early_renewal_hours         = 36
}
