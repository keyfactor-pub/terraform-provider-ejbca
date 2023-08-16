resource "ejbca_end_entity" "end_entity" {
  end_entity_name          = "kfdelivery"
  end_entity_password      = "sTr0nGP@ssw0rd"
  subject_dn               = "CN=Keyfactor Delivery,O=Keyfactor,L=Minneapolis,ST=MN,C=US"
  ca_name                  = "IT-Sub-CA"
  certificate_profile_name = "ephemeralCertificateProfile"
  end_entity_profile_name  = "KeyfactorDelivery"
  token                    = "P12" # The token MUST be P12 for the keystore resource to work
}
resource "ejbca_keystore" "keystore" {
  end_entity_name     = ejbca_end_entity.end_entity.end_entity_name
  end_entity_password = ejbca_end_entity.end_entity.end_entity_password
  key_alg             = "RSA"
  key_spec            = "2048"
}