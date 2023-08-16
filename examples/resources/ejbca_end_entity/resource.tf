# EJBCA End Entity
resource "ejbca_end_entity" "test_end_entity" {
  end_entity_name          = "keyfactor_delivery"
  end_entity_password      = "password"
  subject_dn               = "CN=haydenEndEntity_tftest4"
  ca_name                  = "IT-Sub-CA"
  certificate_profile_name = "tlsServerAuth"
  end_entity_profile_name  = "haydenEndEntity"
  token                    = "P12"
}