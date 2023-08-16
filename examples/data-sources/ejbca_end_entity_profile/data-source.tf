data "ejbca_end_entity_profile" "eep" {
  end_entity_profile_name = "endEntityProfileName"
}

output "eep" {
  value = data.ejbca_end_entity_profile.eep
}