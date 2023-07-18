data "ejbca_authorized_end_entity_profiles" "aeep" {
}

output "aeep" {
  value = data.ejbca_authorized_end_entity_profiles.aeep
}