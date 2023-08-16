data "ejbca_ca_pem" "ca" {
  dn = "CN=Test CA,O=EJBCA Sample,C=SE"
}

output "ca" {
  value = data.ejbca_ca_pem.ca
}