# v1.0.0
## Features
* First public release of EJBCA Terraform Provider
    * Create and manage state of certificates requested from EJBCA. The ejbca_certificate resource requires a PEM-encoded PKCS#10 certificate, and uses the EJBCA PKCS#10 Enrollment endpoint. The end-entity, specified by end_entity_name, is either created in EJBCA or used for enrollment if it already exists.
    * EJBCA Community & EJBCA Enterprise are both supported.

# v1.1.0
## Features
* mTLS and OAuth now supported authentication mechanisms
 
