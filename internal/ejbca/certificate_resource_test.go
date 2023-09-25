package ejbca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type certificateTestCase struct {
	certificateSubject   string
	endEntityProfile     string
	certificateProfile   string
	certificateAuthority string
	endEntityName        string
	endEntityPassword    string
}

func TestAccCertificateResource(t *testing.T) {

	t1 := certificateTestCase{
		certificateSubject:   os.Getenv("EJBCA_CERTIFICATE_SUBJECT"),
		endEntityProfile:     os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME"),
		certificateProfile:   os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME"),
		certificateAuthority: os.Getenv("EJBCA_CA_NAME"),
		endEntityName:        "ejbca_terraform_testacc",
		endEntityPassword:    "password",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccEjbcaCertificate(t1),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Computed fields
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "id"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "certificate"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "issuer_dn"),

					// User input fields
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "certificate_profile_name"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "end_entity_profile_name"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "certificate_authority_name"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "end_entity_name"),
					resource.TestCheckResourceAttrSet("ejbca_certificate.certificate_test", "end_entity_password"),
				),
			},
			// ImportState testing
			//{
			//    ResourceName:      "scaffolding_example.test",
			//    ImportState:       true,
			//    ImportStateVerify: true,
			//    // This is not normally necessary, but is here because this
			//    // example code does not have an actual upstream service.
			//    // Once the Read method is able to refresh information from
			//    // the upstream service, this can be removed.
			//    ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Certificate has no update method
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccEjbcaCertificate(tc certificateTestCase) string {
	csr, err := generateCSR(tc.certificateSubject)
	if err != nil {
		return ""
	}

	return fmt.Sprintf(`
resource "ejbca_certificate" "certificate_test" {
  certificate_signing_request = <<EOT
%s
EOT
  certificate_profile_name = "%s"
  end_entity_profile_name = "%s"
  certificate_authority_name = "%s"
  end_entity_name = "%s"
  end_entity_password = "%s"
}
`, csr, tc.certificateProfile, tc.endEntityProfile, tc.certificateAuthority, tc.endEntityName, tc.endEntityPassword)
}

func generateCSR(subject string) ([]byte, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return make([]byte, 0), err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return make([]byte, 0), err
	}

	return csrBuf.Bytes(), nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com".
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			if randomizeCn {
				name.CommonName = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
