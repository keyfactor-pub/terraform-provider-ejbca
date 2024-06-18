package ejbca

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type endEntityTestCase struct {
	endEntityName        string
	endEntityPassword    string
	certificateSubject   string
	endEntityProfile     string
	certificateProfile   string
	certificateAuthority string
}

func TestAccEndEntityResource(t *testing.T) {
	config := getAccTestConfig(t)
	if !config.isEnterprise {
		t.Skip("Skipping End Entity Resource test since connected instance was not flagged as Enterprise")
	}

	rand, err := generateRandomString(20)
	if err != nil {
		t.Fatalf("Error generating random string: %s", err)
	}

	t1 := populateEndEntityTestCase("ejbca_terraform_testacc"+rand, "password")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccEjbcaEndEntity(t1),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Computed fields
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "id"),

					// User inputted fields
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "end_entity_name"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "end_entity_password"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "subject_dn"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "ca_name"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "certificate_profile_name"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "end_entity_profile_name"),
				),
			},
		},
	})
}

func testAccEjbcaEndEntity(tc endEntityTestCase) string {
	return fmt.Sprintf(`
provider "ejbca" {
    cert_auth {}
}

resource "ejbca_end_entity" "end_entity_test" {
  end_entity_name = "%s"
  end_entity_password = "%s"
  subject_dn = "%s"
  ca_name = "%s"
  certificate_profile_name = "%s"
  end_entity_profile_name = "%s"
  token = "P12"
}
`, tc.endEntityName, tc.endEntityPassword, tc.certificateSubject, tc.certificateAuthority, tc.certificateProfile, tc.endEntityProfile)
}

func populateEndEntityTestCase(username string, password string) endEntityTestCase {
	return endEntityTestCase{
		certificateSubject:   fmt.Sprintf("CN=%s", username),
		endEntityProfile:     os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME"),
		certificateProfile:   os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME"),
		certificateAuthority: os.Getenv("EJBCA_CA_NAME"),
		endEntityName:        username,
		endEntityPassword:    password,
	}
}
