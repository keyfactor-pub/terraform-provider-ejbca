package ejbca

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"testing"
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
	t1 := endEntityTestCase{
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
				Config: testAccEjbcaEndEntity(t1),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Computed fields
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "id"),
					resource.TestCheckResourceAttrSet("ejbca_end_entity.end_entity_test", "status"),

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
resource "ejbca_end_entity" "end_entity_test" {
  end_entity_name = "%s"
  end_entity_password = "%s"
  subject_dn = "%s"
  ca_name = "%s"
  certificate_profile_name = "%s"
  end_entity_profile_name = "%s"
}
`, tc.endEntityProfile, tc.endEntityPassword, tc.certificateSubject, tc.certificateAuthority, tc.certificateProfile, tc.endEntityName)
}
