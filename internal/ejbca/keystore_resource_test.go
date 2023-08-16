package ejbca

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

type keystoresTestCase struct {
	endEntityName     string
	endEntityPassword string
	keyAlg            string
	keySpec           string
}

func TestAccKeystoreResource(t *testing.T) {
	t.Skip("ejbca_keystore is not yet supported")
	// Create a new EndEntity
	endEntityName := "ejbca_terraform_testacc" + generateRandomString(5)
	endEntityPassword := "password"
	endEntityValues := populateEndEntityTestCase(endEntityName, endEntityPassword)

	// Configure test
	ktc1 := keystoresTestCase{
		endEntityName:     endEntityName,
		endEntityPassword: endEntityPassword,
		keyAlg:            "RSA",
		keySpec:           "2048",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccEjbcaKeystore(endEntityValues, ktc1),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Computed fields
					resource.TestCheckResourceAttrSet("ejbca_keystore.keystore_test", "id"),
				),
			},
		},
	})
}

func testAccEjbcaKeystore(etc endEntityTestCase, ktc keystoresTestCase) string {
	return fmt.Sprintf(`
resource "ejbca_end_entity" "end_entity_test" {
  end_entity_name = "%s"
  end_entity_password = "%s"
  subject_dn = "%s"
  ca_name = "%s"
  certificate_profile_name = "%s"
  end_entity_profile_name = "%s"
  token = "P12"
}
resource "ejbca_keystore" "keystore_test" {
  end_entity_name = ejbca_end_entity.end_entity_test.end_entity_name
  end_entity_password = "%s"
  key_alg = "%s"
  key_spec = "%s"
}
`, etc.endEntityName, etc.endEntityPassword, etc.certificateSubject, etc.certificateAuthority, etc.certificateProfile, etc.endEntityProfile, ktc.endEntityPassword, ktc.keyAlg, ktc.keySpec)
}
