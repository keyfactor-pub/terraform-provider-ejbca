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
	t.Skip()
	// Create a new EndEntity
	endEntityName := "ejbca_terraform_testacc"
	endEntityPassword := "password"
	err := createEndEntityIfNoExist(populateEndEntityTestCase(endEntityName, endEntityPassword))
	if err != nil {
		t.Fatal(err)
	}

	// Configure test
	t1 := keystoresTestCase{
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
				Config: testAccEjbcaKeystore(t1),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Computed fields
					resource.TestCheckResourceAttrSet("ejbca_keystore.keystore_test", "id"),
				),
			},
		},
	})
}

func testAccEjbcaKeystore(tc keystoresTestCase) string {
	return fmt.Sprintf(`
resource "ejbca_keystore" "keystore_test" {
  end_entity_name = "%s"
  end_entity_password = "%s"
  key_alg = "%s"
  key_spec = "%s"
}
`, tc.endEntityName, tc.endEntityPassword, tc.keyAlg, tc.keySpec)
}

func createEndEntityIfNoExist(tc endEntityTestCase) error {
	return nil
}
