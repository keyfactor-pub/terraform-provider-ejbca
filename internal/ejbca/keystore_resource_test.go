/*
Copyright 2024 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ejbca

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
	rand, err := generateRandomString(20)
	if err != nil {
		t.Fatalf("Error generating random string: %s", err)
	}
	endEntityName := "ejbca_terraform_testacc" + rand
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
resource "ejbca_keystore" "keystore_test" {
  end_entity_name = ejbca_end_entity.end_entity_test.end_entity_name
  end_entity_password = "%s"
  key_alg = "%s"
  key_spec = "%s"
}
`, etc.endEntityName, etc.endEntityPassword, etc.certificateSubject, etc.certificateAuthority, etc.certificateProfile, etc.endEntityProfile, ktc.endEntityPassword, ktc.keyAlg, ktc.keySpec)
}
