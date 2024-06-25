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
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
    t.Skip("ejbca_end_entity is not yet supported")
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
