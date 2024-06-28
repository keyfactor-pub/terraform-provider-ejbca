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

func TestAccEndEntityProfileDataSource(t *testing.T) {
	config := getAccTestConfig(t)
	if !config.isEnterprise {
		t.Skip("Skipping End Entity Profile Data Source Test since connected instance was not flagged as Enterprise")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccEEPDataSourceConfig(config.endEntityProfileName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ejbca_end_entity_profile.test", "id", config.endEntityProfileName),
					resource.TestCheckResourceAttrSet("data.ejbca_end_entity_profile.test", "subject_distinguished_name_fields.#"),
					resource.TestCheckResourceAttrSet("data.ejbca_end_entity_profile.test", "subject_alternative_name_fields.#"),
					resource.TestCheckResourceAttrSet("data.ejbca_end_entity_profile.test", "available_certificate_profiles.#"),
					resource.TestCheckResourceAttrSet("data.ejbca_end_entity_profile.test", "available_cas.#"),
				),
			},
		},
	})
}

func testAccEEPDataSourceConfig(name string) string {
	return fmt.Sprintf(`
provider "ejbca" {
    cert_auth {}
}

data "ejbca_end_entity_profile" "test" {
    end_entity_profile_name = "%s"
}
    `, name)
}
