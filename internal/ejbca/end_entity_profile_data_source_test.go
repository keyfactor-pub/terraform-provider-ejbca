package ejbca

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
