package ejbca

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAuthorizedEndEntityProfilesDataSource(t *testing.T) {
	config := getAccTestConfig(t)
	if !config.isEnterprise {
		t.Skip("Skipping Authorized End Entity Profile Data Source Test since connected instance was not flagged as Enterprise")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccAuthorizedEEPDataSourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ejbca_authorized_end_entity_profiles.aeep", "authorized_end_entity_profiles.#"),
					resource.TestCheckResourceAttrSet("data.ejbca_authorized_end_entity_profiles.aeep", "id"),
				),
			},
		},
	})
}

const testAccAuthorizedEEPDataSourceConfig = `
provider "ejbca" {
    cert_auth {}
}

data "ejbca_authorized_end_entity_profiles" "aeep" {
}`
