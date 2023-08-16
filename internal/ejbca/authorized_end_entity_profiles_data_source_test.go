package ejbca

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccAuthorizedEndEntityProfilesDataSource(t *testing.T) {

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

const testAccAuthorizedEEPDataSourceConfig = `data "ejbca_authorized_end_entity_profiles" "aeep" {
}`
