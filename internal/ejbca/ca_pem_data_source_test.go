package ejbca

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccCaPemDataSource(t *testing.T) {
    config := getAccTestConfig(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccCaPemDataSourceConfig(config.caDn),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ejbca_ca_pem.test", "ca_pem"),
					resource.TestCheckResourceAttrSet("data.ejbca_ca_pem.test", "id"),
				),
			},
		},
	})
}

func testAccCaPemDataSourceConfig(dn string) string {
	return fmt.Sprintf(`
provider "ejbca" {
    cert_auth {}
}

data "ejbca_ca_pem" "test" {
    dn = "%s"
}`, dn)
}
