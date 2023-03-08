package ejbca

import (
    "testing"

    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccExampleDataSource(t *testing.T) {
    t.Skip()
    resource.Test(t, resource.TestCase{
        PreCheck:                 func() { testAccPreCheck(t) },
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            // Read testing
            {
                Config: testAccExampleDataSourceConfig,
                Check: resource.ComposeAggregateTestCheckFunc(
                    resource.TestCheckResourceAttr("data.scaffolding_example.test", "id", "example-id"),
                ),
            },
        },
    })
}

const testAccExampleDataSourceConfig = `
data "scaffolding_example" "test" {
  configurable_attribute = "example"
}
`
