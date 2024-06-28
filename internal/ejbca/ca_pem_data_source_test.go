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
