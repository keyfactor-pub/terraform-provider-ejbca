package ejbca

import (
    "context"
    "fmt"
    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
    "testing"
)

func TestAccCaPemDataSource(t *testing.T) {
    dn, err := getRandomAuthorizedCa()
    if err != nil {
        t.Fatal(err)
    }
    resource.Test(t, resource.TestCase{
        PreCheck:                 func() { testAccPreCheck(t) },
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            // Read testing
            {
                Config: testAccCaPemDataSourceConfig(dn),
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
data "ejbca_ca_pem" "test" {
    dn = "%s"
}`, dn)
}

func getRandomAuthorizedCa() (string, error) {
    client, err := createEjbcaClient()
    if err != nil {
        return "", err
    }

    authorizedCas, _, err := client.V1CaApi.ListCas(context.Background()).Execute()
    if err != nil {
        return "", err
    }

    for _, ca := range authorizedCas.GetCertificateAuthorities() {
        return ca.GetIssuerDn(), nil
    }

    return "", fmt.Errorf("no authorized CA found")
}
