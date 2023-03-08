package ejbca

import (
    "context"
    "fmt"
    "testing"

    "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccEndEntityProfileDataSource(t *testing.T) {

    eep, err := getRandomAuthorizedEEP()
    if err != nil {
        t.Fatal(err)
    }

    resource.Test(t, resource.TestCase{
        PreCheck:                 func() { testAccPreCheck(t) },
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            // Read testing
            {
                Config: testAccEEPDataSourceConfig(eep),
                Check: resource.ComposeAggregateTestCheckFunc(
                    resource.TestCheckResourceAttr("data.ejbca_end_entity_profile.test", "id", eep),
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
    data "ejbca_end_entity_profile" "test" {
        end_entity_profile_name = "%s"
    }
    `, name)
}

func getRandomAuthorizedEEP() (string, error) {
    client, err := createEjbcaClient()
    if err != nil {
        return "", err
    }

    authorizedEeps, _, err := client.V2EndentityApi.GetAuthorizedEndEntityProfiles(context.Background()).Execute()
    if err != nil {
        return "", err
    }

    for _, profile := range authorizedEeps.GetEndEntitieProfiles() {
        return profile.GetName(), nil
    }

    return "", fmt.Errorf("no authorized EEP found")
}
