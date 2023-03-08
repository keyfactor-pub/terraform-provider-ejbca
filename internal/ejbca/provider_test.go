package ejbca

import (
    "math/rand"
    "os"
    "testing"
    "time"

    "github.com/hashicorp/terraform-plugin-framework/providerserver"
    "github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories are used to instantiate a ejbca during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a ejbca server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
    "ejbca": providerserver.NewProtocol6WithError(New("test")()),
}

/*
EJBCA_HOSTNAME=https://it-ca01.pkihosted-dev.c2company.com/ejbca/;EJBCA_CLIENT_CERT_PATH=C:\Users\hroszell\OneDrive - Keyfactor\Documents\coding\EJBCA\certs\adminHaydenRoszell.pem;TF_ACC=1;EJBCA_CERTIFICATE_SUBJECT=CN=ejbca_tf_testacc,OU=IT;EJBCA_END_ENTITY_PROFILE_NAME=haydenEndEntity;EJBCA_CERTIFICATE_PROFILE_NAME=tlsServerAuth;EJBCA_CA_NAME=ManagementCA
*/

func testAccPreCheck(t *testing.T) {
    // Check for environment variables
    if v := os.Getenv("EJBCA_HOSTNAME"); v == "" {
        t.Fatal("EJBCA_HOSTNAME must be set for acceptance tests")
    }
    if v := os.Getenv("EJBCA_CLIENT_CERT_PATH"); v == "" {
        t.Fatal("EJBCA_CLIENT_CERT_PATH must be set for acceptance tests")
    }
    if v := os.Getenv("EJBCA_CERTIFICATE_SUBJECT"); v == "" {
        t.Fatal("EJBCA_CERTIFICATE_SUBJECT must be set for acceptance tests")
    }
    if v := os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME"); v == "" {
        t.Fatal("EJBCA_END_ENTITY_PROFILE_NAME must be set for acceptance tests")
    }
    if v := os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME"); v == "" {
        t.Fatal("EJBCA_CERTIFICATE_PROFILE_NAME must be set for acceptance tests")
    }
    if v := os.Getenv("EJBCA_CA_NAME"); v == "" {
        t.Fatal("EJBCA_CA_NAME must be set for acceptance tests")
    }
}

func generateRandomString(length int) string {
    rand.Seed(time.Now().UnixNano())
    letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    b := make([]rune, length)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}
