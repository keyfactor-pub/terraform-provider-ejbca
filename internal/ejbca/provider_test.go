package ejbca

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

type fakeEjbcaAuthenticator struct {
	client *http.Client
}

// GetHTTPClient implements ejbcaclient.Authenticator
func (f *fakeEjbcaAuthenticator) GetHTTPClient() (*http.Client, error) {
	return f.client, nil
}

type fakeClientConfig struct {
	testServer *httptest.Server
}

func (f *fakeClientConfig) newFakeAuthenticator(_ context.Context, _ ProviderModel, _ diag.Diagnostics) ejbca.Authenticator {
	return &fakeEjbcaAuthenticator{
		client: f.testServer.Client(),
	}
}

// testAccProtoV6ProviderFactories are used to instantiate a ejbca during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a ejbca server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ejbca": providerserver.NewProtocol6WithError(New("test")()),
}

type ejbcaAccTestConfig struct {
	hostname               string
	clientCertPath         string
	clientKeyPath          string
	caName                 string
	caDn                   string
	endEntityProfileName   string
	certificateProfileName string
	certificateSubject     string
    isEnterprise           bool
}

func getAccTestConfig(t *testing.T) ejbcaAccTestConfig {
	var config ejbcaAccTestConfig

	// Check for environment variables
	if v := os.Getenv("EJBCA_HOSTNAME"); v == "" {
		t.Fatal("EJBCA_HOSTNAME must be set for acceptance tests")
	} else {
		config.hostname = v
	}
	if v := os.Getenv("EJBCA_CLIENT_CERT_PATH"); v == "" {
		t.Fatal("EJBCA_CLIENT_CERT_PATH must be set for acceptance tests")
	} else {
		config.clientCertPath = v
	}
	if v := os.Getenv("EJBCA_CERTIFICATE_SUBJECT"); v == "" {
		t.Fatal("EJBCA_CERTIFICATE_SUBJECT must be set for acceptance tests")
	} else {
		config.certificateSubject = v
	}
	if v := os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME"); v == "" {
		t.Fatal("EJBCA_END_ENTITY_PROFILE_NAME must be set for acceptance tests")
	} else {
		config.endEntityProfileName = v
	}
	if v := os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME"); v == "" {
		t.Fatal("EJBCA_CERTIFICATE_PROFILE_NAME must be set for acceptance tests")
	} else {
		config.certificateProfileName = v
	}
	if v := os.Getenv("EJBCA_CA_NAME"); v == "" {
		t.Fatal("EJBCA_CA_NAME must be set for acceptance tests")
	} else {
		config.caName = v
	}
	if v := os.Getenv("EJBCA_CA_DN"); v == "" {
		t.Fatal("EJBCA_CA_DN must be set for acceptance tests")
	} else {
		config.caDn = v
	}
    if v := os.Getenv("EJBCA_IS_ENTERPRISE"); v != "" {
        config.isEnterprise = true
    }
	return config
}

func testAccPreCheck(t *testing.T) {
	// getAccTestConfig will fail the test if any of the required environment variables are not set
	getAccTestConfig(t)
}
