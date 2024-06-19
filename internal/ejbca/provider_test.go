package ejbca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/require"
)

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
	if v := os.Getenv("EJBCA_CLIENT_CERT_KEY_PATH"); v == "" {
		t.Fatal("EJBCA_CLIENT_CERT_KEY_PATH must be set for acceptance tests")
	} else {
		config.clientKeyPath = v
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

func TestValidateProviderConfig(t *testing.T) {
	t.Parallel()

	caCert, _ := issueTestCertificates(t)
	caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	clientCert, clientKey := issueTestCertificates(t)
	clientCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})

	keyByte, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyByte})

	for i, tt := range []struct {
		name              string
		getEnv            getEnvFunc
		readFile          readFileFunc
		providerConfigHcl string

		expectError                bool
		expectedErrorMessageRegexp string
	}{
		{
			name: "No Auth Method",
			providerConfigHcl: `
            provider "ejbca" {

            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "No authentication method specified",
		},
		{
			name: "Cert Auth but no Cert Path",
			providerConfigHcl: `
            provider "ejbca" {
                cert_auth {
					client_key_path = "/path/to/key.pem"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Client certificate is required for mTLS authentication",
		},
		{
			name: "Cert Auth no Key Path",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                cert_auth {
					client_cert_path = "/path/to/cert.crt"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Client key is required for mTLS authentication",
		},
		{
			name: "OAuth Auth but no Token URL",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Token URL is required for OAuth authentication",
		},
		{
			name: "OAuth Auth but no Client ID",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Client ID is required for OAuth authentication",
		},
		{
			name: "OAuth Auth but no Client Secret",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                cert_auth {
                    client_cert_path = "/path/to/cert.crt"
                    client_key_path = "/path/to/key.pem"
                }
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Client secret is required for OAuth authentication",
		},
		{
			name: "Cert Auth can't find CA",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
				ca_cert_path = "/path/to/ca.crt"
                cert_auth {
                    client_cert_path = "/path/to/cert.crt"
                    client_key_path = "/path/to/key.pem"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(key string) ([]byte, error) {
				if key == "/path/to/cert.crt" {
					return clientCertPem, nil
				}
				if key == "/path/to/key.pem" {
					return keyPem, nil
				}
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Failed to read CA chain from file",
		},
		{
			name: "Cert Auth can't find Client Cert",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
				ca_cert_path = "/path/to/ca.crt"
                cert_auth {
                    client_cert_path = "/path/to/cert.crt"
                    client_key_path = "/path/to/key.pem"
                }
            }
            `,
			readFile: func(key string) ([]byte, error) {
				if key == "/path/to/ca.crt" {
					return caCertPem, nil
				}
				if key == "/path/to/key.pem" {
					return keyPem, nil
				}
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Failed to read client certificate from file",
		},
		{
			name: "Cert Auth can't find Client Key",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                cert_auth {
                    client_cert_path = "/path/to/cert.crt"
                    client_key_path = "/path/to/key.pem"
                }
            }
            `,
			getEnv: func(_ string) string {
				return ""
			},
			readFile: func(key string) ([]byte, error) {
				if key == "/path/to/cert.crt" {
					return clientCertPem, nil
				}
				return nil, errors.New("file not found")
			},

			expectError:                true,
			expectedErrorMessageRegexp: "Failed to read client key from file",
		},
		{
			name: "Cert Auth CA, Client Cert, and Client Key from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                cert_auth {
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_CA_CERT_PATH" {
					return "/path/to/ca.crt"
				}
				if key == "EJBCA_CLIENT_CERT_PATH" {
					return "/path/to/cert.crt"
				}
				if key == "EJBCA_CLIENT_CERT_KEY_PATH" {
					return "/path/to/key.pem"
				}
				return ""
			},
			readFile: func(key string) ([]byte, error) {
				if key == "/path/to/ca.crt" {
					return caCertPem, nil
				}
				if key == "/path/to/cert.crt" {
					return clientCertPem, nil
				}
				if key == "/path/to/key.pem" {
					return keyPem, nil
				}
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
		{
			name: "Token URL from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                    scopes = "read:certificates,write:certificates"
                    audience = "https://ejbca.example.com"
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_OAUTH_TOKEN_URL" {
					return "https://dev.idp.com/oauth/token"
				}
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
		{
			name: "Client ID from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                    scopes = "read:certificates,write:certificates"
                    audience = "https://ejbca.example.com"
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_OAUTH_CLIENT_ID" {
					return "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
				}
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
		{
			name: "Client Secret from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                    scopes = "read:certificates,write:certificates"
                    audience = "https://ejbca.example.com"
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_OAUTH_CLIENT_SECRET" {
					return "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
				}
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
		{
			name: "Scopes from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                    audience = "https://ejbca.example.com"
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_OAUTH_SCOPES" {
					return "read:certificates,write:certificates"
				}
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
		{
			name: "Audience from env",
			providerConfigHcl: `
            provider "ejbca" {
                hostname = "ejbca.example.com"
                oauth {
                    token_url = "https://dev.idp.com/oauth/token"
                    client_id = "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"
                    client_secret = "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"
                    scopes = "read:certificates,write:certificates"
                }
            }
            `,
			getEnv: func(key string) string {
				if key == "EJBCA_OAUTH_AUDIENCE" {
					return "https://ejbca.example.com"
				}
				return ""
			},
			readFile: func(_ string) ([]byte, error) {
				return nil, errors.New("file not found")
			},

			expectError:                false,
			expectedErrorMessageRegexp: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				version: "test",
			}
			// We want to use the actual newAuthenticator func implemented by Provider instead of a fake.
			p.hooks.newAuthenticator = p.newAuthenticator
			p.hooks.getEnv = tt.getEnv
			p.hooks.readFile = tt.readFile

			// NewFakeProvider returns a fully functional Terraform provider that wraps the primary EJBCA provider.
			// We want to isolate the Configure method for this test, which we can't do with the
			// terraform-plugin-test unless we declare a data source or resource in the HCL config file.
			fake := NewFakeProviderWithNoopDataSource(p)

			// We append the expected datasource config HCL to the provider config string
			// to force Terraform to load the provider configuration via *Provider.Configure
			runtimeConfig := fmt.Sprintf("%s\n\n%s", tt.providerConfigHcl, fake.GetDataSourceConfig())

			testStep := resource.TestStep{
				Config: runtimeConfig,
			}
			if tt.expectError {
				testStep.ExpectError = regexp.MustCompile(tt.expectedErrorMessageRegexp)
				t.Logf("\ntestcase[%d] and expected error:%+v\n", i, tt.expectedErrorMessageRegexp)
			} else {
				t.Logf("\ntestcase[%d] and no error expected\n", i)
			}

			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"ejbca": providerserver.NewProtocol6WithError(fake),
				},
				Steps: []resource.TestStep{
					testStep,
				},
			})
		})
	}
}

func issueTestCertificates(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	var err error
	var key *ecdsa.PrivateKey
	now := time.Now()

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey := &key.PublicKey
	signerPrivateKey := key

	serial, _ := rand.Int(rand.Reader, big.NewInt(1337))
	certTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Fake-Root-CA"},
		SerialNumber:          serial,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
	}

	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, publicKey, signerPrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certData)
	require.NoError(t, err)

	return cert, key
}
