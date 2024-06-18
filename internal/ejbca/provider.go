package ejbca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure Provider satisfies the Terraform Provider interfaces.
var _ provider.Provider = &Provider{}

type newEjbcaAuthenticatorFunc func(context.Context, ProviderModel) (ejbca.Authenticator, diag.Diagnostics)
type getEnvFunc func(string) string
type readFileFunc func(string) ([]byte, error)

// Provider defines the ejbca implementation.
type Provider struct {
	// version is set to the ejbca version on release, "dev" when the
	// ejbca is built and ran locally, and "test" when running acceptance
	// testing.
	version string

	hooks struct {
		newAuthenticator newEjbcaAuthenticatorFunc
		getEnv           getEnvFunc
		readFile         readFileFunc
	}
}

// ProviderModel describes the ejbca provider data model.
type ProviderModel struct {
	Hostname   types.String `tfsdk:"hostname"`
	CaCertPath types.String `tfsdk:"ca_cert_path"`
	CertAuth   types.Object `tfsdk:"cert_auth"`
	OAuth      types.Object `tfsdk:"oauth"`
}

type OAuthProviderModel struct {
	TokenURL     types.String `tfsdk:"token_url"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Scopes       types.String `tfsdk:"scopes"`
	Audience     types.String `tfsdk:"audience"`
}

type CertAuthProviderModel struct {
	ClientCertPath types.String `tfsdk:"client_cert_path"`
	ClientKeyPath  types.String `tfsdk:"client_key_path"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ejbca"
	resp.Version = p.version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: providerMarkdownDescription,
		Blocks: map[string]schema.Block{
			"oauth": schema.SingleNestedBlock{
				Description: "An object containing configuration for OAuth 2.0 authentication. Required if OAuth 2.0 is used.",
				Attributes: map[string]schema.Attribute{
					"token_url": schema.StringAttribute{
						Optional:    true,
						Description: "The OAuth 2.0 token URL used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_TOKEN_URL will be used.",
					},
					"client_id": schema.StringAttribute{
						Optional:    true,
						Description: "The OAuth 2.0 client ID used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_CLIENT_ID will be used.",
					},
					"client_secret": schema.StringAttribute{
						Optional:    true,
						Description: "The OAuth 2.0 client secret used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_CLIENT_SECRET will be used.",
					},
					"scopes": schema.StringAttribute{
						Optional:    true,
						Description: "A comma-separated list of OAuth 2.0 scopes used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_SCOPES will be used.",
					},
					"audience": schema.StringAttribute{
						Optional:    true,
						Description: "The OAuth 2.0 audience used to obtain an access token. If not specified, the environment variable EJBCA_OAUTH_AUDIENCE will be used.",
					},
				},
			},
			"cert_auth": schema.SingleNestedBlock{
				Description: "An object containing configuration on where the provider should read the client certificate/private key from. Required if Client Cert Auth is used.",
				Attributes: map[string]schema.Attribute{
					"client_cert_path": schema.StringAttribute{
						Optional: true,
						Description: "Local path to the client certificate used to authenticate to EJBCA. File must include " +
							"a PEM formatted X509v3 certificate, and optionally an unencrypted, PEM formatted PKCS#8 private " +
							"key. If not specified, the environment variable EJBCA_CLIENT_CERT_PATH will be used.",
					},
					"client_key_path": schema.StringAttribute{
						Optional: true,
						Description: "Local path to the private key of the client certificate. Must be an unencrypted, PEM " +
							"formatted PKCS#8 private key. If not specified, the environment variable " +
							"EJBCA_CLIENT_CERT_KEY_PATH will be used.",
					},
				},
			},
		},
		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				Optional: true,
				Description: "Hostname of the EJBCA instance. Hostname can include the port in the format " +
					"{hostname}:{port}. If not specified, the environment variable EJBCA_HOSTNAME will be used.",
			},
			"ca_cert_path": schema.StringAttribute{
				Optional:    true,
				Description: "The path to the CA certificate file used to validate the EJBCA server's certificate. Certificates must be in PEM format.",
			},
		},
	}
}

func (p *Provider) newAuthenticator(ctx context.Context, configModel ProviderModel) (ejbca.Authenticator, diag.Diagnostics) {
	var err error
	var diags diag.Diagnostics

	var caChain []*x509.Certificate
	if !configModel.CaCertPath.IsNull() {
		tflog.Trace(ctx, "Parsing CA chain from file", map[string]any{"path": configModel.CaCertPath.ValueString()})

		caChainBytes, err := p.hooks.readFile(configModel.CaCertPath.ValueString())
		if err != nil {
			tflog.Error(ctx, "Failed to read CA chain from file", map[string]any{"error": err, "path": configModel.CaCertPath.ValueString()})
			diags.AddError("Failed to read CA chain from file", fmt.Sprintf("Failed to read CA chain from file [%s]: %v", configModel.CaCertPath.String(), err.Error()))
			return nil, diags
		}

		blocks := decodePEMBytes(caChainBytes)
		if len(blocks) == 0 {
			diags.AddError("Didn't find certificate in file", "Didn't find certificate in file at path "+configModel.CaCertPath.ValueString())
			return nil, diags
		}

		for _, block := range blocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				diags.AddError("Failed to parse CA certificate", "Failed to parse CA certificate: "+err.Error())
				return nil, diags
			}

			caChain = append(caChain, cert)
		}

		tflog.Debug(ctx, "Parsed CA chain", map[string]any{"length": len(caChain)})
	}

	var authenticator ejbca.Authenticator
	switch {
	case !configModel.OAuth.IsNull():
		tflog.Trace(ctx, "Parsing OAuth block")

		var oauthModel OAuthProviderModel
		diags.Append(configModel.OAuth.As(ctx, &oauthModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		tflog.Trace(ctx, "Creating OAuth authenticator")
		scopes := strings.Split(oauthModel.Scopes.ValueString(), " ")

		authenticator, err = ejbca.NewOAuthAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithTokenUrl(oauthModel.TokenURL.ValueString()).
			WithClientId(oauthModel.ClientID.ValueString()).
			WithClientSecret(oauthModel.ClientSecret.ValueString()).
			WithAudience(oauthModel.Audience.ValueString()).
			WithScopes(scopes).
			Build()
		if err != nil {
			diags.AddError("Failed to build OAuth authenticator", "Failed to build OAuth authenticator: "+err.Error())
			tflog.Error(ctx, "Failed to build OAuth authenticator", map[string]any{"error": err})
			return nil, diags
		}

		tflog.Debug(ctx, "Created OAuth authenticator")
	case !configModel.CertAuth.IsNull():
		tflog.Trace(ctx, "Parsing CertAuth block")

		var certAuthModel CertAuthProviderModel
		diags.Append(configModel.CertAuth.As(ctx, &certAuthModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil, diags
		}

		tflog.Trace(ctx, "Creating mTLS authenticator")

		var clientCertBytes []byte
		tflog.Debug(ctx, "Reading client certificate from file", map[string]any{"path": certAuthModel.ClientCertPath.ValueString()})
		clientCertBytes, err = p.hooks.readFile(certAuthModel.ClientCertPath.ValueString())
		if err != nil {
			tflog.Error(ctx, "Failed to read client certificate from file", map[string]any{"error": err, "path": certAuthModel.ClientCertPath.ValueString()})
			diags.AddError("Failed to read client certificate from file", fmt.Sprintf("Failed to read client certificate file [%s]: %v", certAuthModel.ClientCertPath.String(), err.Error()))
			return nil, diags
		}

		var clientKeyBytes []byte
		tflog.Debug(ctx, "Reading client key from file", map[string]any{"path": certAuthModel.ClientKeyPath.ValueString()})
		clientKeyBytes, err = p.hooks.readFile(certAuthModel.ClientKeyPath.ValueString())
		if err != nil {
			tflog.Error(ctx, "Failed to read client key from file", map[string]any{"error": err, "path": certAuthModel.ClientKeyPath.ValueString()})
			diags.AddError("Failed to read client key from file", fmt.Sprintf("Failed to read client key file [%s]: %v", certAuthModel.ClientKeyPath.String(), err.Error()))
			return nil, diags
		}

		tlsCert, err := tls.X509KeyPair(clientCertBytes, clientKeyBytes)
		if err != nil {
			tflog.Error(ctx, "Failed to load client certificate", map[string]any{"error": err})
			diags.AddError("Failed to load client certificate", "Failed to load client certificate: "+err.Error())
			return nil, diags
		}

		authenticator, err = ejbca.NewMTLSAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithClientCertificate(&tlsCert).
			Build()
		if err != nil {
			tflog.Error(ctx, "Failed to build MTLS authenticator", map[string]any{"error": err})
			diags.AddError("Failed to build MTLS authenticator", "Failed to build MTLS authenticator: "+err.Error())
			return nil, diags
		}

		tflog.Debug(ctx, "Created mTLS authenticator")
	default:
		tflog.Error(ctx, "No authentication method specified")
		diags.AddError("No authentication method specified", "No authentication method specified")
		return nil, diags
	}

	return authenticator, diags
}

func (p *Provider) validateProviderConfig(ctx context.Context, req provider.ConfigureRequest) (ProviderModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	configModel := ProviderModel{}

	diags.Append(req.Config.Get(ctx, &configModel)...)
	if diags.HasError() {
		return configModel, diags
	}

	switch {
	case !configModel.OAuth.IsNull():
		tflog.Debug(ctx, "Found OAuth configuration section in provider config")

		var oauthModel OAuthProviderModel
		diags.Append(configModel.OAuth.As(ctx, &oauthModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return configModel, diags
		}

		if oauthModel.TokenURL.ValueString() == "" {
			oauthModel.TokenURL = types.StringValue(p.hooks.getEnv("EJBCA_OAUTH_TOKEN_URL"))
		}
		if oauthModel.ClientID.ValueString() == "" {
			oauthModel.ClientID = types.StringValue(p.hooks.getEnv("EJBCA_OAUTH_CLIENT_ID"))
		}
		if oauthModel.ClientSecret.ValueString() == "" {
			oauthModel.ClientSecret = types.StringValue(p.hooks.getEnv("EJBCA_OAUTH_CLIENT_SECRET"))
		}
		if oauthModel.Scopes.ValueString() == "" {
			oauthModel.Scopes = types.StringValue(p.hooks.getEnv("EJBCA_OAUTH_SCOPES"))
		}
		if oauthModel.Audience.ValueString() == "" {
			oauthModel.Audience = types.StringValue(p.hooks.getEnv("EJBCA_OAUTH_AUDIENCE"))
		}

		if oauthModel.TokenURL.ValueString() == "" {
			tflog.Error(ctx, "Token URL is required for OAuth authentication")
			diags.AddError("Token URL is required for OAuth authentication", "token_url or EJBCA_OAUTH_TOKEN_URL is required for OAuth authentication")
			return configModel, diags
		}
		if oauthModel.ClientID.ValueString() == "" {
			tflog.Error(ctx, "Client ID is required for OAuth authentication")
			diags.AddError("Client ID is required for OAuth authentication", "client_id or EJBCA_OAUTH_CLIENT_ID is required for OAuth authentication")
			return configModel, diags
		}
		if oauthModel.ClientSecret.ValueString() == "" {
			tflog.Error(ctx, "Client secret is required for OAuth authentication")
			diags.AddError("Client secret is required for OAuth authentication", "client_secret or EJBCA_OAUTH_CLIENT_SECRET is required for OAuth authentication")
			return configModel, diags
		}
	case !configModel.CertAuth.IsNull():
		tflog.Debug(ctx, "Found mTLS configuration section in provider config")

		var certAuth CertAuthProviderModel
		diags.Append(configModel.CertAuth.As(ctx, &certAuth, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return configModel, diags
		}

		if certAuth.ClientCertPath.ValueString() == "" {
			certAuth.ClientCertPath = types.StringValue(p.hooks.getEnv("EJBCA_CLIENT_CERT_PATH"))
		}
		if certAuth.ClientKeyPath.ValueString() == "" {
			certAuth.ClientKeyPath = types.StringValue(p.hooks.getEnv("EJBCA_CLIENT_CERT_KEY_PATH"))
		}

		if certAuth.ClientCertPath.ValueString() == "" {
			tflog.Error(ctx, "Client certificate is required for mTLS authentication")
			diags.AddError("Client certificate is required for mTLS authentication", "client_cert or EJBCA_CLIENT_CERT_PATH is required for mTLS authentication")
			return configModel, diags
		}
		if certAuth.ClientKeyPath.ValueString() == "" {
			tflog.Error(ctx, "Client key is required for mTLS authentication")
			diags.AddError("Client key is required for mTLS authentication", "client_key or EJBCA_CLIENT_KEY_PATH is required for mTLS authentication")
			return configModel, diags
		}

		certAuthModel := map[string]attr.Type{
			"client_cert_path": types.StringType,
			"client_key_path":  types.StringType,
		}
		certAuthObject, innerDiags := types.ObjectValueFrom(ctx, certAuthModel, certAuth)
		diags.Append(innerDiags...)
		if diags.HasError() {
			tflog.Error(ctx, "Failed to convert CertAuth object to attribute map")
			return configModel, diags
		}
		configModel.CertAuth = certAuthObject
	default:
		tflog.Error(ctx, "No authentication method specified - please ensure that an 'oauth' or 'cert_auth' block is present in the provider configuration")
		diags.AddError("No authentication method specified", "no authentication method specified - please ensure that an 'oauth' or 'cert_auth' block is present in the provider configuration")
		return configModel, diags
	}

	if configModel.Hostname.ValueString() == "" {
		configModel.Hostname = types.StringValue(p.hooks.getEnv("EJBCA_HOSTNAME"))
	}

	if configModel.CaCertPath.ValueString() == "" {
		configModel.CaCertPath = types.StringValue(p.hooks.getEnv("EJBCA_CA_CERT_PATH"))
	}

	if configModel.Hostname.ValueString() == "" {
		tflog.Error(ctx, "Hostname is required")
		diags.AddError("Hostname is required", "hostname is required")
		return configModel, diags
	}

	return configModel, diags
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	configModel, diags := p.validateProviderConfig(ctx, req)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to validate provider configuration")
		return
	}

	config := ejbca.NewConfiguration()
	config.Host = configModel.Hostname.ValueString()

	authenticator, diags := p.hooks.newAuthenticator(ctx, configModel)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to create EJBCA Authenticator")
		return
	}
	if authenticator == nil {
		resp.Diagnostics.AddError(
			"Error creating EJBCA Authenticator",
			"Failed to create EJBCA Authenticator: authenticator is nil",
		)
		return
	}

	config.SetAuthenticator(authenticator)

	client, err := ejbca.NewAPIClient(config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating EJBCA SDK",
			"Failed to initialize EJBCA Client SDK: "+err.Error(),
		)
		return
	}
	if client == nil {
		resp.Diagnostics.AddError(
			"Error creating EJBCA SDK",
			"Failed to initialize EJBCA Client SDK: client is nil",
		)
		return
	}

	// Store the EJBCA SDK in the provider state.
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *Provider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
		NewEndEntityResource,
	}
}

func (p *Provider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewEndEntityProfileDataSource,
		NewAuthorizedEndEntityProfilesDataSource,
		NewCaPemDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		p := &Provider{
			version: version,
		}
		p.hooks.newAuthenticator = p.newAuthenticator
		p.hooks.getEnv = os.Getenv
		p.hooks.readFile = os.ReadFile
		return p
	}
}

func ptr[T any](v T) *T {
	return &v
}

const providerMarkdownDescription = `
The EJBCA Terraform provider extends Terraform to interact with EJBCA. The provider can authenticate to EJBCA using mTLS (client certificate) or using the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

### Requirements

* EJBCA [Community](https://www.ejbca.org/) or EJBCA [Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/)
  * The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration.

> EJBCA Enterprise is required for the OAuth 2.0 "client credentials" token flow. EJBCA Community only supports mTLS (client certificate) authentication.
`
