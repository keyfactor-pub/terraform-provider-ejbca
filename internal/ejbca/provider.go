package ejbca

import (
	"context"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure EjbcaProvider satisfies various ejbca interfaces.
var _ provider.Provider = &EjbcaProvider{}

// EjbcaProvider defines the ejbca implementation.
type EjbcaProvider struct {
	// version is set to the ejbca version on release, "dev" when the
	// ejbca is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// ProviderModel describes the ejbca data model.
type ProviderModel struct {
	Hostname          types.String `tfsdk:"hostname"`
	ClientCertPath    types.String `tfsdk:"client_cert_path"`
	ClientCertKeyPath types.String `tfsdk:"client_cert_key_path"`
}

func (p *EjbcaProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ejbca"
	resp.Version = p.version
}

func (p *EjbcaProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				Optional: true,
				Description: "Hostname of the EJBCA instance. Hostname can include the port in the format " +
					"<hostname>:<port>. If not specified, the environment variable EJBCA_HOSTNAME will be used.",
			},
			"client_cert_path": schema.StringAttribute{
				Optional: true,
				Description: "Local path to the client certificate used to authenticate to EJBCA. File must include " +
					"a PEM formatted X509v3 certificate, and optionally an unencrypted, PEM formatted PKCS#8 private " +
					"key. If not specified, the environment variable EJBCA_CLIENT_CERT_PATH will be used.",
			},
			"client_cert_key_path": schema.StringAttribute{
				Optional: true,
				Description: "Local path to the private key of the client certificate. Must be an unencrypted, PEM " +
					"formatted PKCS#8 private key. If not specified, the environment variable " +
					"EJBCA_CLIENT_CERT_KEY_PATH will be used.",
			},
		},
	}
}

func (p *EjbcaProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	config := ProviderModel{}

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	configuration := ejbca.NewConfiguration()
	if !config.Hostname.IsNull() {
		configuration.Host = config.Hostname.ValueString()
	}

	if !config.ClientCertPath.IsNull() {
		configuration.ClientCertificatePath = config.ClientCertPath.ValueString()
	}

	if !config.ClientCertKeyPath.IsNull() {
		configuration.ClientCertificateKeyPath = config.ClientCertKeyPath.ValueString()
	}

	ejbcaSdk, err := ejbca.NewAPIClient(configuration)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating EJBCA SDK",
			"Failed to initialize EJBCA Client SDK: "+err.Error(),
		)
		return
	}

	// Store the EJBCA SDK in the provider state.
	resp.DataSourceData = ejbcaSdk
	resp.ResourceData = ejbcaSdk
}

func (p *EjbcaProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
		NewEndEntityResource,
	}
}

func (p *EjbcaProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewEndEntityProfileDataSource,
		NewAuthorizedEndEntityProfilesDataSource,
		NewCaPemDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &EjbcaProvider{
			version: version,
		}
	}
}

func ptr[T any](v T) *T {
	return &v
}
