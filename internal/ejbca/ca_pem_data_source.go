package ejbca

import (
	"context"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ datasource.DataSource = &CaPemDataSource{}

func NewCaPemDataSource() datasource.DataSource {
	return &CaPemDataSource{}
}

// CaPemDataSource defines the data source implementation.
type CaPemDataSource struct {
	client *ejbca.APIClient
}

func (d *CaPemDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_pem"
}

type CaPemDataSourceModel struct {
	Dn    types.String `tfsdk:"dn"`
	CaPem types.String `tfsdk:"ca_pem"`
	Id    types.String `tfsdk:"id"`
}

func (d *CaPemDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: caPemDataSourceMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"dn": schema.StringAttribute{
				Description: "The DN of the CA.",
				Required:    true,
			},
			"ca_pem": schema.StringAttribute{
				Description: "PEM encoded CA certificate for the specified CA.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the data source.",
			},
		},
	}
}

func (d *CaPemDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the ejbca has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ejbca.APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ejbca.APIClient, got: %T. Please report this issue to the ejbca developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *CaPemDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state CaPemDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Download the CA PEM
	chain, err := CreateCertificateContext(ctx, d.client).DownloadCaChain(state.Dn.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to retrieve CA PEM for CA with DN "+state.Dn.ValueString(),
			fmt.Sprintf("Got error: %s", err.Error()),
		)
		return
	}

	state.CaPem = types.StringValue(compileCertificatesToPemString(ctx, chain))
	state.Id = types.StringValue(fmt.Sprintf("%X", chain[0].SerialNumber))

	tflog.Debug(ctx, "Retrieved CA PEM for CA with DN "+state.Dn.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

const caPemDataSourceMarkdownDescription = `
Data source that provides the PEM encoded CA certificate for the specified CA.

## EJBCA API Usage
* ` + "`" + `GET /v1/ca/{subject_dn}/certificate/download` + "`" + ` - Used to download the CA certificate chain
`
