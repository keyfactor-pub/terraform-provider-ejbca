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

func (d *CaPemDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_pem"
}

type CaPemDataSourceModel struct {
	Dn    types.String `tfsdk:"dn"`
	CaPem types.String `tfsdk:"ca_pem"`
	ID    types.String `tfsdk:"id"`
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

func (d *CaPemDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	if d.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	// Read Terraform configuration data into the model
	var state CaPemDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Download the CA PEM
	chain, diags := CreateCertificateContext(ctx, d.client).DownloadCAChain(state.Dn.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.CaPem = types.StringValue(compileCertificatesToPemString(ctx, chain))
	state.ID = types.StringValue(fmt.Sprintf("%X", chain[0].SerialNumber))

	tflog.Debug(ctx, "Retrieved CA PEM for CA with DN "+state.Dn.ValueString())

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

const caPemDataSourceMarkdownDescription = `
Data source that provides the PEM encoded CA certificate for the specified CA.

## EJBCA API Usage
* ` + "`" + `GET /v1/ca/{subject_dn}/certificate/download` + "`" + ` - Used to download the CA certificate chain
`
