package ejbca

import (
	"context"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ datasource.DataSource = &AuthorizedEndEntityProfilesDataSource{}

func NewAuthorizedEndEntityProfilesDataSource() datasource.DataSource {
	return &AuthorizedEndEntityProfilesDataSource{}
}

// AuthorizedEndEntityProfilesDataSource defines the data source implementation.
type AuthorizedEndEntityProfilesDataSource struct {
	client *ejbca.APIClient
}

func (d *AuthorizedEndEntityProfilesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authorized_end_entity_profiles"
}

// AuthorizedEndEntityProfilesDataSourceModel describes the data source data model.
type AuthorizedEndEntityProfilesDataSourceModel struct {
	AuthorizedEndEntityProfiles types.Set   `tfsdk:"authorized_end_entity_profiles"`
	Id                          types.Int64 `tfsdk:"id"`
}

func (d *AuthorizedEndEntityProfilesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: authorizedEndEntityDataSourceMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"authorized_end_entity_profiles": schema.SetAttribute{
				Description: "Set of authorized end entity profiles for the current user.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"id": schema.Int64Attribute{
				Computed:    true,
				Description: "The ID of the data source.",
			},
		},
	}
}

func (d *AuthorizedEndEntityProfilesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AuthorizedEndEntityProfilesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state AuthorizedEndEntityProfilesDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the list of authorized end entity profiles for the current user.
	authorizedEndEntityProfiles, _, err := d.client.V2EndentityApi.GetAuthorizedEndEntityProfiles(ctx).Execute()
	if err != nil {
		tflog.Error(ctx, "Failed to get list of authorized end entity profiles: "+err.Error())

		detail := ""
		var bodyError *ejbca.GenericOpenAPIError
		ok := errors.As(err, &bodyError)
		if ok {
			detail = string(bodyError.Body())
		}

		resp.Diagnostics.AddError(
			"Failed to get list of authorized end entity profiles",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)
		return
	}

	// Create list of strings from the authorized end entity profile names
	var authorizedEndEntityProfilesList []string
	for _, authorizedEndEntityProfile := range authorizedEndEntityProfiles.EndEntitieProfiles {
		if *authorizedEndEntityProfile.Name == "" {
			continue
		}

		authorizedEndEntityProfilesList = append(authorizedEndEntityProfilesList, *authorizedEndEntityProfile.Name)
	}

	// Convert the list of authorized end entity profiles to a set.
	set, diag := types.SetValueFrom(ctx, types.StringType, authorizedEndEntityProfilesList)
	resp.Diagnostics.Append(diag...)
	state.AuthorizedEndEntityProfiles = set

	// Check for error
	if resp.Diagnostics.HasError() {
		return
	}

	state.Id = types.Int64Value(int64(len(authorizedEndEntityProfilesList)))

	tflog.Trace(ctx, fmt.Sprintf("Retrieved list of authorized end entity profiles."))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

const authorizedEndEntityDataSourceMarkdownDescription = `
Data source that provides the list of authorized end entity profiles for the current user.

## EJBCA API Usage
* ` + "`" + `GET /v2/endentity/profiles/authorized` + "`" + ` - Used to get the list of authorized end entity profiles for the current user.
`
