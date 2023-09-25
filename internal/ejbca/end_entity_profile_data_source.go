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

var _ datasource.DataSource = &EndEntityProfileDataSource{}

func NewEndEntityProfileDataSource() datasource.DataSource {
	return &EndEntityProfileDataSource{}
}

// EndEntityProfileDataSource defines the data source implementation.
type EndEntityProfileDataSource struct {
	client *ejbca.APIClient
}

// EndEntityProfileDataSourceModel describes the data source data model.
type EndEntityProfileDataSourceModel struct {
	EndEntityProfileName           types.String `tfsdk:"end_entity_profile_name"`
	SubjectDistinguishedNameFields types.Set    `tfsdk:"subject_distinguished_name_fields"`
	SubjectAlternativeNameFields   types.List   `tfsdk:"subject_alternative_name_fields"`
	AvailableCertificateProfiles   types.Set    `tfsdk:"available_certificate_profiles"`
	AvailableCAs                   types.Set    `tfsdk:"available_cas"`
	Id                             types.String `tfsdk:"id"`
}

func (d *EndEntityProfileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_end_entity_profile"
}

func (d *EndEntityProfileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: endEntityProfileDataSourceMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"end_entity_profile_name": schema.StringAttribute{
				Description: "Name of the end entity profile to return data for.",
				Required:    true,
			},
			"subject_distinguished_name_fields": schema.SetAttribute{
				Description: "List of subject distinguished name fields that are required for this end entity profile.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"subject_alternative_name_fields": schema.ListAttribute{
				Description: "List of subject alternative name fields that are available for this end entity profile.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"available_certificate_profiles": schema.SetAttribute{
				Description: "List of certificate profiles that are available for this end entity profile.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"available_cas": schema.SetAttribute{
				Description: "List of CAs that end entities can use to enroll with this end entity profile.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Valid name of the end entity profile designated by the `end_entity_profile_name` attribute.",
				Computed:            true,
			},
		},
	}
}

func (d *EndEntityProfileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *EndEntityProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state EndEntityProfileDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the end entity profile from EJBCA
	profileData, _, err := d.client.V2EndentityApi.Profile(ctx, state.EndEntityProfileName.ValueString()).Execute()
	if err != nil {
		tflog.Error(ctx, "Failed to retrieve data for end entity profile: "+err.Error())

		detail := ""
		var bodyError *ejbca.GenericOpenAPIError
		ok := errors.As(err, &bodyError)
		if ok {
			detail = string(bodyError.Body())
		}

		resp.Diagnostics.AddError(
			"Failed to retrieve data for end entity profile",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)
		return
	}

	// Set the subject distinguished name fields
	set, diag := types.SetValueFrom(ctx, types.StringType, removeDuplicates(profileData.SubjectDistinguishedNameFields))
	resp.Diagnostics.Append(diag...)
	state.SubjectDistinguishedNameFields = set

	// Set the subject alternative name fields
	list, diag := types.ListValueFrom(ctx, types.StringType, profileData.SubjectAlternativeNameFields)
	resp.Diagnostics.Append(diag...)
	state.SubjectAlternativeNameFields = list

	// Set the available certificate profiles
	set, diag = types.SetValueFrom(ctx, types.StringType, profileData.AvailableCertificateProfiles)
	resp.Diagnostics.Append(diag...)
	state.AvailableCertificateProfiles = set

	// Set the available CAs
	set, diag = types.SetValueFrom(ctx, types.StringType, profileData.AvailableCas)
	resp.Diagnostics.Append(diag...)
	state.AvailableCAs = set

	// Check for error
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the ID
	state.Id = types.StringValue(*profileData.EndEntityProfileName)

	tflog.Trace(ctx, fmt.Sprintf("Retrieved data for end entity profile called %s", *profileData.EndEntityProfileName))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func removeDuplicates(list []string) []string {
	keys := make(map[string]bool)
	var resultList []string

	for _, entry := range list {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			resultList = append(resultList, entry)
		}
	}

	return resultList
}

const endEntityProfileDataSourceMarkdownDescription = `
Data source that provides information about an EJBCA End Entity Profile

## EJBCA API Usage
* ` + "`" + `GET /v2/endentity/profile/{endentity_profile_name}` + "`" + ` - Used to retrieve the end entity profile
`
