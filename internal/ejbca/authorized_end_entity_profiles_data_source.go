package ejbca

import (
    "context"
    "fmt"
    "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
    "github.com/hashicorp/terraform-plugin-framework/datasource"
    "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
    "github.com/hashicorp/terraform-plugin-framework/types"
    "github.com/hashicorp/terraform-plugin-log/tflog"
    "math/rand"
    "time"
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
    AuthorizedEndEntityProfiles types.Set    `tfsdk:"authorized_end_entity_profiles"`
    Id                          types.String `tfsdk:"id"`
}

func (d *AuthorizedEndEntityProfilesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
    resp.Schema = schema.Schema{
        MarkdownDescription: "Data source that provides the list of authorized end entity profiles for the current user.",

        Attributes: map[string]schema.Attribute{
            "authorized_end_entity_profiles": schema.SetAttribute{
                Description: "Set of authorized end entity profiles for the current user.",
                ElementType: types.StringType,
                Computed:    true,
            },
            "id": schema.StringAttribute{
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
        tflog.Error(ctx, "Failed to get list of authorized end entity profiles: %s"+err.Error())
        resp.Diagnostics.AddError(
            "Failed to get list of authorized end entity profiles",
            "EJBCA API returned error: "+err.Error()+" \""+string(err.(*ejbca.GenericOpenAPIError).Body())+"\"",
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

    // Set the ID of the data source as a random 10 character string.
    state.Id = types.StringValue(generateRandomString(10))

    tflog.Trace(ctx, fmt.Sprintf("Retrieved list of authorized end entity profiles."))

    // Save data into Terraform state
    resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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
