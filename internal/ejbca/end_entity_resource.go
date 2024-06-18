package ejbca

import (
	"context"
	"fmt"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure ejbca defined types fully satisfy framework interfaces.
var _ resource.Resource = &EndEntityResource{}
var _ resource.ResourceWithImportState = &EndEntityResource{}
var _ resource.ResourceWithConfigure = &EndEntityResource{}

func NewEndEntityResource() resource.Resource {
	return &EndEntityResource{}
}

// EndEntityResource defines the resource implementation.
type EndEntityResource struct {
	client *ejbca.APIClient
}

type EndEntityResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	EndEntityName          types.String `tfsdk:"end_entity_name"`
	EndEntityPassword      types.String `tfsdk:"end_entity_password"` // Not returned
	SubjectDn              types.String `tfsdk:"subject_dn"`
	SubjectAltName         types.String `tfsdk:"subject_alt_name"`
	Email                  types.String `tfsdk:"email"`
	CaName                 types.String `tfsdk:"ca_name"`                  // Not returned
	CertificateProfileName types.String `tfsdk:"certificate_profile_name"` // Not returned
	EndEntityProfileName   types.String `tfsdk:"end_entity_profile_name"`  // Not returned
	Token                  types.String `tfsdk:"token"`
	AccountBindingID       types.String `tfsdk:"account_binding_id"` // Not returned
	Status                 types.String `tfsdk:"status"`
	// TODO extension_data
}

func (r *EndEntityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_end_entity"
}

func (r *EndEntityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: endEntityMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"end_entity_name": schema.StringAttribute{
				Required:    true,
				Description: "Username of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"end_entity_password": schema.StringAttribute{
				Required:    true,
				Description: "Password of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"subject_dn": schema.StringAttribute{
				Required:    true,
				Description: "Subject DN of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"subject_alt_name": schema.StringAttribute{
				Optional:    true,
				Description: "Subject Alternative Name of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"email": schema.StringAttribute{
				Optional:    true,
				Description: "Email of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of CA used to sign the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate_profile_name": schema.StringAttribute{
				Required:    true,
				Description: "EJBCA Certificate Profile Name to use for the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"end_entity_profile_name": schema.StringAttribute{
				Required:    true,
				Description: "EJBCA End Entity Profile Name to use for the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"token": schema.StringAttribute{
				Required:    true,
				Description: "Token type property (USERGENERATED, P12, JKS, PEM)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"account_binding_id": schema.StringAttribute{
				Optional:    true,
				Description: "Account Binding ID of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			// TODO extension_data

			// Computed attributes
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Username of the created end entity",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status of the created end entity",
			},
		},
	}
}

func (r *EndEntityResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

func (r *EndEntityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	tflog.Info(ctx, "Create called on EndEntityResource resource")

	// Read Terraform plan state into the model
	var state EndEntityResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create end entity in EJBCA
	resp.Diagnostics.Append(CreateEndEntityContext(ctx, r.client).CreateEndEntity(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *EndEntityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	tflog.Info(ctx, "Read called on EndEntityResource resource")

	// Read Terraform state into the model
	var state EndEntityResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read end entity from EJBCA
	resp.Diagnostics.Append(CreateEndEntityContext(ctx, r.client).ReadEndEntityContext(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *EndEntityResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Update operation not supported. Force recreation
	resp.Diagnostics.AddError(
		"Update operation not supported for EJBCA EndEntityResource",
		"Provider error. This operation shouldn't be called.",
	)
}

func (r *EndEntityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	tflog.Info(ctx, "Delete called on EndEntityResource resource")

	// Read Terraform state into the model
	var state EndEntityResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete end entity from EJBCA
	resp.Diagnostics.Append(CreateEndEntityContext(ctx, r.client).DeleteEndEntity(&state)...)
}

func (r *EndEntityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

const endEntityMarkdownDescription = `
The EJBCA End Entity Resource allows you to manage an end entity in EJBCA. End Entities are users, machines, or services that are issued certificates by EJBCA. End Entities are identified by their username and are associated with a Certificate Authority (CA), Certificate Profile, and End Entity Profile. End Entities can be created, read, and deleted (CRD) using this resource.

## EJBCA API Usage
* ` + "`" + `POST /v1/endentity` + "`" + ` - Used to create a new end entity
* ` + "`" + `POST /v1/endentity/search` + "`" + ` - Used to read and delete an existing end entity
* ` + "`" + `POST /v1/endentity/{endentity_name}/setstatus` + "`" + ` Used to update the status of an End Entity if it's not NEW'
* ` + "`" + `DELETE /v1/endentity/{endentity_name}` + "`" + ` - Used to delete an existing end entity
`
