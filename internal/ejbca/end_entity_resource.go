package ejbca

import (
	"context"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
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

func NewEndEntityResource() resource.Resource {
	return &EndEntityResource{}
}

// EndEntityResource defines the resource implementation.
type EndEntityResource struct {
	client *ejbca.APIClient
}

type EndEntityResourceModel struct {
	Id                     types.String `tfsdk:"id"`
	EndEntityName          types.String `tfsdk:"end_entity_name"`
	EndEntityPassword      types.String `tfsdk:"end_entity_password"` // Not returned
	SubjectDn              types.String `tfsdk:"subject_dn"`
	SubjectAltName         types.String `tfsdk:"subject_alt_name"`
	Email                  types.String `tfsdk:"email"`
	CaName                 types.String `tfsdk:"ca_name"`                  // Not returned
	CertificateProfileName types.String `tfsdk:"certificate_profile_name"` // Not returned
	EndEntityProfileName   types.String `tfsdk:"end_entity_profile_name"`  // Not returned
	Token                  types.String `tfsdk:"token"`
	AccountBindingId       types.String `tfsdk:"account_binding_id"` // Not returned
	// TODO extension_data

	Status types.String `tfsdk:"status"`
}

func (r *EndEntityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_end_entity"
}

func (r *EndEntityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The EJBCA Certificate Resource allows you to manage a certificate in EJBCA.",

		Attributes: map[string]schema.Attribute{
			"username": schema.StringAttribute{
				Required:    true,
				Description: "Username of the end entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
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
				Optional:    true,
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

			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Username of the created end entity",
			},
		},
	}
}

func (r *EndEntityResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

func (r *EndEntityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var state EndEntityResourceModel

	// Read Terraform plan state into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).CreateEndEntity(&state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save state into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *EndEntityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state EndEntityResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate resource")

	// Create certificate context to easily manipulate EJBCA state
	// Then, read end entity context corresponding to end entity with username in state
	// ReadEndEntityContext returns a list of diags. If an error occurred, return.
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).ReadEndEntityContext(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *EndEntityResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Update operation not supported. Force recreation
	resp.Diagnostics.AddError(
		"Update operation not supported for EJBCA EndEntityResource",
		fmt.Sprintf("Provider error. This operation shouldn't be called."),
	)
}

func (r *EndEntityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {

}

func (r *EndEntityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {

}