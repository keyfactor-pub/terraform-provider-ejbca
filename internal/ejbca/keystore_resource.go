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

/*
 * This file contains the implementation of the EJBCA KeystoreResource resource.
 * It is not in use yet because the EJBCA API requires modification to support
 * downloading the enrolled certificate in a format better supported by GoLang.
 */

// Ensure ejbca defined types fully satisfy framework interfaces.
var _ resource.Resource = &KeystoreResource{}
var _ resource.ResourceWithImportState = &KeystoreResource{}
var _ resource.ResourceWithConfigure = &KeystoreResource{}

func NewKeystoreResource() resource.Resource {
	return &KeystoreResource{}
}

// KeystoreResource defines the resource implementation.
type KeystoreResource struct {
	client *ejbca.APIClient
}

type KeystoreResourceModel struct {
	Id                types.String `tfsdk:"id"`
	EndEntityName     types.String `tfsdk:"end_entity_name"`
	EndEntityPassword types.String `tfsdk:"end_entity_password"`
	KeyAlg            types.String `tfsdk:"key_alg"`
	KeySpec           types.String `tfsdk:"key_spec"`
	Certificate       types.String `tfsdk:"certificate"`
	Key               types.String `tfsdk:"key"`
	IssuerDn          types.String `tfsdk:"issuer_dn"`
}

func (r *KeystoreResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keystore"
}

func (r *KeystoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: keystoreResourceMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"end_entity_name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the EJBCA entity to create for the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"end_entity_password": schema.StringAttribute{
				Required:    true,
				Description: "Password of the EJBCA entity",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_alg": schema.StringAttribute{
				Optional:    true,
				Description: "Key algorithm assigned to end entity created if CSR is not provided",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_spec": schema.StringAttribute{
				Optional:    true,
				Description: "Key spec assigned to end entity created if CSR is not provided",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			// Computed attributes
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Serial number of the certificate",
			},
			"certificate": schema.StringAttribute{
				Computed:    true,
				Description: "PEM encoded X509v3 certificate and chain",
			},
			"key": schema.StringAttribute{
				Computed:    true,
				Description: "PEM encoded PKCS#8 private key",
			},
			"issuer_dn": schema.StringAttribute{
				Computed:    true,
				Description: "Distinguished name of the certificate issuer",
			},
		},
	}
}

func (r *KeystoreResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *KeystoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	tflog.Info(ctx, "Create called on KeystoreResource resource")

	// Read Terraform plan state into the model
	var state KeystoreResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Perform a Keystore enrollment
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).EnrollKeystore(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *KeystoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state KeystoreResourceModel

	tflog.Info(ctx, "Read called on KeystoreResource resource")

	// Read Terraform state into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the certificate from EJBCA
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).ReadKeystoreContext(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *KeystoreResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Update operation not supported. Force recreation
	resp.Diagnostics.AddError(
		"Update operation not supported for EJBCA KeystoreResource",
		"Provider error. This operation shouldn't be called.",
	)
}

func (r *KeystoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state KeystoreResourceModel

	tflog.Info(ctx, "Delete called on KeystoreResource resource")

	// Read Terraform state into the model
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract issuer DN and certificate serial number from state
	issuerDn := state.IssuerDn.ValueString()
	certificateSerialNumber := state.Id.ValueString()

	// Revoke certificate
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).RevokeCertificate(issuerDn, certificateSerialNumber)...)
}

func (r *KeystoreResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

const keystoreResourceMarkdownDescription = `
The EJBCA Keystore Resource allows you to enroll a certificate and let EJBCA generate keys for you. The end entity referenced by the resource must already exist in EJBCA, which can be accomplished using the ` + "`" + `ejbca_end_entity` + "`" + ` resource.

## EJBCA API Usage
* ` + "`" + `POST /v1/certificate/enrollkeystore` + "`" + ` - Used to enroll a certificate and let EJBCA generate keys for you according to the configuration of the specified end entity
* ` + "`" + `POST /v1/certificate/search` + "`" + ` - Used to search for a certificate by serial number
* ` + "`" + `GET /v1/ca/{subject_dn}/certificate/download` + "`" + ` - Used to download the CA certificate chain if it was not provided in the response from ` + "`" + `/v1/certificate/search` + "`" + `
* ` + "`" + `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` + "`" + ` - Used to revoke a certificate
* ` + "`" + `POST /v1/endentity/{endentity_name}/setstatus` + "`" + ` Used to update the status of an End Entity if it's not NEW'
`
