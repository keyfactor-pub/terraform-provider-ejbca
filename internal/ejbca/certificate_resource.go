package ejbca

import (
	"context"
	"fmt"
	"os"

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
var _ resource.ResourceWithImportState = &CertificateResource{}
var _ resource.ResourceWithConfigure = &CertificateResource{}

func NewCertificateResource() resource.Resource {
	return &CertificateResource{}
}

// CertificateResource defines the resource implementation.
type CertificateResource struct {
	client *ejbca.APIClient
}

// CertificateResourceModel describes the resource data model.
type CertificateResourceModel struct {
	ID                        types.String `tfsdk:"id"`
	CertificateSigningRequest types.String `tfsdk:"certificate_signing_request"`
	CertificateProfileName    types.String `tfsdk:"certificate_profile_name"`
	EndEntityProfileName      types.String `tfsdk:"end_entity_profile_name"`
	CertificateAuthorityName  types.String `tfsdk:"certificate_authority_name"`
	EndEntityName             types.String `tfsdk:"end_entity_name"`
	EndEntityPassword         types.String `tfsdk:"end_entity_password"`
	Certificate               types.String `tfsdk:"certificate"`
	IssuerDn                  types.String `tfsdk:"issuer_dn"`
	AccountBindingID          types.String `tfsdk:"account_binding_id"`
}

func (r *CertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	tflog.Debug(ctx, "Returning schema for CertificateResource")
	resp.Schema = schema.Schema{
		MarkdownDescription: certificateResourceMarkdownDescription,

		Attributes: map[string]schema.Attribute{
			"certificate_signing_request": schema.StringAttribute{
				Required:    true,
				Description: "PKCS#10 PEM-encoded Certificate Signing Request",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate_profile_name": schema.StringAttribute{
				Required:    true,
				Description: "EJBCA Certificate Profile Name to use for the certificate. Profile must exist in the connected EJBCA instance, and it must correspond to the format of the certificate_signing_request.",
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
			"certificate_authority_name": schema.StringAttribute{
				Required:    true,
				Description: "EJBCA Certificate Authority Name used to sign the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"end_entity_name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the EJBCA entity to create for the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"end_entity_password": schema.StringAttribute{
				Optional:    true,
				Description: "Password of the EJBCA entity. If not provided, a random password will be generated",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"account_binding_id": schema.StringAttribute{
				Optional:    true,
				Description: "An account binding ID in EJBCA to associate with issued certificates.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Serial number of the certificate",
			},
			"certificate": schema.StringAttribute{
				Computed:    true,
				Description: "PEM encoded X509v3 certificate and chain",
			},
			"issuer_dn": schema.StringAttribute{
				Computed:    true,
				Description: "Distinguished name of the certificate issuer",
			},
		},
	}
}

func (r *CertificateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	tflog.Trace(ctx, "Configuring EJBCA CertificateResource")

	client, ok := req.ProviderData.(*ejbca.APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ejbca.APIClient, got: %T. Please report this issue to the ejbca developers.", req.ProviderData),
		)
		return
	}

	r.client = client
	tflog.Debug(ctx, "EJBCA CertificateResource is configured")
}

func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	tflog.Info(ctx, "Create called on CertificateResource resource")

	// Read Terraform plan state into the model
	var state CertificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Perform a PKCS#10 enrollment.
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).EnrollPkcs10Certificate(&state)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Failed to enroll certificate")
		return
	}

	// Save the certificate to the filesystem for debugging purposes.
	filename := fmt.Sprintf("%s.pem", state.EndEntityName.ValueString())
	err := os.WriteFile(filename, []byte(state.Certificate.ValueString()), 0600)
	if err != nil {
		// We don't care if the write fails; just log a warning.
		tflog.Warn(ctx, fmt.Sprintf("Failed to write certificate to %s: %v", filename, err))
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	var state CertificateResourceModel

	tflog.Info(ctx, "Read called on CertificateResource resource")

	// Read Terraform state into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read certificate from EJBCA
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).ReadCertificateContext(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CertificateResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Update operation not supported. Force recreation
	resp.Diagnostics.AddError(
		"Update operation not supported for EJBCA CertificateResource",
		"Provider error. This operation shouldn't be called.",
	)
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		return
	}

	tflog.Info(ctx, "Delete called on CertificateResource resource")

	// Read Terraform state into the model
	var state CertificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract issuer DN and certificate serial number from state
	issuerDn := state.IssuerDn.ValueString()
	certificateSerialNumber := state.ID.ValueString()

	// Revoke certificate
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).RevokeCertificate(issuerDn, certificateSerialNumber)...)
}

func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

const certificateResourceMarkdownDescription = `
The EJBCA Certificate Resource allows you to enroll certificates with client-generated keys (IE keys not generated by EJBCA)
with EJBCA according to a certificate profile, end entity profile, and CA. When ` + "`ejbca_certificate`" + ` resources are created,
an End Entity is created in EJBCA which is **not** deleted when the resource is destroyed. If this is behavior that is
desired, please use the ` + "`ejbca_end_entity`" + ` resource to generate the end entity, and reference the end entity name
in the ` + "`end_entity_name`" + ` attribute of the ` + "`ejbca_certificate`" + ` resource.

The EJBCA Certificate Resource uses the following EJBCA API endpoints:

* ` + "`" + `POST /v1/certificate/pkcs10enroll` + "`" + ` - Used to enroll a certificate with a PKCS#10 Certificate Signing Request
* ` + "`" + `POST /v1/certificate/search` + "`" + ` - Used to search for a certificate by serial number
* ` + "`" + `GET /v1/ca/{subject_dn}/certificate/download` + "`" + ` - Used to download the CA certificate chain if it was not provided in the response from ` + "`" + `/v1/certificate/search` + "`" + `
* ` + "`" + `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` + "`" + ` - Used to revoke a certificate

The EJBCA Certificate Resource allows users to determine how the End Entity Name is selected at runtime. Here are the options you can use for ` + "`" + `end_entity_name` + "`" + `:

* **` + "`" + `cn` + "`" + `:** Uses the Common Name from the CSR's Distinguished Name.
* **` + "`" + `dns` + "`" + `:** Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **` + "`" + `uri` + "`" + `:** Uses the first URI from the CSR's Subject Alternative Names (SANs).
* **` + "`" + `ip` + "`" + `:** Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
* **Custom Value:** Any other string will be directly used as the End Entity Name.

If the ` + "`" + `end_entity_name` + "`" + ` field is not explicitly set, the EJBCA Terraform Provider will attempt to determine the End Entity Name using the following default behavior:

* **First, it will try to use the Common Name:** It looks at the Common Name from the CSR's Distinguished Name.
* **If the Common Name is not available, it will use the first DNS Name:** It looks at the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **If the DNS Name is not available, it will use the first URI:** It looks at the first URI from the CSR's Subject Alternative Names (SANs).
* **If the URI is not available, it will use the first IP Address:** It looks at the first IP Address from the CSR's Subject Alternative Names (SANs).
* **If none of the above are available, it will return an error.
`
