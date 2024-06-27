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
	"os"
	"time"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/keyfactor-pub/terraform-provider-ejbca/internal/ejbca/attrpmbool"
)

// Ensure ejbca defined types fully satisfy framework interfaces.
var _ resource.ResourceWithImportState = &CertificateResource{}
var _ resource.ResourceWithConfigure = &CertificateResource{}
var _ resource.ResourceWithModifyPlan = &CertificateResource{}

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
	Certificate               types.String `tfsdk:"certificate"`
	Chain                     types.String `tfsdk:"chain"`
	IssuerDn                  types.String `tfsdk:"issuer_dn"`
	AccountBindingID          types.String `tfsdk:"account_binding_id"`
	ValidityEndTime           types.String `tfsdk:"validity_end_time"`
	ValidityStartTime         types.String `tfsdk:"validity_start_time"`
	EarlyRenewalHours         types.Int64  `tfsdk:"early_renewal_hours"`
	ReadyForRenewal           types.Bool   `tfsdk:"ready_for_renewal"`
	IsRevoked                 types.Bool   `tfsdk:"is_revoked"`
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
			"account_binding_id": schema.StringAttribute{
				Optional:    true,
				Description: "An account binding ID in EJBCA to associate with issued certificates.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"early_renewal_hours": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
				Description: "The resource will consider the certificate to have expired the given number of hours " +
					"before its actual expiry time. This can be useful to renew the certificate in advance of " +
					"the expiration of the current certificate. " +
					"The advance update can only be performed if the resource is applied within the early renewal period. (default: `0`)",
			},

			// Computed schema
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Serial number of the certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"certificate": schema.StringAttribute{
				Computed:    true,
				Description: "PEM encoded X509v3 leaf certificate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"chain": schema.StringAttribute{
				Computed:    true,
				Description: "The PEM encoded X509v3 certificate chain up to the root CA.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"issuer_dn": schema.StringAttribute{
				Computed:    true,
				Description: "Distinguished name of the certificate issuer",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"validity_end_time": schema.StringAttribute{
				Computed:            true,
				Description:         "The time until which the certificate is invalid, expressed as an RFC3339 timestamp.",
				MarkdownDescription: "The time until which the certificate is invalid, expressed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"validity_start_time": schema.StringAttribute{
				Computed:            true,
				Description:         "The time after which the certificate is valid, expressed as an RFC3339 timestamp.",
				MarkdownDescription: "The time after which the certificate is valid, expressed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ready_for_renewal": schema.BoolAttribute{
				Computed: true,
				// Default:  booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					attrpmbool.ReadyForRenewal(),
				},
				Description: "Is the certificate either expired (i.e. beyond the `validity_period_hours`) " +
					"or ready for an early renewal (i.e. within the `early_renewal_hours`)?",
			},
			"is_revoked": schema.BoolAttribute{
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{},
				Description:   "Was the certificate revoked by the issuing CA?",
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
	filename := fmt.Sprintf("%s.pem", state.ID.ValueString())
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
	resp.Diagnostics.Append(CreateCertificateContext(ctx, r.client).ReadCertificate(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write the state back to Terraform
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ModifyPlan determines if the certificate resource needs to be replaced. The two cases where this is true are:
//   - The certificate is expired (-early_renewal_hours)
//   - The certificate is revoked
func (r *CertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Unconfigured EJBCA client", "The EJBCA client is not configured. Please report this issue to the ejbca developers.")
		return
	}

	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}

	earlyRenewalHoursPath := path.Root("early_renewal_hours")
	var earlyRenewalHours int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, earlyRenewalHoursPath, &earlyRenewalHours)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
	earlyRenewalTime := validityEndTime.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(overridableTimeFunc())
	if timeToEarlyRenewal <= 0 {
		tflog.Info(ctx, "Certificate is ready for early renewal")
		readyForRenewalPath := path.Root("ready_for_renewal")
		// Plan modifiers can only change state from known to unknown, not known to known.
		// https://developer.hashicorp.com/terraform/plugin/framework/resources/plan-modification#caveats
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, readyForRenewalPath, types.BoolUnknown())...)
		resp.RequiresReplace = append(resp.RequiresReplace, readyForRenewalPath)
	}

	idPath := path.Root("id")
	var sn types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, idPath, &sn)...)
	if resp.Diagnostics.HasError() {
		return
	}

	issuerDNPath := path.Root("issuer_dn")
	var issuerDN types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, issuerDNPath, &issuerDN)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// We also trigger a replace if the certificate is revoked.
	isRevoked, _diags := CreateCertificateContext(ctx, r.client).IsCertificateRevoked(issuerDN.ValueString(), sn.ValueString())
	resp.Diagnostics.Append(_diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if isRevoked {
		isRevokedPath := path.Root("is_revoked")
		tflog.Info(ctx, "Certificate is revoked - marking for replacement")
		// Plan modifiers can only change state from known to unknown, not known to known.
		// https://developer.hashicorp.com/terraform/plugin/framework/resources/plan-modification#caveats
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, isRevokedPath, types.BoolUnknown())...)
		resp.RequiresReplace = append(resp.RequiresReplace, isRevokedPath)
	}
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

	certificateContext := CreateCertificateContext(ctx, r.client)
	isRevoked, _diags := certificateContext.IsCertificateRevoked(issuerDn, certificateSerialNumber)
	resp.Diagnostics.Append(_diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if isRevoked {
		tflog.Info(ctx, "Certificate was already revoked during resource delete - Delete returning with no further action")
		resp.Diagnostics.AddWarning("Certificate was already revoked during resource delete - Delete returning with no further action", "Something outside of Terraform has already revoked the certificate.")
		return
	}

	if issuerDn == "" {
		resp.Diagnostics.AddError("Issuer DN not found", "The issuer DN was not found in the state. Please report this issue to the ejbca developers.")
		return
	}
	if certificateSerialNumber == "" {
		resp.Diagnostics.AddError("Certificate serial number not found", "The certificate serial number was not found in the state. Please report this issue to the ejbca developers.")
		return
	}

	// Revoke certificate
	resp.Diagnostics.Append(certificateContext.RevokeCertificate(issuerDn, certificateSerialNumber)...)
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

> Deletion of ` + "`ejbca_certificate`" + ` resources always revokes the certificate. Certificate revocation cannot be undone, so this action should be taken with caution.

## End Entity Name Customization

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

## Revocation

The EJBCA Certificate resource tracks certificate revocation to ensure that instantiated certificates
are up-to-date and also match the state of the EJBCA issuing CA. If a certificate represented by a Certificate resource
is revoked in EJBCA, Terraform plan will mark the certificate as revoked and force recreation upon the next apply.

> If the certificate is revoked in EJBCA by means other than Terraform, destroy will detect this and return with a 
warning.

## Automatic Certificate Renewal

The EJBCA Certificate resource supports 'automatic' certificate renewal via the ` + "`" + "early_renewal_hours" + "` " +
	`attribute. If this value is greater than zero and the certificate is known to expire within the number of hours 
specified by this resource, Terraform plan will mark ` + "`" + "ready_for_renewal" + "` " +
	` to trigger recreation of the Certificate resource. Then, upon the next apply, the Certificate will be renewed.

> Certificate 'renewal' in this context is different from 'renewal' in [Keyfactor Command](https://www.keyfactor.com/products/command/).

## API Usage

The EJBCA Certificate Resource uses the following EJBCA API endpoints:

* ` + "`" + `POST /v1/certificate/pkcs10enroll` + "`" + ` - Used to enroll a certificate with a PKCS#10 Certificate Signing Request
* ` + "`" + `POST /v1/certificate/search` + "`" + ` - Used to search for a certificate by serial number
* ` + "`" + `GET /v1/ca/{subject_dn}/certificate/download` + "`" + ` - Used to download the CA certificate chain if it was not provided in the response from ` + "`" + `/v1/certificate/search` + "`" + `
* ` + "`" + `PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke` + "`" + ` - Used to revoke a certificate
`
