package ejbca

import (
    "context"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
    "github.com/hashicorp/terraform-plugin-framework/path"
    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema"
    "github.com/hashicorp/terraform-plugin-framework/types"
    "github.com/hashicorp/terraform-plugin-log/tflog"
    "time"
)

// Ensure ejbca defined types fully satisfy framework interfaces.
var _ resource.Resource = &CertificateResource{}
var _ resource.ResourceWithImportState = &CertificateResource{}

func NewCertificateResource() resource.Resource {
    return &CertificateResource{}
}

// CertificateResource defines the resource implementation.
type CertificateResource struct {
    client *ejbca.APIClient
}

// CertificateResourceModel describes the resource data model.
type CertificateResourceModel struct {
    Id                        types.String `tfsdk:"id"`
    CertificateSigningRequest types.String `tfsdk:"certificate_signing_request"`
    CertificateProfileName    types.String `tfsdk:"certificate_profile_name"`
    EndEntityProfileName      types.String `tfsdk:"end_entity_profile_name"`
    CertificateAuthorityName  types.String `tfsdk:"certificate_authority_name"`
    EndEntityName             types.String `tfsdk:"end_entity_name"`
    EndEntityPassword         types.String `tfsdk:"end_entity_password"`
    Certificate               types.String `tfsdk:"certificate"`
    IssuerDn                  types.String `tfsdk:"issuer_dn"`
}

func (r *CertificateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        MarkdownDescription: "The EJBCA Certificate Resource allows you to manage a certificate in EJBCA.",

        Attributes: map[string]schema.Attribute{
            "certificate_signing_request": schema.StringAttribute{
                Required:    true,
                Description: "PKCS#10 Certificate Signing Request",
            },
            "certificate_profile_name": schema.StringAttribute{
                Required:    true,
                Description: "EJBCA Certificate Profile Name to use for the certificate",
            },
            "end_entity_profile_name": schema.StringAttribute{
                Required:    true,
                Description: "EJBCA End Entity Profile Name to use for the certificate",
            },
            "certificate_authority_name": schema.StringAttribute{
                Required:    true,
                Description: "EJBCA Certificate Authority Name used to sign the certificate",
            },
            "end_entity_name": schema.StringAttribute{
                Required:    true,
                Description: "Name of the EJBCA entity to create for the certificate",
            },
            "end_entity_password": schema.StringAttribute{
                Required:    true,
                Description: "Password of the EJBCA entity",
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

func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
    var state CertificateResourceModel

    // Read Terraform plan state into the model
    resp.Diagnostics.Append(req.Plan.Get(ctx, &state)...)
    if resp.Diagnostics.HasError() {
        return
    }

    // Configure EJBCA PKCS#10 request
    enroll := ejbca.EnrollCertificateRestRequest{
        CertificateRequest:       ptr(state.CertificateSigningRequest.ValueString()),
        CertificateProfileName:   ptr(state.CertificateProfileName.ValueString()),
        EndEntityProfileName:     ptr(state.EndEntityProfileName.ValueString()),
        CertificateAuthorityName: ptr(state.CertificateAuthorityName.ValueString()),
        Username:                 ptr(state.EndEntityName.ValueString()),
        Password:                 ptr(state.EndEntityPassword.ValueString()),
        IncludeChain:             ptr(true),
    }

    // Enroll the PKCS#10 CSR using the EJBCA API
    enrollResp, _, err := r.client.V1CertificateApi.EnrollPkcs10Certificate(ctx).EnrollCertificateRestRequest(enroll).Execute()
    if err != nil {
        tflog.Error(ctx, "Failed to enroll PKCS#10 CSR: %s"+err.Error())
        resp.Diagnostics.AddError(
            "Failed to enroll PKCS#10 CSR",
            "EJBCA API returned error: "+err.Error()+" \""+string(err.(*ejbca.GenericOpenAPIError).Body())+"\"",
        )
        return
    }

    // Set the ID of the resource to the certificate serial number
    state.Id = types.StringValue(*enrollResp.SerialNumber)

    tflog.Trace(ctx, "Enrolled certificate with serial number: "+*enrollResp.SerialNumber)

    // Save state into Terraform state
    resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
    var state CertificateResourceModel

    diags := req.State.Get(ctx, &state)
    resp.Diagnostics.Append(diags...)
    if resp.Diagnostics.HasError() {
        return
    }

    tflog.Info(ctx, "Read called on certificate resource")
    certificateSerialNumber := state.Id.ValueString()

    criteria := ejbca.SearchCertificateCriteriaRestRequest{
        Property:             ptr("SerialNr"),
        Value:                ptr(certificateSerialNumber),
        Operation:            ptr("EQUAL"),
        AdditionalProperties: nil,
    }

    certSearch := ejbca.SearchCertificatesRestRequest{
        MaxNumberOfResults:   ptr(int32(1)),
        Criteria:             []ejbca.SearchCertificateCriteriaRestRequest{criteria},
        AdditionalProperties: nil,
    }

    searchResult, _, err := r.client.V1CertificateApi.SearchCertificates(ctx).SearchCertificatesRestRequest(certSearch).Execute()
    if err != nil {
        tflog.Error(ctx, "Failed to query EJBCA for certificate: %s"+err.Error())
        resp.Diagnostics.AddError(
            "Failed to query EJBCA for certificate",
            "EJBCA API returned error: "+err.Error()+" \""+string(err.(*ejbca.GenericOpenAPIError).Body())+"\"",
        )
    }

    if len(searchResult.Certificates) > 0 {
        certificate := searchResult.Certificates[0]

        dn, err := getIssuerDnFromCertificate(*certificate.Certificate)
        if err != nil {
            tflog.Error(ctx, "Failed to extract issuer DN from certificate: %s"+err.Error())
            resp.Diagnostics.AddError(
                "Failed to extract issuer DN from certificate",
                "EJBCA API returned error: "+err.Error()+" \""+string(err.(*ejbca.GenericOpenAPIError).Body())+"\"",
            )
        }

        state.Id = types.StringValue(*certificate.SerialNumber)
        state.CertificateProfileName = types.StringValue(*certificate.CertificateProfile)
        state.EndEntityProfileName = types.StringValue(*certificate.EndEntityProfile)
        state.Certificate = types.StringValue(*certificate.Certificate)
        state.IssuerDn = types.StringValue(dn)
    }

    diags = resp.State.Set(ctx, &state)
    resp.Diagnostics.Append(diags...)
}

func (r *CertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
    var data *CertificateResourceModel

    // Read Terraform plan data into the model
    resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

    if resp.Diagnostics.HasError() {
        return
    }

    // If applicable, this is a great opportunity to initialize any necessary
    // ejbca client data and make a call using it.
    // httpResp, err := r.client.Do(httpReq)
    // if err != nil {
    //     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update example, got error: %s", err))
    //     return
    // }

    // Save updated data into Terraform state
    resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
    var state CertificateResourceModel

    diags := req.State.Get(ctx, &state)
    resp.Diagnostics.Append(diags...)
    if resp.Diagnostics.HasError() {
        return
    }

    message, _, err := r.client.V1CertificateApi.RevokeCertificate(ctx, state.IssuerDn.ValueString(), state.Id.ValueString()).Reason("CESSATION_OF_OPERATION").Date(time.Now()).Execute()
    if err != nil {
        tflog.Error(ctx, "Failed to revoke certificate with serial number \""+state.Id.ValueString()+"\": "+err.Error())
        resp.Diagnostics.AddError(
            "Failed to revoke certificate with serial number \""+state.Id.ValueString()+"\"",
            "EJBCA API returned error: "+err.Error()+" \""+string(err.(*ejbca.GenericOpenAPIError).Body())+"\"",
        )
    }

    tflog.Info(ctx, "Revoked certificate with serial number \""+state.Id.ValueString()+"\": "+*message.Message)
}

func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
    resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func getIssuerDnFromCertificate(certificate string) (string, error) {
    block, _ := pem.Decode([]byte(certificate))
    if block == nil {
        return "", errors.New("failed to parse certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return "", err
    }

    return cert.Issuer.String(), nil
}
