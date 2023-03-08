package ejbca

import (
    "context"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "fmt"
    "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
    "github.com/hashicorp/terraform-plugin-framework/diag"
    "github.com/hashicorp/terraform-plugin-framework/path"
    "github.com/hashicorp/terraform-plugin-framework/resource"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
    "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
    "github.com/hashicorp/terraform-plugin-framework/types"
    "github.com/hashicorp/terraform-plugin-log/tflog"
    "io"
    "strings"
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
            "certificate_authority_name": schema.StringAttribute{
                Required:    true,
                Description: "EJBCA Certificate Authority Name used to sign the certificate",
                PlanModifiers: []planmodifier.String{
                    stringplanmodifier.RequiresReplace(),
                },
            },
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
    certificate, _, err := r.client.V1CertificateApi.EnrollPkcs10Certificate(ctx).EnrollCertificateRestRequest(enroll).Execute()
    if err != nil {
        tflog.Error(ctx, "Failed to enroll PKCS#10 CSR: "+err.Error())

        detail := ""
        bodyError, ok := err.(*ejbca.GenericOpenAPIError)
        if ok {
            detail = string(bodyError.Body())
        }

        resp.Diagnostics.AddError(
            "Failed to enroll PKCS#10 CSR",
            fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
        )
        return
    }

    // Set the ID of the resource to the certificate serial number
    state.Id = types.StringValue(certificate.GetSerialNumber())

    tflog.Debug(ctx, "Enrolled certificate with serial number: "+certificate.GetSerialNumber())

    // Construct a string containing new leaf certificate and the whole chain
    if certificateAndChain, issuerDn, errorOccurred := constructCertificateChainString(ctx, r.client, &resp.Diagnostics, *certificate); !errorOccurred {
        state.Certificate = types.StringValue(certificateAndChain)
        state.IssuerDn = types.StringValue(issuerDn)
    } else {
        tflog.Error(ctx, "An error occurred while extracting certificate and chain from EJBCA certificate object")
        return
    }

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
        Property:             ptr("QUERY"),
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
        tflog.Error(ctx, "Failed to query EJBCA for certificate: "+err.Error())

        detail := ""
        bodyError, ok := err.(*ejbca.GenericOpenAPIError)
        if ok {
            detail = string(bodyError.Body())
        }

        resp.Diagnostics.AddError(
            "Failed to query EJBCA for certificate",
            fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
        )
        return
    }

    if len(searchResult.Certificates) == 0 {
        resp.Diagnostics.AddError(
            "EJBCA didn't return any certificates",
            fmt.Sprintf("EJBCA API returned no certificates after enrollment."),
        )
        return
    }
    certificate := searchResult.Certificates[0]

    // Construct a string containing new leaf certificate and the whole chain
    if certificateAndChain, issuerDn, errorOccurred := constructCertificateChainString(ctx, r.client, &resp.Diagnostics, certificate); !errorOccurred {
        state.Certificate = types.StringValue(certificateAndChain)
        state.IssuerDn = types.StringValue(issuerDn)
    } else {
        tflog.Error(ctx, "An error occurred while extracting certificate and chain from EJBCA certificate object")
        return
    }

    state.Id = types.StringValue(*certificate.SerialNumber)
    state.CertificateProfileName = types.StringValue(certificate.GetCertificateProfile())
    state.EndEntityProfileName = types.StringValue(certificate.GetEndEntityProfile())

    diags = resp.State.Set(ctx, &state)
    resp.Diagnostics.Append(diags...)
}

func (r *CertificateResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
    // Update operation not supported. Force recreation
    resp.Diagnostics.AddError(
        "Update operation not supported for EJBCA CertificateResource",
        fmt.Sprintf("Provider error. This operation shouldn't be called."),
    )
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
    var state CertificateResourceModel

    diags := req.State.Get(ctx, &state)
    resp.Diagnostics.Append(diags...)
    if resp.Diagnostics.HasError() {
        return
    }

    message, _, err := r.client.V1CertificateApi.RevokeCertificate(ctx, state.IssuerDn.ValueString(), state.Id.ValueString()).Reason("CESSATION_OF_OPERATION").Execute()
    if err != nil {
        tflog.Error(ctx, "Failed to revoke certificate with serial number \""+state.Id.ValueString()+"\": "+err.Error())

        detail := ""
        bodyError, ok := err.(*ejbca.GenericOpenAPIError)
        if ok {
            detail = string(bodyError.Body())
        }

        resp.Diagnostics.AddError(
            "Failed to revoke certificate with serial number \""+state.Id.ValueString()+"\": "+err.Error(),
            fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
        )
        return
    }

    tflog.Info(ctx, "Revoked certificate with serial number \""+state.Id.ValueString()+"\": "+*message.Message)
}

func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
    resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// constructCertificateChainString extracts the certificate from an EJBCA CertificateRestResponse, encodes it to PEM format
// if necessary, and either extracts or downloads the certificate chain. It takes the following arguments:
//   - ctx: The context of the current Terraform run
//   - client: Pointer to the EJBCA client
//   - diagnostics: Pointer to a diagnostics object to which errors can be added
//   - certificate: The EJBCA CertificateRestResponse object from which the certificate chain should be extracted
// If an error occurred, the function returns an empty string and adds an error to the diagnostics object.
// If no error occurred, the function returns the certificate chain as a string, the issuer DN, and adds no error to the diagnostics object.
func constructCertificateChainString(ctx context.Context, client *ejbca.APIClient, diagnostics *diag.Diagnostics, ejbcaCert ejbca.CertificateRestResponse) (string, string, bool) {
    var leafAndChain []*x509.Certificate
    var issuerDn string

    // Get a x509 certificate from the EJBCA certificate response object
    if leaf, chainFound, err := getCertificatesFromEjbcaObject(ejbcaCert); err == nil && chainFound {
        // If EJBCA returned a chain, we don't need to query EJBCA for the chain
        leafAndChain = append(leafAndChain, leaf...)
        issuerDn = leafAndChain[0].Issuer.String()
    } else if err == nil && !chainFound {
        // If EJBCA did not return a chain, we need to query EJBCA for the chain
        leafAndChain = append(leafAndChain, leaf...)
        issuerDn = leafAndChain[0].Issuer.String()

        // Get the chain from EJBCA
        chain, err := getCaChain(ctx, client, issuerDn)
        if err != nil {
            diagnostics.AddError(
                "Failed to retrieve CA PEM for CA with DN "+issuerDn,
                fmt.Sprintf("Got error: %s", err.Error()),
            )
            return "", "", diagnostics.HasError()
        }
        leafAndChain = append(leafAndChain, chain...)
    } else {
        diagnostics.AddError(
            "Failed to parse certificate",
            fmt.Sprintf("Failed to parse certificate: %s", err.Error()),
        )
        return "", "", diagnostics.HasError()
    }

    return compileCertificatesToPemString(ctx, leafAndChain), issuerDn, diagnostics.HasError()
}

func getCertificatesFromEjbcaObject(ejbcaCert ejbca.CertificateRestResponse) ([]*x509.Certificate, bool, error) {
    var certBytes []byte
    var err error
    certChainFound := false

    if ejbcaCert.GetResponseFormat() == "PEM" {
        // Extract the certificate from the PEM string
        block, _ := pem.Decode([]byte(ejbcaCert.GetCertificate()))
        if block == nil {
            return nil, false, errors.New("failed to parse certificate PEM")
        }
        certBytes = block.Bytes
    } else if ejbcaCert.GetResponseFormat() == "DER" {
        // Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
        // Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
        // will give more insight into the failure.
        bytes := []byte(ejbcaCert.GetCertificate())
        for i := 0; i < 2; i++ {
            var tempBytes []byte
            tempBytes, err = base64.StdEncoding.DecodeString(string(bytes))
            if err == nil {
                bytes = tempBytes
            }
        }
        certBytes = append(certBytes, bytes...)

        // If the certificate chain is present, append it to the certificate bytes
        if len(ejbcaCert.GetCertificateChain()) > 0 {
            var chainCertBytes []byte

            certChainFound = true
            for _, chainCert := range ejbcaCert.GetCertificateChain() {
                // Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
                // Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
                // will give more insight into the failure.
                for i := 0; i < 2; i++ {
                    var tempBytes []byte
                    tempBytes, err = base64.StdEncoding.DecodeString(chainCert)
                    if err == nil {
                        chainCertBytes = tempBytes
                    }
                }

                certBytes = append(certBytes, chainCertBytes...)
            }
        }
    } else {
        return nil, false, errors.New("ejbca returned unknown certificate format: " + ejbcaCert.GetResponseFormat())
    }

    certs, err := x509.ParseCertificates(certBytes)
    if err != nil {
        return nil, false, err
    }

    return certs, certChainFound, nil
}

func getCaChain(ctx context.Context, client *ejbca.APIClient, issuerDn string) ([]*x509.Certificate, error) {
    caResp, err := client.V1CaApi.GetCertificateAsPem(ctx, issuerDn).Execute()
    if err != nil {
        return nil, err
    }

    encodedBytes, err := io.ReadAll(caResp.Body) // EJBCA returns CA chain as a single PEM file
    if err != nil {
        return nil, err
    }

    // Decode PEM file into a slice of der bytes
    var block *pem.Block
    var derBytes []byte
    for {
        block, encodedBytes = pem.Decode(encodedBytes)
        if block == nil {
            break
        }
        derBytes = append(derBytes, block.Bytes...)
    }

    certificates, err := x509.ParseCertificates(derBytes)
    if err != nil {
        return nil, err
    }

    return certificates, nil
}

// compileCertificatesToPemString takes a slice of x509 certificates and returns a string containing the certificates in PEM format
// If an error occurred, the function logs the error and continues to parse the remaining objects.
func compileCertificatesToPemString(ctx context.Context, certificates []*x509.Certificate) string {
    var pemBuilder strings.Builder

    for _, certificate := range certificates {
        err := pem.Encode(&pemBuilder, &pem.Block{
            Type:  "CERTIFICATE",
            Bytes: certificate.Raw,
        })
        if err != nil {
            tflog.Error(ctx, "Failed to encode certificate with serial number "+certificate.SerialNumber.String()+" to PEM. Continuing anyway. ("+err.Error()+")")
        }
    }

    return pemBuilder.String()
}
