package ejbca

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CertificateContext struct {
	ctx    context.Context
	client *ejbca.APIClient
}

func CreateCertificateContext(ctx context.Context, client *ejbca.APIClient) *CertificateContext {
	return &CertificateContext{
		ctx:    ctx,
		client: client,
	}
}

func (c *CertificateContext) EnrollPkcs10Certificate(state *CertificateResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	if state == nil {
		diags.AddError("EnrollPkcs10Certificate was called improperly", "Pointer to CertificateResourceModel is nil")
		return diags
	}

	// Configure EJBCA PKCS#10 request
	enroll := ejbca.EnrollCertificateRestRequest{
		CertificateRequest:       state.CertificateSigningRequest.ValueStringPointer(),
		CertificateProfileName:   state.CertificateProfileName.ValueStringPointer(),
		EndEntityProfileName:     state.EndEntityProfileName.ValueStringPointer(),
		CertificateAuthorityName: state.CertificateAuthorityName.ValueStringPointer(),
		Username:                 state.EndEntityName.ValueStringPointer(),
		Password:                 state.EndEntityPassword.ValueStringPointer(),
		IncludeChain:             ptr(true),
	}

	// Enroll the PKCS#10 CSR using the EJBCA API
	certificate, _, err := c.client.V1CertificateApi.EnrollPkcs10Certificate(c.ctx).EnrollCertificateRestRequest(enroll).Execute()
	if err != nil {
		tflog.Error(c.ctx, "Failed to enroll PKCS#10 CSR: "+err.Error())

		detail := ""
		bodyError, ok := err.(*ejbca.GenericOpenAPIError)
		if ok {
			detail = string(bodyError.Body())
		}

		diags.AddError(
			"Failed to enroll PKCS#10 CSR",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)

		return diags
	}

	tflog.Debug(c.ctx, "Enrolled certificate using PKCS#10 enrollment with serial number: "+certificate.GetSerialNumber())
	return c.ComposeStateFromCertificateResponse(certificate, state)
}

func (c *CertificateContext) ReadEndEntityContext(state *EndEntityResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	username := state.EndEntityName.ValueString()

	// QUERY - multiplicity [0, 1] - is used to search by SubjectDn, SubjectAn, Username;
	tflog.Debug(c.ctx, "Searching for End Entity with username "+state.EndEntityName.ValueString())
	searchRequest := ejbca.SearchEndEntitiesRestRequest{
		Criteria: []ejbca.SearchEndEntityCriteriaRestRequest{
			{
				Property:             ptr("QUERY"),
				Value:                &username,
				Operation:            ptr("EQUAL"),
				AdditionalProperties: nil,
			},
		},
		AdditionalProperties: nil,
	}
	searchRequest.SetMaxNumberOfResults(1)

	searchResult, _, err := c.client.V1EndentityApi.Search(c.ctx).SearchEndEntitiesRestRequest(searchRequest).Execute()
	if err != nil {
		tflog.Error(c.ctx, "Failed to query EJBCA for end entity: "+err.Error())

		detail := ""
		bodyError, ok := err.(*ejbca.GenericOpenAPIError)
		if ok {
			detail = string(bodyError.Body())
		}

		diags.AddError(
			"Failed to query EJBCA for end entity",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)
		return diags
	}

	if len(searchResult.EndEntities) == 0 {
		diags.AddError(
			"EJBCA didn't return any end entities with username "+username,
			fmt.Sprintf("EJBCA API returned no end entities."),
		)
		return diags
	}
	endEntity := searchResult.EndEntities[0]

	state.EndEntityName = types.StringValue(endEntity.GetUsername())
	state.SubjectDn = types.StringValue(endEntity.GetDn())
	state.SubjectAltName = types.StringValue(endEntity.GetSubjectAltName())
	state.Email = types.StringValue(endEntity.GetEmail())
	state.Token = types.StringValue(endEntity.GetDn())

	// TODO need to find creative way to retrieve EndEntityPassword, CaName, CertificateProfileName, EndEntityProfileName, and AccountBindingId

	return diags
}

func (c *CertificateContext) CreateEndEntity(state *EndEntityResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	request := ejbca.AddEndEntityRestRequest{
		Username:               state.EndEntityName.ValueStringPointer(),
		Password:               state.EndEntityPassword.ValueStringPointer(),
		SubjectDn:              state.SubjectDn.ValueStringPointer(),
		SubjectAltName:         state.SubjectAltName.ValueStringPointer(),
		Email:                  state.Email.ValueStringPointer(),
		ExtensionData:          nil,
		CaName:                 state.CaName.ValueStringPointer(),
		CertificateProfileName: state.CertificateProfileName.ValueStringPointer(),
		EndEntityProfileName:   state.EndEntityProfileName.ValueStringPointer(),
		Token:                  state.Token.ValueStringPointer(),
		AccountBindingId:       state.AccountBindingId.ValueStringPointer(),
		AdditionalProperties:   nil,
	}

	_, err := c.client.V1EndentityApi.Add(c.ctx).AddEndEntityRestRequest(request).Execute()
	if err != nil {
		tflog.Error(c.ctx, "Failed to create new End Entity: "+err.Error())

		detail := ""
		bodyError, ok := err.(*ejbca.GenericOpenAPIError)
		if ok {
			detail = string(bodyError.Body())
		}

		diags.AddError(
			"Failed to create new End Entity",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)

		return diags
	}

	// Set the ID to the EndEntityName (username)
	state.Id = state.EndEntityName

	tflog.Info(c.ctx, "Created new End Entity with username "+state.EndEntityName.ValueString())
	return diags
}

func (c *CertificateContext) EnrollKeystore(state *CertificateResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	request := ejbca.KeyStoreRestRequest{
		Username:             state.EndEntityName.ValueStringPointer(),
		Password:             state.EndEntityPassword.ValueStringPointer(),
		KeyAlg:               nil, // TODO
		KeySpec:              nil, // TODO
		AdditionalProperties: nil,
	}

	certificate, _, err := c.client.V1CertificateApi.EnrollKeystore(c.ctx).KeyStoreRestRequest(request).Execute()
	if err != nil {
		tflog.Error(c.ctx, "Failed to submit Keystore Enrollment: "+err.Error())

		detail := ""
		bodyError, ok := err.(*ejbca.GenericOpenAPIError)
		if ok {
			detail = string(bodyError.Body())
		}

		diags.AddError(
			"Failed to enroll Keystore Enrollment",
			fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
		)

		return diags
	}

	return c.ComposeStateFromCertificateResponse(certificate, state)
}

// ComposeStateFromCertificateResponse extracts the certificate from an EJBCA CertificateRestResponse, encodes it to PEM format
// if necessary, and either extracts or downloads the certificate chain.
func (c *CertificateContext) ComposeStateFromCertificateResponse(certificate *ejbca.CertificateRestResponse, state *CertificateResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}
	if state == nil {
		diags.AddError("ComposeStateFromCertificateResponse was called improperly", "Pointer to CertificateResourceModel is nil")
		return diags
	}

	var leafAndChain []*x509.Certificate
	var issuerDn string

	// Get a x509 certificate from the EJBCA certificate response object
	if leaf, chainFound, err := getCertificatesFromEjbcaObject(certificate); err == nil && chainFound {
		// If EJBCA returned a chain, we don't need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()
	} else if err == nil && !chainFound {
		// If EJBCA did not return a chain, we need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()

		// Get the chain from EJBCA
		chain, err := getCaChain(c.ctx, c.client, issuerDn)
		if err != nil {
			diags.AddError(
				"Failed to retrieve CA PEM for CA with DN "+issuerDn,
				fmt.Sprintf("Got error: %s", err.Error()),
			)
			return diags
		}
		leafAndChain = append(leafAndChain, chain...)
	} else {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", err.Error()),
		)
		return diags
	}

	pemLeafAndChain := compileCertificatesToPemString(c.ctx, leafAndChain)

	// Set the ID of the resource to the certificate serial number
	state.Id = types.StringValue(certificate.GetSerialNumber())
	state.Certificate = types.StringValue(pemLeafAndChain)
	state.IssuerDn = types.StringValue(issuerDn)
	state.CertificateProfileName = types.StringValue(certificate.GetCertificateProfile())
	state.EndEntityProfileName = types.StringValue(certificate.GetEndEntityProfile())

	tflog.Debug(c.ctx, "Composed certificate information into state")

	return diags
}
