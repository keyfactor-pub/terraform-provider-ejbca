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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"io"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
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

func (c *CertificateContext) createEndEntityContext() *EndEntityContext {
	return &EndEntityContext{
		ctx:    c.ctx,
		client: c.client,
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
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to enroll PKCS#10 CSR")
	}

	tflog.Debug(c.ctx, "Enrolled certificate using PKCS#10 enrollment with serial number: "+certificate.GetSerialNumber())
	return c.ComposeStateFromCertificateResponse(certificate, state)
}

func (c *CertificateContext) ReadCertificateContext(state *CertificateResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

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

	searchResult, _, err := c.client.V1CertificateApi.SearchCertificates(c.ctx).SearchCertificatesRestRequest(certSearch).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to query EJBCA for certificate")
	}

	if len(searchResult.Certificates) == 0 {
		diags.AddError(
			"EJBCA didn't return any certificates",
			"EJBCA API returned no certificates after enrollment.",
		)
		return diags
	}
	certificate := searchResult.Certificates[0]

	return c.ComposeStateFromCertificateResponse(&certificate, state)
}

func (c *CertificateContext) EnrollKeystore(state *KeystoreResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	endEntityContext := c.createEndEntityContext()

	// Validate that the EndEntity has token type P12
	endEntity := EndEntityResourceModel{EndEntityName: state.EndEntityName}
	diags.Append(endEntityContext.ReadEndEntityContext(&endEntity)...)
	if diags.HasError() {
		return diags
	}

	// Force EndEntity to have status NEW
	if endEntity.Status.ValueString() != "NEW" {
		endEntity.Status = types.StringValue("NEW")
		diags.Append(endEntityContext.UpdateEndEntityStatus(&endEntity)...)
		if diags.HasError() {
			return diags
		}
	}

	// TODO support other token types
	if endEntity.Token.ValueString() != "P12" {
		message := fmt.Sprintf("EndEntity called %s must have token type P12", state.EndEntityName)
		detail := fmt.Sprintf("In order to perform a Keystore enrollment, the EndEntity called %s must have token type PKCS12, but it currently has type %s", state.EndEntityName, endEntity.Token.ValueString())

		tflog.Error(c.ctx, detail)
		diags.AddError(message, detail)
		return diags
	}

	request := ejbca.KeyStoreRestRequest{
		Username:             state.EndEntityName.ValueStringPointer(),
		Password:             state.EndEntityPassword.ValueStringPointer(),
		KeyAlg:               state.KeyAlg.ValueStringPointer(),
		KeySpec:              state.KeySpec.ValueStringPointer(),
		AdditionalProperties: nil,
	}

	certificate, _, err := c.client.V1CertificateApi.EnrollKeystore(c.ctx).KeyStoreRestRequest(request).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to enroll Keystore")
	}

	diags.Append(c.ComposeStateFromKeystoreResponse(certificate, state)...)
	if diags.HasError() {
		return diags
	}

	// Compute KeyAlg and KeySpec from the certificate
	// TODO

	return diags
}

func (c *CertificateContext) ReadKeystoreContext(state *KeystoreResourceModel) diag.Diagnostics {
	var certificateState CertificateResourceModel

	// Read the certificate
	diags := c.ReadCertificateContext(&certificateState)
	if diags.HasError() {
		return diags
	}

	// Copy the certificate state to the keystore state
	state.Id = certificateState.Id
	state.EndEntityName = certificateState.EndEntityName
	state.Certificate = certificateState.Certificate
	state.IssuerDn = certificateState.IssuerDn

	// TODO: Compute KeyAlg and KeySpec from the certificate

	return nil
}

func (c *CertificateContext) RevokeCertificate(issuerDn string, certificateSerialNumber string) diag.Diagnostics {
	diags := diag.Diagnostics{}

	message, _, err := c.client.V1CertificateApi.RevokeCertificate(c.ctx, issuerDn, certificateSerialNumber).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to revoke certificate with serial number \""+certificateSerialNumber+"\"")
	}

	tflog.Info(c.ctx, "Revoked certificate with serial number \""+certificateSerialNumber+"\": "+*message.Message)

	return diags
}

func (c *CertificateContext) ComposeStateFromKeystoreResponse(certificate *ejbca.CertificateRestResponse, state *KeystoreResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}
	if state == nil {
		diags.AddError("ComposeStateFromKeystoreResponse was called improperly", "Pointer to KeystoreResourceModel is nil")
		return diags
	}

	var leafAndChain []*x509.Certificate
	var issuerDn string

	leaf, key, err := getCertificatesFromEjbcaObject(certificate, state.EndEntityPassword.ValueString())
	if err != nil {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", err.Error()),
		)
		return diags
	} else if len(leaf) == 0 {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", "No certificate returned from EJBCA"),
		)
		return diags
	}

	// Get a x509 certificate from the EJBCA certificate response object
	if len(leaf) > 1 {
		// If EJBCA returned a chain, we don't need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()
	} else if len(leaf) == 1 {
		// If EJBCA did not return a chain, we need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()

		// Get the chain from EJBCA
		chain, err := c.DownloadCaChain(issuerDn)
		if err != nil {
			diags.AddError(
				"Failed to retrieve CA PEM for CA with DN "+issuerDn,
				fmt.Sprintf("Got error: %s", err.Error()),
			)
			return diags
		}
		leafAndChain = append(leafAndChain, chain...)
	}

	pemLeafAndChain := compileCertificatesToPemString(c.ctx, leafAndChain)

	// Now handle the private key
	keyString, ok := key.(string)
	if ok {
		state.Key = types.StringValue(keyString)
	}

	// Set the ID of the resource to the certificate serial number
	state.Id = types.StringValue(certificate.GetSerialNumber())
	state.Certificate = types.StringValue(pemLeafAndChain)
	state.IssuerDn = types.StringValue(issuerDn)

	tflog.Debug(c.ctx, "Composed certificate information into state")

	return diags
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

	leaf, _, err := getCertificatesFromEjbcaObject(certificate, "")
	if err != nil {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", err.Error()),
		)
		return diags
	} else if len(leaf) == 0 {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", "No certificate returned from EJBCA"),
		)
		return diags
	}

	// Get a x509 certificate from the EJBCA certificate response object
	if len(leaf) > 1 {
		// If EJBCA returned a chain, we don't need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()
	} else if len(leaf) == 1 {
		// If EJBCA did not return a chain, we need to query EJBCA for the chain
		leafAndChain = append(leafAndChain, leaf...)
		issuerDn = leafAndChain[0].Issuer.String()

		// Get the chain from EJBCA
		chain, err := c.DownloadCaChain(issuerDn)
		if err != nil {
			diags.AddError(
				"Failed to retrieve CA PEM for CA with DN "+issuerDn,
				fmt.Sprintf("Got error: %s", err.Error()),
			)
			return diags
		}
		leafAndChain = append(leafAndChain, chain...)
	}

	pemLeafAndChain := compileCertificatesToPemString(c.ctx, leafAndChain)

	// Set the ID of the resource to the certificate serial number
	state.Id = types.StringValue(certificate.GetSerialNumber())
	state.Certificate = types.StringValue(pemLeafAndChain)
	state.IssuerDn = types.StringValue(issuerDn)

	if certProfileName, ok := certificate.GetCertificateProfileOk(); ok && *certProfileName != "" {
		state.CertificateProfileName = types.StringValue(*certProfileName)
	}
	if endEntityProfileName, ok := certificate.GetEndEntityProfileOk(); ok && *endEntityProfileName != "" {
		state.EndEntityProfileName = types.StringValue(*endEntityProfileName)
	}

	tflog.Debug(c.ctx, "Composed certificate information into state")

	return diags
}

func (c *CertificateContext) DownloadCaChain(issuerDn string) ([]*x509.Certificate, error) {
	caResp, err := c.client.V1CaApi.GetCertificateAsPem(c.ctx, issuerDn).Execute()
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

func logErrorAndReturnDiags(ctx context.Context, diags diag.Diagnostics, err error, message string) diag.Diagnostics {
	messageString := fmt.Sprintf("%s: %s", message, err.Error())

	tflog.Error(ctx, messageString)

	detail := ""
	var bodyError *ejbca.GenericOpenAPIError
	ok := errors.As(err, &bodyError)
	if ok {
		detail = string(bodyError.Body())
	}

	diags.AddError(
		messageString,
		fmt.Sprintf("EJBCA API returned error %s (%s)", detail, err.Error()),
	)

	return diags
}

func getCertificatesFromEjbcaObject(ejbcaCert *ejbca.CertificateRestResponse, password string) ([]*x509.Certificate, interface{}, error) {
	var certBytes []byte
	var err error
	var privateKey interface{}

	if ejbcaCert.GetResponseFormat() == "PEM" {
		// Extract the certificate from the PEM string
		block, _ := pem.Decode([]byte(ejbcaCert.GetCertificate()))
		if block == nil {
			return nil, nil, errors.New("failed to parse certificate PEM")
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
	} else if ejbcaCert.GetResponseFormat() == "PKCS12" {
		var pkcs12Bytes []byte
		pkcs12Bytes, err = base64.StdEncoding.DecodeString(ejbcaCert.GetCertificate())
		if err != nil {
			return nil, nil, errors.New("failed to base64 decode PKCS12 certificate: " + err.Error())
		}

		// Temporarily put pkcs12Bytes into a file for testing
		err = os.WriteFile("pkcs12.p12", pkcs12Bytes, 0644)
		if err != nil {
			return nil, nil, err
		}

		key, leaf, chain, err := pkcs12.DecodeChain(pkcs12Bytes, password)
		if err != nil {
			return nil, nil, errors.New("failed to decode PKCS12 certificate: " + err.Error())
		}

		// Copy the leaf certificate into the certBytes slice
		certBytes = leaf.Raw

		// Copy the chain certificates into the certBytes slice
		for _, chainCert := range chain {
			certBytes = append(certBytes, chainCert.Raw...)
		}

		// Copy the private key into the privateKey variable
		privateKey = key
	} else {
		return nil, nil, fmt.Errorf("ejbca returned unknown certificate format: %s. Expected PEM, DER, or PKCS12", ejbcaCert.GetResponseFormat())
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, false, err
	}

	return certs, privateKey, nil
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
