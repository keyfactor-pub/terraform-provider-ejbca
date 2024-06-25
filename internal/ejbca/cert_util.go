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
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var overridableTimeFunc = func() time.Time {
	return time.Now()
}

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
	if c == nil {
		diags.AddError("EnrollPkcs10Certificate was called improperly", "Pointer to CertificateContext is nil")
		return diags
	}
	if c.client == nil {
		diags.AddError("EnrollPkcs10Certificate was called improperly", "Pointer to EJBCA client is nil")
		return diags
	}
	if state == nil {
		diags.AddError("EnrollPkcs10Certificate was called improperly", "Pointer to CertificateResourceModel is nil")
		return diags
	}

	tflog.Trace(c.ctx, "Parsing CSR from request")
	blocks := decodePEMBytes([]byte(state.CertificateSigningRequest.ValueString()))
	if len(blocks) != 1 {
		diags.AddError("Failed to parse CSR", fmt.Sprintf("CSR must contain exactly one PEM block, found %d", len(blocks)))
		tflog.Error(c.ctx, "Failed to parse CSR", map[string]any{"err": fmt.Sprintf("CSR must contain exactly one PEM block, found %d", len(blocks))})
		return diags
	}
	parsedCsr, err := x509.ParseCertificateRequest(blocks[0].Bytes)
	if err != nil {
		diags.AddError("Failed to parse CSR", err.Error())
		tflog.Error(c.ctx, "Failed to parse CSR", map[string]any{"err": err.Error()})
		return diags
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: parsedCsr.Raw})

	tflog.Trace(c.ctx, "Determining end entity name")
	endEntityName, err := c.getEndEntityName(state.EndEntityName.ValueString(), parsedCsr)
	if err != nil {
		diags.AddError("Failed to determine end entity name", err.Error())
		return diags
	}

	password, err := generateRandomString(20)
	if err != nil {
		diags.AddError("Failed to generate random password", err.Error())
		return diags
	}

	// Configure EJBCA PKCS#10 request
	tflog.Trace(c.ctx, "Preparing EJBCA enrollment request")
	config := ejbca.EnrollCertificateRestRequest{}
	config.SetCertificateRequest(string(csrPem))
	config.SetCertificateAuthorityName(state.CertificateAuthorityName.ValueString())
	config.SetCertificateProfileName(state.CertificateProfileName.ValueString())
	config.SetEndEntityProfileName(state.EndEntityProfileName.ValueString())
	config.SetUsername(endEntityName)
	config.SetPassword(password)
	config.SetIncludeChain(true)
	config.SetAccountBindingId(state.AccountBindingID.ValueString())

	tflog.Debug(c.ctx, "Prepared EJBCA enrollment request", map[string]any{"subject": parsedCsr.Subject.String(), "uriSANs": parsedCsr.URIs, "endEntityName": endEntityName, "caName": config.GetCertificateAuthorityName(), "certificateProfileName": config.CertificateProfileName, "endEntityProfileName": config.EndEntityProfileName, "accountBindingId": config.GetAccountBindingId()})

	// Enroll the PKCS#10 CSR using the EJBCA API
	certificate, httpResponse, err := c.client.V1CertificateApi.EnrollPkcs10Certificate(c.ctx).EnrollCertificateRestRequest(config).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to enroll PKCS#10 CSR")
	}
	if httpResponse != nil && httpResponse.Body != nil {
		httpResponse.Body.Close()
	}

	tflog.Debug(c.ctx, "Enrolled certificate using PKCS#10 enrollment with serial number: "+certificate.GetSerialNumber())
	return c.ComposeStateFromCertificateResponse(certificate, state)
}

// getEndEntityName calculates the End Entity Name based on the default_end_entity_name from the EJBCA UpstreamAuthority
// configuration. The possible values are:
// - cn: Uses the Common Name from the CSR's Distinguished Name.
// - dns: Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
// - uri: Uses the first URI from the CSR's Subject Alternative Names (SANs).
// - ip: Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
// - Custom Value: Any other string will be directly used as the End Entity Name.
// If the default_end_entity_name is not set, the plugin will determine the End Entity Name in the same order as above.
func (c *CertificateContext) getEndEntityName(defaultEndEntityName string, csr *x509.CertificateRequest) (string, error) {
	eeName := ""
	// 1. If the endEntityName option is set, determine the end entity name based on the option
	// 2. If the endEntityName option is not set, determine the end entity name based on the CSR

	// cn: Use the CommonName from the CertificateRequest's DN
	if defaultEndEntityName == "cn" || defaultEndEntityName == "" {
		if csr.Subject.CommonName != "" {
			eeName = csr.Subject.CommonName
			tflog.Debug(c.ctx, "Using CommonName from the CSR's DN as the EJBCA end entity name", map[string]any{"endEntityName": eeName})
			return eeName, nil
		}
	}

	// dns: Use the first DNSName from the CertificateRequest's DNSNames SANs
	if defaultEndEntityName == "dns" || defaultEndEntityName == "" {
		if len(csr.DNSNames) > 0 && csr.DNSNames[0] != "" {
			eeName = csr.DNSNames[0]
			tflog.Debug(c.ctx, "Using the first DNSName from the CSR's DNSNames SANs as the EJBCA end entity name", map[string]any{"endEntityName": eeName})
			return eeName, nil
		}
	}

	// uri: Use the first URI from the CertificateRequest's URI Sans
	if defaultEndEntityName == "uri" || defaultEndEntityName == "" {
		if len(csr.URIs) > 0 {
			eeName = csr.URIs[0].String()
			tflog.Debug(c.ctx, "Using the first URI from the CSR's URI Sans as the EJBCA end entity name", map[string]any{"endEntityName": eeName})
			return eeName, nil
		}
	}

	// ip: Use the first IPAddress from the CertificateRequest's IPAddresses SANs
	if defaultEndEntityName == "ip" || defaultEndEntityName == "" {
		if len(csr.IPAddresses) > 0 {
			eeName = csr.IPAddresses[0].String()
			tflog.Debug(c.ctx, "Using the first IPAddress from the CSR's IPAddresses SANs as the EJBCA end entity name", map[string]any{"endEntityName": eeName})
			return eeName, nil
		}
	}

	// End of defaults; if the endEntityName option is set to anything but cn, dns, or uri, use the option as the end entity name
	if defaultEndEntityName != "" && defaultEndEntityName != "cn" && defaultEndEntityName != "dns" && defaultEndEntityName != "uri" {
		eeName = defaultEndEntityName
		tflog.Debug(c.ctx, "Using the default_end_entity_name config value as the EJBCA end entity name", map[string]any{"endEntityName": eeName})
		return eeName, nil
	}

	// If we get here, we were unable to determine the end entity name
	tflog.Error(c.ctx, fmt.Sprintf("the endEntityName option is set to %q, but no valid end entity name could be determined from the CertificateRequest", defaultEndEntityName))

	return "", fmt.Errorf("no valid end entity name could be determined from the CertificateRequest")
}

func (c *CertificateContext) ReadCertificate(state *CertificateResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	certificateSerialNumber := state.ID.ValueString()

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

	searchResult, httpResponse, err := c.client.V1CertificateApi.SearchCertificates(c.ctx).SearchCertificatesRestRequest(certSearch).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to query EJBCA for certificate")
	}
	defer httpResponse.Body.Close()

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

func (c *CertificateContext) RevokeCertificate(issuerDn string, certificateSerialNumber string) diag.Diagnostics {
	diags := diag.Diagnostics{}

	message, httpResponse, err := c.client.V1CertificateApi.RevokeCertificate(c.ctx, issuerDn, certificateSerialNumber).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to revoke certificate with serial number \""+certificateSerialNumber+"\"")
	}
	if httpResponse != nil && httpResponse.Body != nil {
		httpResponse.Body.Close()
	}

	tflog.Info(c.ctx, "Revoked certificate with serial number \""+certificateSerialNumber+"\": "+*message.Message)

	return diags
}

// ComposeStateFromCertificateResponse extracts the certificate from an EJBCA CertificateRestResponse, encodes it to PEM format
// if necessary, and either extracts or downloads the certificate chain.
func (c *CertificateContext) ComposeStateFromCertificateResponse(certificate *ejbca.CertificateRestResponse, state *CertificateResourceModel) diag.Diagnostics {
	var err error
	diags := diag.Diagnostics{}
	if state == nil {
		diags.AddError("ComposeStateFromCertificateResponse was called improperly", "Pointer to CertificateResourceModel is nil")
		return diags
	}

	var leaf *x509.Certificate
	var chain []*x509.Certificate

	leaf, chain, err = getCertificatesFromEjbcaObject(certificate)
	if err != nil {
		diags.AddError(
			"Failed to parse certificate",
			fmt.Sprintf("Failed to parse certificate: %s", err.Error()),
		)
		return diags
	}

	if len(chain) == 0 {
		var diag diag.Diagnostics
		chain, diag = c.DownloadCAChain(leaf.Issuer.String())
		diags.Append(diag...)
	}

	// Sanity check - validate the leaf cert up to the root
	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[len(chain)-1])
	intermediatePool := x509.NewCertPool()
	for _, cert := range chain[:len(chain)-1] {
		intermediatePool.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	})
	if err != nil {
		diags.AddError(
			"Failed to validate certificate chain",
			fmt.Sprintf("Got error from x509.Verify: %s", err.Error()),
		)
		return diags
	}

	leafPemString := compileCertificatesToPemString(c.ctx, []*x509.Certificate{leaf})
	chainPemString := compileCertificatesToPemString(c.ctx, chain)

	isRevoked, _diags := c.IsCertificateRevoked(leaf.Issuer.String(), certificate.GetSerialNumber())
	diags.Append(_diags...)
	if diags.HasError() {
		return diags
	}

	validFromBytes, err := leaf.NotBefore.MarshalText()
	if err != nil {
		diags.AddError("Failed to serialize validity start time", err.Error())
		return diags
	}
	validToBytes, err := leaf.NotAfter.MarshalText()
	if err != nil {
		diags.AddError("Failed to serialize validity end time", err.Error())
		return diags
	}

	currentTime := overridableTimeFunc()

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-state.EarlyRenewalHours.ValueInt64()) * time.Hour
	earlyRenewalTime := leaf.NotAfter.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(currentTime)
	if timeToEarlyRenewal <= 0 {
		tflog.Info(c.ctx, "Certificate is eligible for renewal")
		state.ReadyForRenewal = types.BoolValue(true)
	} else {
		state.ReadyForRenewal = types.BoolValue(false)
	}

	// Set the ID of the resource to the certificate serial number
	state.ID = types.StringValue(certificate.GetSerialNumber())
	state.Certificate = types.StringValue(leafPemString)
	state.Chain = types.StringValue(chainPemString)
	state.IssuerDn = types.StringValue(leaf.Issuer.String())
	state.ValidityStartTime = types.StringValue(string(validFromBytes))
	state.ValidityEndTime = types.StringValue(string(validToBytes))
	state.IsRevoked = types.BoolValue(isRevoked)

	if certProfileName, ok := certificate.GetCertificateProfileOk(); ok && *certProfileName != "" {
		state.CertificateProfileName = types.StringValue(*certProfileName)
	}
	if endEntityProfileName, ok := certificate.GetEndEntityProfileOk(); ok && *endEntityProfileName != "" {
		state.EndEntityProfileName = types.StringValue(*endEntityProfileName)
	}

	tflog.Debug(c.ctx, "Composed certificate information into state")

	return diags
}

func (c *CertificateContext) IsCertificateRevoked(issuerDN string, serialNumber string) (bool, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	tflog.Debug(c.ctx, "Checking if certificate is revoked", map[string]any{"issuerDN": issuerDN, "serialNumber": serialNumber})
	status, r, err := c.client.V1CertificateApi.RevocationStatus(c.ctx, issuerDN, serialNumber).Execute()
	if err != nil {
		return false, diags
	}
	defer r.Body.Close()
	return status.GetRevoked(), diags
}

func (c *CertificateContext) DownloadCAChain(issuerDN string) ([]*x509.Certificate, diag.Diagnostics) {
	diags := diag.Diagnostics{}
	tflog.Debug(c.ctx, "Downloading CA chain", map[string]any{"issuerDN": issuerDN})
	caResp, err := c.client.V1CaApi.GetCertificateAsPem(c.ctx, issuerDN).Execute()
	if err != nil {
		return nil, logErrorAndReturnDiags(c.ctx, diags, err, "Failed to retrieve CA PEM for CA with DN "+issuerDN)
	}
	defer caResp.Body.Close()

	encodedBytes, err := io.ReadAll(caResp.Body) // EJBCA returns CA chain as a single PEM file
	if err != nil {
		diags.AddError("Failed to read CA chain response", err.Error())
		return nil, diags
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
		diags.AddError("Failed to parse CA chain", err.Error())
		return nil, diags
	}

	return certificates, diags
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

func getCertificatesFromEjbcaObject(ejbcaCert *ejbca.CertificateRestResponse) (*x509.Certificate, []*x509.Certificate, error) {
	var certBytes []byte
	var chainBytes []byte
	var err error

	switch {
	case ejbcaCert.GetResponseFormat() == "PEM":
		// Extract the certificate from the PEM string
		block, _ := pem.Decode([]byte(ejbcaCert.GetCertificate()))
		if block == nil {
			return nil, nil, errors.New("failed to parse certificate PEM")
		}
		certBytes = block.Bytes

		for _, certString := range ejbcaCert.GetCertificateChain() {
			block, _ := pem.Decode([]byte(certString))
			if block == nil {
				return nil, nil, errors.New("failed to parse certificate PEM")
			}
			chainBytes = append(chainBytes, block.Bytes...)
		}
	case ejbcaCert.GetResponseFormat() == "DER":
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

				chainBytes = append(chainBytes, chainCertBytes...)
			}
		}
	default:
		return nil, nil, fmt.Errorf("ejbca returned unknown certificate format: %s. Expected PEM or DER", ejbcaCert.GetResponseFormat())
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("EJBCA returned no leaf certificates")
	}
	if len(certs) > 1 {
		return nil, nil, fmt.Errorf("EJBCA returned more than one leaf certificate")
	}

	var chainCerts []*x509.Certificate
	if len(chainBytes) > 0 {
		chainCerts, err = x509.ParseCertificates(chainBytes)
		if err != nil {
			return nil, nil, err
		}
	}

	return certs[0], chainCerts, nil
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

func decodePEMBytes(buf []byte) []*pem.Block {
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}
		certificates = append(certificates, block)
	}
	return certificates
}

// generateRandomString generates a random string of the specified length.
func generateRandomString(length int) (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}
	return string(b), nil
}
