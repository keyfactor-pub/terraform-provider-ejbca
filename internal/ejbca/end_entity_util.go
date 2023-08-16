package ejbca

import (
	"context"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type EndEntityContext struct {
	ctx    context.Context
	client *ejbca.APIClient
}

func CreateEndEntityContext(ctx context.Context, client *ejbca.APIClient) *EndEntityContext {
	return &EndEntityContext{
		ctx:    ctx,
		client: client,
	}
}

// EndEntityContext has the following methods:
// - CreateEndEntity - Used by end_entity_resource
// - ReadEndEntityContext - Used by end_entity_resource
// - DeleteEndEntity - Used by end_entity_resource

func (c *EndEntityContext) CreateEndEntity(state *EndEntityResourceModel) diag.Diagnostics {
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
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to create new End Entity")
	}

	tflog.Info(c.ctx, "Created new End Entity with username "+state.EndEntityName.ValueString())

	// Update the state with the new End Entity's information
	diags.Append(c.ReadEndEntityContext(state)...)
	if diags.HasError() {
		return diags
	}

	return diags
}

func (c *EndEntityContext) ReadEndEntityContext(state *EndEntityResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	username := state.EndEntityName.ValueString()

	// QUERY - multiplicity [0, 1] - is used to search by SubjectDn, SubjectAn, Username
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
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to query EJBCA for end entity")
	}

	if len(searchResult.EndEntities) == 0 {
		diags.AddError(
			"EJBCA didn't return any end entities with username "+username,
			fmt.Sprintf("EJBCA API returned no end entities."),
		)
		return diags
	}
	endEntity := searchResult.EndEntities[0]

	// Set the ID to the EndEntityName (username)
	state.Id = types.StringValue(endEntity.GetUsername())

	// Set the rest of the state
	if endEntityName, ok := endEntity.GetUsernameOk(); ok && *endEntityName != "" {
		state.EndEntityName = types.StringValue(*endEntityName)
	}
	if endEntityDn, ok := endEntity.GetDnOk(); ok && *endEntityDn != "" {
		state.SubjectDn = types.StringValue(*endEntityDn)
	}
	if endEntitySubjectAltName, ok := endEntity.GetSubjectAltNameOk(); ok && *endEntitySubjectAltName != "" {
		state.SubjectAltName = types.StringValue(*endEntitySubjectAltName)
	}
	if endEntityEmail, ok := endEntity.GetEmailOk(); ok && *endEntityEmail != "" {
		state.Email = types.StringValue(*endEntityEmail)
	}
	if endEntityToken, ok := endEntity.GetTokenOk(); ok && *endEntityToken != "" {
		state.Token = types.StringValue(*endEntityToken)
	}
	if status, ok := endEntity.GetStatusOk(); ok && *status != "" {
		state.Status = types.StringValue(*status)
	}

	// TODO need to find creative way to retrieve EndEntityPassword, CaName, CertificateProfileName, EndEntityProfileName, and AccountBindingId

	return diags
}

// UpdateEndEntityStatus sets the token
func (c *EndEntityContext) UpdateEndEntityStatus(state *EndEntityResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	// Set the new status
	request := ejbca.SetEndEntityStatusRestRequest{
		Password:             state.EndEntityPassword.ValueStringPointer(),
		Token:                state.Token.ValueStringPointer(),
		Status:               state.Status.ValueStringPointer(),
		AdditionalProperties: nil,
	}
	_, err := c.client.V1EndentityApi.Setstatus(c.ctx, state.EndEntityName.ValueString()).SetEndEntityStatusRestRequest(request).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to update End Entity status")
	}

	// Update the state with the new End Entity's information
	diags.Append(c.ReadEndEntityContext(state)...)
	if diags.HasError() {
		return diags
	}

	return diags
}

func (c *EndEntityContext) DeleteEndEntity(state *EndEntityResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	username := state.EndEntityName.ValueString()

	_, err := c.client.V1EndentityApi.Delete(c.ctx, username).Execute()
	if err != nil {
		return logErrorAndReturnDiags(c.ctx, diags, err, "Failed to delete End Entity with username "+username)
	}

	tflog.Info(c.ctx, "Deleted End Entity with username "+username)
	return diags
}
