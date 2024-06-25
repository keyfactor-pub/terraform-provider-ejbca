package attribute_plan_modifier_bool

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// readyForRenewalAttributePlanModifier determines whether the certificate is ready for renewal.
type certificateIsRevokedAttributePlanModifier struct {
}

// Description implements planmodifier.Bool.
func (c *certificateIsRevokedAttributePlanModifier) Description(ctx context.Context) string {
    return c.MarkdownDescription(ctx)
}

// MarkdownDescription implements planmodifier.Bool.
func (c *certificateIsRevokedAttributePlanModifier) MarkdownDescription(context.Context) string {
	return "Sets the value of is_revoked by fetching the revocation status from EJBCA"
}

// PlanModifyBool implements planmodifier.Bool.
func (c *certificateIsRevokedAttributePlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	panic("unimplemented")
}

// ReadyForRenewal is an helper to instantiate a defaultValueAttributePlanModifier.
func CertificateIsRevoked() planmodifier.Bool {
	return &certificateIsRevokedAttributePlanModifier{}
}
