// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Taken from https://github.com/hashicorp/terraform-provider-tls/blob/8f69cf7de64d98d042c171aaeafd1f97c16e05f1/internal/provider/attribute_plan_modifier_bool/default_value.go

package attrpmbool

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var overridableTimeFunc = time.Now

// readyForRenewalAttributePlanModifier determines whether the certificate is ready for renewal.
type readyForRenewalAttributePlanModifier struct {
}

// ReadyForRenewal is an helper to instantiate a defaultValueAttributePlanModifier.
func ReadyForRenewal() planmodifier.Bool {
	return &readyForRenewalAttributePlanModifier{}
}

var _ planmodifier.Bool = (*readyForRenewalAttributePlanModifier)(nil)

func (apm *readyForRenewalAttributePlanModifier) Description(ctx context.Context) string {
	return apm.MarkdownDescription(ctx)
}

func (apm *readyForRenewalAttributePlanModifier) MarkdownDescription(_ context.Context) string {
	return "Sets the value of ready_for_renewal depending on value of validity_period_hours and early_renewal_hours"
}

func (apm *readyForRenewalAttributePlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, res *planmodifier.BoolResponse) {
	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if res.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		res.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}
	now := overridableTimeFunc()

	validityPeriodHours := math.Floor(validityEndTime.Sub(now).Hours())

	if validityPeriodHours == 0 {
		res.PlanValue = types.BoolValue(true)
		return
	}

	var earlyRenewalHours types.Int64

	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("early_renewal_hours"), &earlyRenewalHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	if earlyRenewalHours.IsNull() || earlyRenewalHours.IsUnknown() {
		return
	}

	if earlyRenewalHours.ValueInt64() >= int64(validityPeriodHours) {
		res.PlanValue = types.BoolValue(true)

		return
	}
}
