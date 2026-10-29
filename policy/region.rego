# GOV_001: deploy only to approved regions (data residency and resilience).
# The region is read from the provider configuration, either as a literal
# or through a variable.
package main

approved_regions := {"us-east-1", "us-east-2"}

aws_region := r if {
	r := input.configuration.provider_config.aws.expressions.region.constant_value
} else := r if {
	some ref in input.configuration.provider_config.aws.expressions.region.references
	startswith(ref, "var.")
	name := substring(ref, 4, -1)
	r := input.variables[name].value
}

finding contains v if {
	r := aws_region
	not r in approved_regions
	v := {
		"rule": "GOV_001",
		"resource": "provider.aws",
		"msg": sprintf("region '%s' is not approved %v", [r, sort(approved_regions)]),
	}
}
